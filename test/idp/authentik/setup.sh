#!/usr/bin/env bash
# Configure a fresh Authentik: OIDC provider+app, SAML provider+app, then print the
# values needed for the OPNsense auth servers to /tmp/authentik-out.env.
set -euo pipefail
cd "$(dirname "$0")"
TOK=$(grep AUTHENTIK_BOOTSTRAP_TOKEN .env | cut -d= -f2-)
# The SP base URL the browser (and therefore the IdP) uses -- overridable because the
# lab's forwarded WebGUI port is (see test/Vagrantfile SSO_GUI_PORT). os-sso gives
# every SAML server its own SP identity, hence ?provider=<auth server name>.
SP_BASE="${SP_BASE:-https://localhost:8443}"
SAML_PROVIDER="${SAML_PROVIDER:-authentik-saml}"
SP_Q="?provider=$SAML_PROVIDER"
API=http://localhost:9000/api/v3
H="Authorization: Bearer $TOK"
CT="Content-Type: application/json"

echo ">>> waiting for Authentik API..."
for i in $(seq 1 60); do
  curl -fsS -H "$H" "$API/core/users/me/" >/dev/null 2>&1 && break
  sleep 3
done

# Look up the pks we need (names are stable across versions).
AUTHZ=$(curl -s -H "$H" "$API/flows/instances/?designation=authorization" | jq -r '.results[] | select(.slug|test("implicit")) | .pk' | head -1)
INVAL=$(curl -s -H "$H" "$API/flows/instances/?designation=invalidation" | jq -r '.results[0].pk')
SIGN=$(curl -s -H "$H" "$API/crypto/certificatekeypairs/?has_key=true" | jq -r '.results[0].pk')
SCOPES=$(curl -s -H "$H" "$API/propertymappings/provider/scope/?page_size=50" \
  | jq -r '[.results[] | select(.scope_name|test("^(openid|email|profile)$")) | .pk] | @json')
UNAME=$(curl -s -H "$H" "$API/propertymappings/provider/saml/?page_size=50" \
  | jq -r '.results[] | select(.name|test("Username$";"i")) | .pk' | head -1)

echo ">>> creating OIDC provider + app"
# Reuse an existing provider: this script is expected to be re-runnable (e.g. after
# changing SP_BASE), and POSTing blindly would pile up duplicates whose application
# slug collides, leaving the app pointed at the first, stale provider.
OIDC_PROV=$(curl -s -H "$H" "$API/providers/oauth2/?name=opnsense-oidc" | jq -r '.results[0].pk // empty')
[ -z "$OIDC_PROV" ] && OIDC_PROV=$(curl -s -H "$H" -H "$CT" -X POST "$API/providers/oauth2/" -d "{
  \"name\":\"opnsense-oidc\",\"authorization_flow\":\"$AUTHZ\",\"invalidation_flow\":\"$INVAL\",
  \"client_type\":\"confidential\",\"signing_key\":\"$SIGN\",\"include_claims_in_id_token\":true,
  \"sub_mode\":\"user_username\",\"grant_types\":[\"authorization_code\",\"refresh_token\"],
  \"redirect_uris\":[{\"matching_mode\":\"strict\",\"url\":\"$SP_BASE/api/sso/oidc/callback\"}],
  \"property_mappings\":$SCOPES}" | jq -r '.pk')
# Re-apply the redirect URI every run so a changed SP_BASE takes effect on a lab that
# was already set up (the provider is only created once).
curl -s -H "$H" -H "$CT" -X PATCH "$API/providers/oauth2/$OIDC_PROV/" \
  -d "{\"redirect_uris\":[{\"matching_mode\":\"strict\",\"url\":\"$SP_BASE/api/sso/oidc/callback\"}]}" >/dev/null
OIDC_CID=$(curl -s -H "$H" "$API/providers/oauth2/$OIDC_PROV/" | jq -r '.client_id')
OIDC_SEC=$(curl -s -H "$H" "$API/providers/oauth2/$OIDC_PROV/" | jq -r '.client_secret')
# Point the application at the provider whether it was just created or reused.
if curl -sf -H "$H" "$API/core/applications/opnsense/" >/dev/null 2>&1; then
  curl -s -H "$H" -H "$CT" -X PATCH "$API/core/applications/opnsense/" \
    -d "{\"provider\":$OIDC_PROV}" >/dev/null
else
  curl -s -H "$H" -H "$CT" -X POST "$API/core/applications/" \
    -d "{\"name\":\"OPNsense\",\"slug\":\"opnsense\",\"provider\":$OIDC_PROV}" >/dev/null
fi

echo ">>> creating SAML provider + app"
# Attribute mappings: without at least one, Authentik emits an EMPTY
# <AttributeStatement/>, which is invalid per the SAML schema and php-saml (strict)
# rejects the whole response. Attach the default SAML mappings (Email/Groups/Name/...)
# -- they also carry the groups os-sso maps to OPNsense groups.
SAML_MAPS=$(curl -s -H "$H" "$API/propertymappings/provider/saml/?page_size=50" \
  | jq -c '[.results[] | select(.name|contains("default SAML Mapping")) | .pk]')
SAML_PROV=$(curl -s -H "$H" "$API/providers/saml/?name=opnsense-saml" | jq -r '.results[0].pk // empty')
[ -z "$SAML_PROV" ] && SAML_PROV=$(curl -s -H "$H" -H "$CT" -X POST "$API/providers/saml/" -d "{
  \"name\":\"opnsense-saml\",\"authorization_flow\":\"$AUTHZ\",\"invalidation_flow\":\"$INVAL\",
  \"acs_url\":\"$SP_BASE/api/sso/saml/acs$SP_Q\",
  \"issuer\":\"https://authentik.test:9443/application/saml/opnsense-saml/\",
  \"audience\":\"$SP_BASE/api/sso/saml/metadata$SP_Q\",
  \"sp_binding\":\"post\",\"signing_kp\":\"$SIGN\",\"sign_assertion\":true,\"sign_response\":false,
  \"property_mappings\":$SAML_MAPS,
  \"name_id_mapping\":\"$UNAME\"}" | jq -r '.pk')
if curl -sf -H "$H" "$API/core/applications/opnsense-saml/" >/dev/null 2>&1; then
  curl -s -H "$H" -H "$CT" -X PATCH "$API/core/applications/opnsense-saml/" \
    -d "{\"provider\":$SAML_PROV}" >/dev/null
else
  curl -s -H "$H" -H "$CT" -X POST "$API/core/applications/" \
    -d "{\"name\":\"OPNsense SAML\",\"slug\":\"opnsense-saml\",\"provider\":$SAML_PROV}" >/dev/null
fi
# Same for the SAML provider's ACS and audience.
curl -s -H "$H" -H "$CT" -X PATCH "$API/providers/saml/$SAML_PROV/" \
  -d "{\"acs_url\":\"$SP_BASE/api/sso/saml/acs$SP_Q\",\"audience\":\"$SP_BASE/api/sso/saml/metadata$SP_Q\"}" >/dev/null

# SAML signing cert (use="signing") from the provider metadata
SAML_CERT=$(curl -s -H "$H" "$API/providers/saml/$SAML_PROV/metadata/" \
  | jq -r '.metadata' | grep -o '<ds:X509Certificate>[^<]*' | head -1 | sed 's/<ds:X509Certificate>//')

# --- SCIM provider (provisioning) ---
# Attached to the application as a BACKCHANNEL provider: an application already has
# the OIDC one on its front channel, and without that attachment the SCIM sync has an
# empty user scope and silently does nothing.
SCIM_TOKEN="${SCIM_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -d '=+/')}"
SCIM_MAPS=$(curl -s -H "$H" "$API/propertymappings/provider/scim/?page_size=20" \
  | jq -c '[.results[] | select(.name|test("User")) | .pk]')
SCIM_GMAPS=$(curl -s -H "$H" "$API/propertymappings/provider/scim/?page_size=20" \
  | jq -c '[.results[] | select(.name|test("Group")) | .pk]')
SCIM_PROV=$(curl -s -H "$H" "$API/providers/scim/?name=opnsense-scim" | jq -r '.results[0].pk // empty')
if [ -z "$SCIM_PROV" ]; then
  SCIM_PROV=$(curl -s -H "$H" -H "$CT" -X POST "$API/providers/scim/" -d "{
    \"name\":\"opnsense-scim\",\"url\":\"$SP_BASE/api/sso/scim\",\"token\":\"$SCIM_TOKEN\",
    \"exclude_users_service_account\":true,
    \"property_mappings\":$SCIM_MAPS,\"property_mappings_group\":$SCIM_GMAPS}" | jq -r '.pk')
fi
# verify_certificates off: the lab firewall serves a self-signed certificate, and the
# sync fails silently (status "done", nothing pushed) when it cannot verify it.
curl -s -H "$H" -H "$CT" -X PATCH "$API/providers/scim/$SCIM_PROV/" -d "{
  \"url\":\"$SP_BASE/api/sso/scim\",\"token\":\"$SCIM_TOKEN\",\"verify_certificates\":false}" >/dev/null
curl -s -H "$H" -H "$CT" -X PATCH "$API/core/applications/opnsense/" \
  -d "{\"backchannel_providers\":[$SCIM_PROV]}" >/dev/null
echo ">>> scim provider pk=$SCIM_PROV"

cat > /tmp/authentik-out.env <<EOF
SCIM_TOKEN=$SCIM_TOKEN
SCIM_PROVIDER_PK=$SCIM_PROV
OIDC_CLIENT_ID=$OIDC_CID
OIDC_CLIENT_SECRET=$OIDC_SEC
OIDC_ISSUER=https://authentik.test:9443/application/o/opnsense
SAML_IDP_ENTITY=https://authentik.test:9443/application/saml/opnsense-saml/metadata/
SAML_IDP_SSO=https://authentik.test:9443/application/saml/opnsense-saml/sso/binding/redirect/
SAML_CERT=$SAML_CERT
EOF
echo ">>> done -> /tmp/authentik-out.env"
grep -vE 'SECRET|CERT' /tmp/authentik-out.env
