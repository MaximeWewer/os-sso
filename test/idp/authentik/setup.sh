#!/usr/bin/env bash
# Configure a fresh Authentik: OIDC provider+app, SAML provider+app, then print the
# values needed for the OPNsense auth servers to /tmp/authentik-out.env.
set -euo pipefail
cd "$(dirname "$0")"
TOK=$(grep AUTHENTIK_BOOTSTRAP_TOKEN .env | cut -d= -f2-)
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
OIDC_PROV=$(curl -s -H "$H" -H "$CT" -X POST "$API/providers/oauth2/" -d "{
  \"name\":\"opnsense-oidc\",\"authorization_flow\":\"$AUTHZ\",\"invalidation_flow\":\"$INVAL\",
  \"client_type\":\"confidential\",\"signing_key\":\"$SIGN\",\"include_claims_in_id_token\":true,
  \"sub_mode\":\"user_username\",\"grant_types\":[\"authorization_code\",\"refresh_token\"],
  \"redirect_uris\":[{\"matching_mode\":\"strict\",\"url\":\"https://localhost:8443/api/sso/oidc/callback\"}],
  \"property_mappings\":$SCOPES}" | jq -r '.pk')
OIDC_CID=$(curl -s -H "$H" "$API/providers/oauth2/$OIDC_PROV/" | jq -r '.client_id')
OIDC_SEC=$(curl -s -H "$H" "$API/providers/oauth2/$OIDC_PROV/" | jq -r '.client_secret')
curl -s -H "$H" -H "$CT" -X POST "$API/core/applications/" \
  -d "{\"name\":\"OPNsense\",\"slug\":\"opnsense\",\"provider\":$OIDC_PROV}" >/dev/null

echo ">>> creating SAML provider + app"
# Attribute mappings: without at least one, Authentik emits an EMPTY
# <AttributeStatement/>, which is invalid per the SAML schema and php-saml (strict)
# rejects the whole response. Attach the default SAML mappings (Email/Groups/Name/...)
# -- they also carry the groups os-sso maps to OPNsense groups.
SAML_MAPS=$(curl -s -H "$H" "$API/propertymappings/provider/saml/?page_size=50" \
  | jq -c '[.results[] | select(.name|contains("default SAML Mapping")) | .pk]')
SAML_PROV=$(curl -s -H "$H" -H "$CT" -X POST "$API/providers/saml/" -d "{
  \"name\":\"opnsense-saml\",\"authorization_flow\":\"$AUTHZ\",\"invalidation_flow\":\"$INVAL\",
  \"acs_url\":\"https://localhost:8443/api/sso/saml/acs\",
  \"issuer\":\"https://authentik.test:9443/application/saml/opnsense-saml/\",
  \"audience\":\"https://localhost:8443/api/sso/saml/metadata\",
  \"sp_binding\":\"post\",\"signing_kp\":\"$SIGN\",\"sign_assertion\":true,\"sign_response\":false,
  \"property_mappings\":$SAML_MAPS,
  \"name_id_mapping\":\"$UNAME\"}" | jq -r '.pk')
curl -s -H "$H" -H "$CT" -X POST "$API/core/applications/" \
  -d "{\"name\":\"OPNsense SAML\",\"slug\":\"opnsense-saml\",\"provider\":$SAML_PROV}" >/dev/null
# SAML signing cert (use="signing") from the provider metadata
SAML_CERT=$(curl -s -H "$H" "$API/providers/saml/$SAML_PROV/metadata/" \
  | jq -r '.metadata' | grep -o '<ds:X509Certificate>[^<]*' | head -1 | sed 's/<ds:X509Certificate>//')

cat > /tmp/authentik-out.env <<EOF
OIDC_CLIENT_ID=$OIDC_CID
OIDC_CLIENT_SECRET=$OIDC_SEC
OIDC_ISSUER=https://authentik.test:9443/application/o/opnsense
SAML_IDP_ENTITY=https://authentik.test:9443/application/saml/opnsense-saml/metadata/
SAML_IDP_SSO=https://authentik.test:9443/application/saml/opnsense-saml/sso/binding/redirect/
SAML_CERT=$SAML_CERT
EOF
echo ">>> done -> /tmp/authentik-out.env"
grep -vE 'SECRET|CERT' /tmp/authentik-out.env
