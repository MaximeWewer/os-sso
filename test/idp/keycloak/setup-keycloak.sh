#!/usr/bin/env bash
# Configure Keycloak (realm + OIDC client + SAML client + test user) for os-sso.
set -euo pipefail
cd "$(dirname "$0")"
PW=$(grep KC_ADMIN_PASSWORD .env | cut -d= -f2)
KC=(docker exec keycloak /opt/keycloak/bin/kcadm.sh)
R=opnsense

"${KC[@]}" config credentials --server http://localhost:8080 --realm master --user admin --password "$PW" >/dev/null

# Realm (idempotent)
"${KC[@]}" get "realms/$R" >/dev/null 2>&1 || "${KC[@]}" create realms -s realm="$R" -s enabled=true >/dev/null
echo "realm: $R"

# --- OIDC client ---
CID=$("${KC[@]}" get clients -r "$R" -q clientId=opnsense-oidc --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
if [ -z "$CID" ]; then
  CID=$("${KC[@]}" create clients -r "$R" \
    -s clientId=opnsense-oidc -s protocol=openid-connect \
    -s publicClient=false -s standardFlowEnabled=true \
    -s 'redirectUris=["https://localhost:8443/api/sso/oidc/callback"]' \
    -s 'webOrigins=["+"]' -i 2>/dev/null | tr -d '\r')
fi
SECRET=$("${KC[@]}" get "clients/$CID/client-secret" -r "$R" 2>/dev/null | grep -o '"value"[^,]*' | cut -d'"' -f4)
echo "oidc_client_uuid=$CID"
echo "oidc_client_secret=$SECRET"

# --- SAML client (SP) ---
# Keycloak signs the assertion with the realm key; SP request signature not required.
SAML_ENTITY="https://localhost:8443/api/sso/saml/metadata"
SCID=$("${KC[@]}" get clients -r "$R" -q clientId="$SAML_ENTITY" --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
if [ -z "$SCID" ]; then
  # Fine-grained ACS + SLO URLs instead of adminUrl (the Master SAML Processing URL
  # would otherwise be used for BOTH ACS and the LogoutResponse, sending SLO replies
  # to /acs). Keep the SLO endpoint distinct so the round-trip lands on /slo.
  SCID=$("${KC[@]}" create clients -r "$R" \
    -s clientId="$SAML_ENTITY" -s protocol=saml \
    -s 'redirectUris=["https://localhost:8443/api/sso/saml/acs"]' \
    -s frontchannelLogout=true \
    -s 'attributes."saml.assertion.signature"=true' \
    -s 'attributes."saml.server.signature"=true' \
    -s 'attributes."saml.client.signature"=false' \
    -s 'attributes."saml_name_id_format"=username' \
    -s 'attributes."saml_force_name_id_format"=true' \
    -s 'attributes."saml_assertion_consumer_url_post"=https://localhost:8443/api/sso/saml/acs' \
    -s 'attributes."saml_assertion_consumer_url_redirect"=https://localhost:8443/api/sso/saml/acs' \
    -s 'attributes."saml_single_logout_service_url_redirect"=https://localhost:8443/api/sso/saml/slo' \
    -s 'attributes."saml_single_logout_service_url_post"=https://localhost:8443/api/sso/saml/slo' \
    -i 2>/dev/null | tr -d '\r')
fi
echo "saml_client_uuid=$SCID"

# --- test user ---
UID_=$("${KC[@]}" get users -r "$R" -q username=kctest --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
if [ -z "$UID_" ]; then
  UID_=$("${KC[@]}" create users -r "$R" -s username=kctest -s enabled=true \
    -s email=kctest@example.com -s firstName=KC -s lastName=Test -s emailVerified=true \
    -i 2>/dev/null | tr -d '\r')
fi
"${KC[@]}" set-password -r "$R" --userid "$UID_" --new-password 'Test12345!' 2>/dev/null || true
echo "user_uuid=$UID_"

# --- IdP SAML signing certificate (for the OPNsense SP to trust) ---
"${KC[@]}" get "keys" -r "$R" 2>/dev/null | grep -o '"certificate"[^,]*' | head -1 | cut -d'"' -f4 > /tmp/kc-saml-cert.txt || true
echo "saml_cert_written=$(wc -c </tmp/kc-saml-cert.txt 2>/dev/null || echo 0)"

# Persist OIDC creds for the next step
printf 'OIDC_CLIENT_ID=opnsense-oidc\nOIDC_CLIENT_SECRET=%s\nSAML_ENTITY=%s\n' "$SECRET" "$SAML_ENTITY" > /tmp/kc-out.env
echo "DONE"
