#!/usr/bin/env bash
# Register the lab's OIDC and SAML authentication servers in the OPNsense VM.
#
# This step used to exist only in the config.xml of whichever VM had been around
# longest: `up.sh` configures the IdPs and the setup scripts create the clients, but
# nothing ever told OPNsense about them. On a VM that had accumulated them by hand it
# looked like there was no step at all -- until a freshly built box turned up with no
# authentication servers and half the end-to-end suites failed on a provider that did
# not exist. Scripting it also removes the class of mistake that hid the SAML failure
# the first time: passing AS_IDP_X instead of AS_IDP_X509 registers an empty signing
# certificate, and the SP metadata then comes back without an EntityID.
#
# Reads whatever the IdP setup wrote (/tmp/kc-out.env or /tmp/authentik-out.env), so it
# is always the values that were actually provisioned rather than a second guess.
#
# Usage:
#   IDP=keycloak  SP_BASE=https://192.168.60.10 test/vagrant/register-authservers.sh
#   IDP=authentik SP_BASE=https://192.168.60.10 test/vagrant/register-authservers.sh
set -euo pipefail
cd "$(dirname "$0")/.."          # test/

IDP="${IDP:-keycloak}"
SP_BASE="${SP_BASE:-${SSO_GUI_URL:-https://192.168.60.10}}"

case "$IDP" in
    keycloak)  ENVFILE=/tmp/kc-out.env;        OIDC_NAME=keycloak;  SAML_NAME=keycloak-saml ;;
    authentik) ENVFILE=/tmp/authentik-out.env; OIDC_NAME=authentik; SAML_NAME=authentik-saml ;;
    *) echo "IDP must be keycloak or authentik (got '$IDP')" >&2; exit 1 ;;
esac

if [ ! -r "$ENVFILE" ]; then
    echo "$ENVFILE is missing -- run the $IDP setup script first (see test/README.md)" >&2
    exit 1
fi

# Read the file rather than sourcing it: SAML_CERT is a bare base64 blob and a stray
# character in an IdP-generated value should not become shell.
val() { sed -n "s/^$1=//p" "$ENVFILE" | head -1; }

OIDC_CLIENT_ID=$(val OIDC_CLIENT_ID)
OIDC_CLIENT_SECRET=$(val OIDC_CLIENT_SECRET)
OIDC_ISSUER=$(val OIDC_ISSUER)
SAML_IDP_ENTITY=$(val SAML_IDP_ENTITY)
SAML_IDP_SSO=$(val SAML_IDP_SSO)
SAML_CERT=$(val SAML_CERT)

for required in OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_ISSUER SAML_IDP_ENTITY SAML_IDP_SSO SAML_CERT; do
    eval "value=\${$required}"
    if [ -z "$value" ]; then
        echo "$ENVFILE has no $required -- re-run the $IDP setup script" >&2
        exit 1
    fi
done

HELPER=/home/vagrant/os-sso/test/vagrant/add_authserver.php

# One base64-encoded env file per server, rather than values interpolated into a nested
# `vagrant ssh -c "sudo sh -c '...'"`: the SAML certificate is a ~900 character base64
# blob, and that nesting is exactly how it silently arrives empty (which is what left
# the SP metadata with no EntityID and took the SAML suite down with it).
register() {
    blob=$(printf '%s' "$1" | base64 -w0)
    vagrant ssh -c "echo $blob | b64decode -r > /tmp/as.env && sudo sh -c '
        set -a; . /tmp/as.env; set +a; php $HELPER; rm -f /tmp/as.env'" 2>&1 \
        | grep -vE '^Warning: Permanently added|^$'
}

# Registering is a setup step, so an existing server is left alone by default: the
# suites write their own settings onto these (SCIM token, service scope, session
# lifetime), and recreating one mid-run silently discards all of it. FORCE=1 replaces
# instead, which is what repairs a registration made with the wrong values.
register "AS_REPLACE=${FORCE:-0}
AS_TYPE=oidc
AS_NAME=$OIDC_NAME
AS_LABEL=$OIDC_NAME
AS_ISSUER=$OIDC_ISSUER
AS_CLIENT_ID=$OIDC_CLIENT_ID
AS_CLIENT_SECRET=$OIDC_CLIENT_SECRET
AS_BASE_URL=$SP_BASE"

register "AS_REPLACE=${FORCE:-0}
AS_TYPE=saml
AS_NAME=$SAML_NAME
AS_LABEL=$SAML_NAME
AS_IDP_ENTITY=$SAML_IDP_ENTITY
AS_IDP_SSO=$SAML_IDP_SSO
AS_IDP_X509=$SAML_CERT
AS_BASE_URL=$SP_BASE"

echo ">>> registered '$OIDC_NAME' (oidc) and '$SAML_NAME' (saml) with base URL $SP_BASE"
