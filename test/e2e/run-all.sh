#!/usr/bin/env bash
# Run every os-sso end-to-end suite and summarise.
#
# Two kinds of suite live here:
#   host-side (oidc.sh, saml.sh) drive a real browser ceremony, so they run where the
#     forwarded WebGUI port and the IdP hostname resolve -- the host;
#   VM-side (jwt.sh, cp.sh, vpn.sh) touch config.xml, configd and the OpenVPN hooks,
#     so they run as root inside the VM.
#
# Usage:
#   SSO_GUI_PORT=8444 ./run-all.sh                 # everything
#   SSO_GUI_PORT=8444 ./run-all.sh oidc saml       # a subset
#   SSO_GUI_PORT=8444 IDP=authentik ./run-all.sh   # against the other IdP
set -uo pipefail
# Work from this script's own directory whatever the caller's: every path below is
# relative to it (lib/, ../idp/), and the suites are started both from here and from
# run-all.sh. CDPATH= so a CDPATH in the environment cannot land us somewhere else, and
# -- so a path beginning with "-" is not read as an option. A symlink is followed where
# readlink can (GNU and FreeBSD both do), otherwise the guard below says so plainly.
self=$0
[ -L "$self" ] && self=$(readlink -f -- "$self" 2>/dev/null || printf '%s' "$self")
cd "$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)" || exit 1

PORT="${SSO_GUI_PORT:-8443}"
GUI_URL="${SSO_GUI_URL:-https://localhost:$PORT}"
IDP="${IDP:-keycloak}"
VM_SUITES="jwt cp vpn"
HOST_SUITES="oidc saml portal vpn-client scim"
WANT="${*:-$HOST_SUITES $VM_SUITES}"
rc=0

# Provider names follow the IdP: the lab registers "<idp>" and "<idp>-saml".
case "$IDP" in
    keycloak)  OIDC_PROVIDER=keycloak;  SAML_PROVIDER=keycloak-saml
               IDP_BASE="https://keycloak.test:9443/realms/opnsense"
               IDP_USER="${KC_USER:-kctest}"; IDP_PASS="${KC_PASS:-Test12345!}" ;;
    authentik) OIDC_PROVIDER=authentik; SAML_PROVIDER=authentik-saml
               IDP_BASE="https://authentik.test:9443"
               IDP_USER="${AK_USER:-akadmin}"
               # Read straight from the stack's .env rather than through a pipeline:
               # the bootstrap password is generated and nobody types it in by hand.
               IDP_PASS="${AK_PASS:-$(python3 -c '
import sys
for line in open("../idp/authentik/.env"):
    if line.startswith("AUTHENTIK_BOOTSTRAP_PASSWORD="):
        print(line.split("=", 1)[1].strip()); break
')}" ;;
    *) echo "unknown IDP '$IDP' (keycloak|authentik)"; exit 1 ;;
esac

run_host() {
    echo "############ ${1} (host, idp=$IDP) ############"
    SSO_GUI_PORT="$PORT" SSO_GUI_URL="$GUI_URL" IDP="$IDP" IDP_BASE="$IDP_BASE" \
    IDP_USER="$IDP_USER" IDP_PASS="$IDP_PASS" \
    SSO_PROVIDER="$OIDC_PROVIDER" SSO_SAML_PROVIDER="$SAML_PROVIDER" \
        bash "./$1.sh" || rc=1
}

run_vm() {
    echo "############ ${1} (VM) ############"
    vagrant ssh -c "sudo sh /home/vagrant/os-sso/test/e2e/$1.sh" 2>/dev/null || rc=1
}

for suite in $WANT; do
    case " $HOST_SUITES " in *" $suite "*) run_host "$suite"; continue ;; esac
    case " $VM_SUITES "   in *" $suite "*) run_vm   "$suite"; continue ;; esac
    echo "unknown suite '$suite'"; rc=1
done

echo ""
[ "$rc" -eq 0 ] && echo "### ALL SUITES PASSED" || echo "### SOME SUITES FAILED"
exit "$rc"
