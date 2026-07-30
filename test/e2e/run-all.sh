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

# How far the VM clock may be off before it is corrected. The signing checks tolerate
# 60s of skew (OidcProtocol::LEEWAY, and the JWT clock-skew setting), so anything under a
# few seconds is nothing; the margin above that is what a long run can eat into.
CLOCK_TOLERANCE="${SSO_CLOCK_TOLERANCE:-5}"

# Bring the VM clock back in line with the host's.
#
# A VirtualBox guest that was suspended and resumed drifts, and the WAN interface is
# disabled in this lab so its own NTP has no route out. When the drift passes the leeway,
# every browser login fails on the ID token instead of the clock:
#
#   os-sso oidc: Cannot handle token with iat prior to 2026-07-30T12:14:38+00:00
#
# The IdPs run on the host, so the host clock is the reference. Set SSO_SKIP_CLOCK_SYNC=1
# to leave the guest alone.
sync_vm_clock() {
    [ -n "${SSO_SKIP_CLOCK_SYNC:-}" ] && return 0

    local host_epoch vm_epoch drift
    host_epoch=$(date -u +%s)
    vm_epoch=$(vagrant ssh -c 'date -u +%s' 2>/dev/null | tr -d '\r')
    case "$vm_epoch" in
        '' | *[!0-9]*)
            echo ">>> clock: cannot read the VM clock, skipping the check (is the VM up?)"
            return 0
            ;;
    esac

    # Includes the ssh round trip, which is why the tolerance is seconds and not zero.
    drift=$((vm_epoch - host_epoch))
    [ "$drift" -lt 0 ] && drift=$((-drift))
    if [ "$drift" -le "$CLOCK_TOLERANCE" ]; then
        return 0
    fi

    echo ">>> clock: the VM is ${drift}s off the host, resynchronising"
    if vagrant ssh -c "sudo date -u $(date -u +%Y%m%d%H%M.%S)" >/dev/null 2>&1; then
        echo ">>> clock: set from the host"
    else
        echo ">>> clock: WARNING could not set it; logins may fail on token freshness"
    fi
}

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

sync_vm_clock

for suite in $WANT; do
    case " $HOST_SUITES " in *" $suite "*) run_host "$suite"; continue ;; esac
    case " $VM_SUITES "   in *" $suite "*) run_vm   "$suite"; continue ;; esac
    echo "unknown suite '$suite'"; rc=1
done

echo ""
[ "$rc" -eq 0 ] && echo "### ALL SUITES PASSED" || echo "### SOME SUITES FAILED"
exit "$rc"
