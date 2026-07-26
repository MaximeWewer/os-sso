#!/bin/sh
# os-sso: package the SSO captive-portal login page as an uploadable zone template.
#
# The captive portal takes templates as a zip holding index.html at its root. Building
# that zip by hand -- on a firewall, over SSH, from a directory most people never look
# in -- is the only reason the SSO portal page was not usable out of the box. This
# builds it; the operator then uploads it once under
# Services > Captive Portal > Administration > Templates and picks it on the zone.
set -eu

SRC=/usr/local/opnsense/scripts/OPNsense/SSO/cp-portal
OUT=${1:-/tmp/os-sso-cp-template.zip}

case "$OUT" in
    /*) ;;
    *) echo "output path must be absolute" >&2; exit 1 ;;
esac

if [ ! -f "$SRC/index.html" ]; then
    echo "os-sso: $SRC/index.html is missing" >&2
    exit 1
fi

# zip is a package dependency; if it is gone, something removed it after install.
command -v zip >/dev/null 2>&1 || {
    echo "os-sso: 'zip' is missing (it is an os-sso dependency: pkg install zip)" >&2
    exit 1
}

rm -f "$OUT"
# -j: flatten, index.html must sit at the root of the archive.
(cd "$SRC" && zip -q -j "$OUT" index.html)
chmod 600 "$OUT"

echo "$OUT"
