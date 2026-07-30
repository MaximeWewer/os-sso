#!/bin/sh
# os-sso: collect the translatable strings into lang/os-sso.pot.
#
# OPNsense has ONE gettext domain ("OPNsense", bound to /usr/local/share/locale by
# authgui.inc) and the catalogues live in the opnsense/lang repository, built from the
# core and plugin sources. A plugin therefore does not ship a catalogue of its own --
# doing so would collide with the domain everything else uses. What it owes translators
# is that every user-facing string is reachable by the scanner, which is what this
# template makes checkable: run it, read the diff, and anything user-facing that is
# missing from it is a string somebody forgot to wrap.
#
#   sh tools/extract-strings.sh          # rewrite lang/os-sso.pot
#
# Needs xgettext (devel/gettext-tools). The volt templates are scanned as PHP: their
# {{ lang._('...') }} calls are what the WebGUI resolves at render time.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/lang/os-sso.pot"

command -v xgettext >/dev/null 2>&1 || {
    echo "os-sso: xgettext is missing (pkg install gettext-tools)" >&2
    exit 1
}

mkdir -p "$ROOT/lang"
cd "$ROOT"

# Volt is not a language xgettext knows; it reads them as PHP, which is enough to find
# lang._() and gettext() calls. Vendored libraries are somebody else's strings.
# Model and form XML carry labels and help too; those are translated by the WebGUI's
# own renderer at display time and xgettext cannot see inside XML, which is a limitation
# of the toolchain rather than of this script -- core has the same one.
find src \( -name '*.php' -o -name '*.volt' \) \
    | grep -v '/vendor/' \
    | sort > /tmp/os-sso-potfiles.$$

xgettext \
    --files-from=/tmp/os-sso-potfiles.$$ \
    --language=PHP \
    --from-code=UTF-8 \
    --keyword=gettext \
    --keyword=lang._ \
    --package-name=os-sso \
    --copyright-holder="Maxime Wewer" \
    --msgid-bugs-address=https://github.com/MaximeWewer/os-sso/issues \
    --add-comments \
    --sort-by-file \
    --output="$OUT"

rm -f /tmp/os-sso-potfiles.$$
echo "$OUT"
