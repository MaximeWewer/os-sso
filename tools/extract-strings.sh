set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/lang/os-sso.pot"

command -v xgettext >/dev/null 2>&1 || {
    echo "os-sso: xgettext is missing (pkg install gettext-tools)" >&2
    exit 1
}

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM

mkdir -p "$ROOT/lang"
cd "$ROOT"

find src \( -name '*.php' -o -name '*.inc' -o -name '*.volt' \) \
    | grep -v '/vendor/' \
    | sort > "$STAGE/POTFILES"

# Volt is not PHP. xgettext's PHP lexer only reads what sits inside <?php ... ?>,
# so handed a template as-is it returns nothing at all, and an apostrophe in the
# surrounding HTML is enough to swallow whatever it did reach. Stage each view as
# its lang._() calls and nothing else, one output line per input line, so the #:
# references still name the volt line the string came from.
while read -r f; do
    case "$f" in
        *.volt) ;;
        *) continue ;;
    esac
    mkdir -p "$STAGE/$(dirname "$f")"
    awk '
        {
            out = ""
            rest = $0
            while (match(rest, /lang\._\([ \t]*("[^"]*"|'"'"'[^'"'"']*'"'"')[ \t]*\)/)) {
                out = out substr(rest, RSTART, RLENGTH) "; "
                rest = substr(rest, RSTART + RLENGTH)
            }
            if (index(rest, "lang._(") > 0) {
                printf "%s:%d: lang._() must open and close on one line\n", FILENAME, FNR \
                    > "/dev/stderr"
                bad = 1
            }
            print (out == "" ? "" : "<?php " out "?>")
        }
        END { if (bad) exit 1 }
    ' "$f" > "$STAGE/$f"
done < "$STAGE/POTFILES"

# --directory is searched in order, so a staged view shadows the real one and
# everything else is read from the tree.
xgettext \
    --directory="$STAGE" \
    --directory="$ROOT" \
    --files-from="$STAGE/POTFILES" \
    --language=PHP \
    --from-code=UTF-8 \
    --keyword=gettext \
    --keyword=lang._ \
    --package-name=os-sso \
    --copyright-holder="Maxime Wewer" \
    --msgid-bugs-address=https://github.com/MaximeWewer/os-sso/issues \
    --add-comments \
    --sort-by-file \
    --output="$STAGE/os-sso.pot"

# xgettext leaves the placeholder charset behind, which msgfmt refuses to read as
# UTF-8 and every merge tool then guesses at.
sed 's/charset=CHARSET/charset=UTF-8/' "$STAGE/os-sso.pot" > "$OUT"

msgfmt --check-format --output-file=/dev/null "$OUT"
echo "$OUT"
