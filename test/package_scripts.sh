#!/bin/sh

set -eu

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

export TEST_ROOT

cat > "$TEST_ROOT/sync" <<'EOF'
#!/bin/sh
echo "sync:$*" >> "$TEST_ROOT/log"
EOF

cat > "$TEST_ROOT/guard" <<'EOF'
#!/bin/sh
case "$1" in
    onestatus)
        test -f "$TEST_ROOT/running"
        ;;
    onestart)
        echo onestart >> "$TEST_ROOT/log"
        : > "$TEST_ROOT/running"
        ;;
    onerestart)
        echo onerestart >> "$TEST_ROOT/log"
        : > "$TEST_ROOT/running"
        ;;
    *)
        exit 64
        ;;
esac
EOF

chmod 755 "$TEST_ROOT/sync" "$TEST_ROOT/guard"

SSO_SYNC="$TEST_ROOT/sync" SSO_GUARD="$TEST_ROOT/guard" sh ./+POST_INSTALL.post
grep -qx 'sync:' "$TEST_ROOT/log"
grep -qx 'onestart' "$TEST_ROOT/log"

: > "$TEST_ROOT/log"
SSO_SYNC="$TEST_ROOT/sync" SSO_GUARD="$TEST_ROOT/guard" sh ./+POST_INSTALL.post
grep -qx 'sync:' "$TEST_ROOT/log"
grep -qx 'onerestart' "$TEST_ROOT/log"
