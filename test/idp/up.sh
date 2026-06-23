#!/usr/bin/env bash
# Bring up the split IdP stacks: shared network + Authentik + Keycloak + proxy.
# Usage: ./up.sh            (all)
#        ./up.sh authentik  (one stack + proxy)
#        ./up.sh keycloak
set -euo pipefail
cd "$(dirname "$0")"

docker network inspect os-sso-idp >/dev/null 2>&1 || docker network create os-sso-idp

case "${1:-all}" in
  authentik) (cd authentik && docker compose up -d) ;;
  keycloak)  (cd keycloak  && docker compose up -d) ;;
  all)
    (cd authentik && docker compose up -d)
    (cd keycloak  && docker compose up -d)
    ;;
  *) echo "usage: $0 [all|authentik|keycloak]"; exit 1 ;;
esac

(cd proxy && docker compose up -d)
echo ">>> idp stacks up. Proxy: https://authentik.test:9443 / https://keycloak.test:9443"
