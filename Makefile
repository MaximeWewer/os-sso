PLUGIN_NAME=            sso
PLUGIN_VERSION=         2026.6.2
PLUGIN_COMMENT=         Interactive SSO (OIDC + SAML + JWT) authentication for WebGUI / Captive Portal / VPN
PLUGIN_MAINTAINER=      https://github.com/MaximeWewer
PLUGIN_DEPENDS=         php83-curl php83-dom php83-xml php83-mbstring

# Composer-vendored runtime libraries.
# Vendored into src/opnsense/mvc/app/library/OPNsense/SSO/vendor at build time.
COMPOSER_DIR=           ${.CURDIR}/src/opnsense/mvc/app/library/OPNsense/SSO

.include "../../Mk/plugins.mk"

# Pull composer deps before packaging. Skipped when vendor/ is already present
# (the CI vendors on the host runner, so the FreeBSD build VM needs no composer).
post-extract:
	@if [ -f ${COMPOSER_DIR}/vendor/autoload.php ]; then \
		echo ">>> os-sso: vendor/ already present, skipping composer"; \
	elif [ -f ${COMPOSER_DIR}/composer.json ]; then \
		echo ">>> vendoring composer deps for os-sso"; \
		cd ${COMPOSER_DIR} && composer install --no-dev --no-interaction --classmap-authoritative; \
	fi
