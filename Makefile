PLUGIN_NAME=            sso
PLUGIN_VERSION=         0.0.0-dev
PLUGIN_COMMENT=         SSO (OIDC + SAML + JWT) and SCIM provisioning for WebGUI / Captive Portal / VPN
PLUGIN_MAINTAINER=      https://github.com/MaximeWewer
# php${PLUGIN_PHP}-*, never a hardcoded major: OPNsense 25.7/26.1 are FreeBSD 14 with
# php83, 26.7 is FreeBSD 15 with php85, and a package naming php83-curl on 26.7 refuses
# to install at all ("Missing dependency 'php83-curl'"). Mk/defaults.mk derives
# PLUGIN_PHP from the php binary on the build host; the release workflow has no php in
# its build VM and passes it per ABI on the make command line instead.
PLUGIN_DEPENDS=         php${PLUGIN_PHP}-curl php${PLUGIN_PHP}-dom php${PLUGIN_PHP}-xml \
                        php${PLUGIN_PHP}-mbstring php${PLUGIN_PHP}-gettext zip

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
		cd ${COMPOSER_DIR} && composer install --no-dev --no-interaction \
			--classmap-authoritative --no-scripts --no-plugins; \
	fi
