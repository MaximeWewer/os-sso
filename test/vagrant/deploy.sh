#!/bin/sh
# Provisioner: deploy os-sso from /vagrant into the live OPNsense tree and vendor
# composer deps. Idempotent; runs on every `vagrant up`/`provision`.
set -e

# The puzzle/opnsense box runs provisioners as the unprivileged vagrant user;
# re-exec under sudo so we can write into /usr/local/opnsense.
[ "$(id -u)" -eq 0 ] || exec sudo sh "$0" "$@"

# The box boots without a default route / working DNS on the NAT interface.
# Restore both (runtime-only; harmless if already set) so pkg/composer work.
route -n get default >/dev/null 2>&1 || route add default 10.0.2.2 >/dev/null 2>&1 || true
if ! host -W2 pkg.opnsense.org >/dev/null 2>&1; then
    printf 'nameserver 10.0.2.3\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi

# Map the IdP hostname to the NAT gateway (the host) so the issuer string
# https://authentik.test:9443 is identical to what the host browser uses.
grep -q 'authentik.test' /etc/hosts || echo '10.0.2.2 authentik.test' >> /etc/hosts
grep -q 'keycloak.test' /etc/hosts || echo '10.0.2.2 keycloak.test' >> /etc/hosts

# Trust the lab CA so the OIDC RP (libcurl uses the /etc/ssl/certs capath) accepts
# the Authentik issuer's TLS cert. FreeBSD way: drop the CA in a trusted dir and
# rehash. Lab-only; a real deployment uses a publicly-trusted IdP cert.
LAB_CA=/home/vagrant/os-sso/test/idp/certs/ca.crt
if [ -f "$LAB_CA" ] && ! [ -f /usr/share/certs/trusted/os-sso-lab-ca.pem ]; then
    mkdir -p /usr/share/certs/trusted
    cp "$LAB_CA" /usr/share/certs/trusted/os-sso-lab-ca.pem
    certctl rehash >/dev/null 2>&1 && echo ">>> os-sso: lab CA trusted (certctl rehash)"
fi

# Source rsynced here by Vagrant's synced_folder (.. -> /home/vagrant/os-sso) on
# every `vagrant up`/`provision` -- vendored libs included. No manual push needed.
SRC=/home/vagrant/os-sso/src/opnsense/mvc/app
DST=/usr/local/opnsense/mvc/app
SSO_LIB="$DST/library/OPNsense/SSO"

echo ">>> os-sso: deploying source into the live tree"
mkdir -p "$DST/library/OPNsense/Auth/SSOProviders" \
         "$DST/controllers/OPNsense/SSO/Api"

cp -R "$SRC/library/OPNsense/SSO"                          "$DST/library/OPNsense/"
cp    "$SRC/library/OPNsense/Auth/SsoOidc.php"             "$DST/library/OPNsense/Auth/"
cp    "$SRC/library/OPNsense/Auth/SsoSaml.php"             "$DST/library/OPNsense/Auth/"
cp    "$SRC/library/OPNsense/Auth/SsoJwt.php"              "$DST/library/OPNsense/Auth/"
cp    "$SRC/library/OPNsense/Auth/SSOProviders/SsoProviderContainer.php" \
      "$DST/library/OPNsense/Auth/SSOProviders/"
cp -R "$SRC/controllers/OPNsense/SSO"                      "$DST/controllers/OPNsense/"
mkdir -p "$DST/models/OPNsense"
cp -R "$SRC/models/OPNsense/SSO"                           "$DST/models/OPNsense/"
# Re-pointed Logout menu item -> drop the cached menu so it rebuilds.
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml 2>/dev/null || true

echo ">>> os-sso: runtime libs"
# The appliance PHP CLI has no phar + allow_url_fopen=off, so composer cannot run
# here. Vendored sources + a hand-written PSR-4 autoloader are shipped in the tree
# (see vendor/autoload.php). Nothing to install if that autoloader is present.
if [ -f "$SSO_LIB/vendor/autoload.php" ]; then
    echo "    vendor/autoload.php present (pre-vendored on the host)"
else
    echo "!! vendor/autoload.php missing -- OIDC will fail until php-jwt is vendored"
fi

echo ">>> os-sso: deploying VPN deferred-auth bits"
SVC_SRC=/home/vagrant/os-sso/src/opnsense
# OpenVPN auth-user-pass-verify hook + its lab config
mkdir -p /usr/local/etc/sso
cp "$SVC_SRC/service/templates/OPNsense/SSO/auth-user-pass-verify.sh" /usr/local/etc/sso/
chmod 0700 /usr/local/etc/sso/auth-user-pass-verify.sh
if [ ! -f /usr/local/etc/sso/vpn.conf ]; then
    printf 'PROTOCOL=oidc\nPROVIDER=keycloak\nHOST=localhost:8443\nTIMEOUT=180\n' > /usr/local/etc/sso/vpn.conf
fi
# privileged verdict writer + configd action
mkdir -p /usr/local/opnsense/scripts/OPNsense/SSO
cp "$SVC_SRC/scripts/OPNsense/SSO/vpn_verdict.sh" /usr/local/opnsense/scripts/OPNsense/SSO/
chmod 0755 /usr/local/opnsense/scripts/OPNsense/SSO/vpn_verdict.sh
cp "$SVC_SRC/service/conf/actions.d/actions_sso.conf" /usr/local/opnsense/service/conf/actions.d/
service configd restart >/dev/null 2>&1 || true

echo ">>> os-sso: restarting the WebGUI to pick up new classes"
/usr/local/etc/rc.restart_webgui >/dev/null 2>&1 || service php_fpm restart || true

echo ">>> os-sso: deployed. Files:"
ls "$DST/library/OPNsense/SSO"
echo ">>> vendor:"
ls "$SSO_LIB/vendor" 2>/dev/null || echo "  (no vendor dir -- composer step failed)"
