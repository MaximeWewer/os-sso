#!/bin/sh
# Bring the Captive Portal up in the lab with the os-sso template installed.
# Run inside the VM as root. Idempotent.
#
#   CP_AUTH=keycloak sh setup-cp.sh          # zone bound to that SSO provider
#
# The ordering here is the part that is easy to get wrong:
#   1. the zone has to exist in config.xml BEFORE the templates are rendered --
#      that render is what writes /etc/rc.conf.d/captiveportal, and without it the
#      service refuses to start ("Set captiveportal_enable to YES");
#   2. the template has to be stored and assigned to the zone BEFORE the SECOND
#      render, because the zone->template link is read from the generated ini;
#   3. only then does overlay_template.py drop our index.html into the zone htdocs.
# Creating zones by writing config.xml directly (as the e2e helpers do) skips step 1,
# which is why the portal looks "broken" until this script runs.
set -eu

H=$(dirname "$0")
AUTH=${CP_AUTH:-keycloak}
DESC=${CP_DESC:-sso-cp-test}

echo ">>> zone (bound to $AUTH)"
ZONE=$(CP_DESC="$DESC" CP_AUTH="$AUTH" php "$H/add_cp_zone.php")
echo "    zoneid=$ZONE"

echo ">>> building the os-sso portal template"
ZIP=$(configctl sso build_cp_template)
echo "    $ZIP"

echo ">>> storing it and assigning it to the zone"
# NB: the template NAME may not contain a hyphen -- the core model's mask allows
# letters, digits, '.', ',', '_' and spaces only.
php -r "
require_once('config.inc'); require_once('util.inc'); require_once('script/load_phalcon.php');
\$mdl = new OPNsense\CaptivePortal\CaptivePortal();
\$content = base64_encode(file_get_contents('$ZIP'));
\$tpl = null;
foreach (\$mdl->templates->template->iterateItems() as \$t) {
    if ((string)\$t->name === 'os_sso') { \$tpl = \$t; break; }
}
if (\$tpl === null) {
    \$tpl = \$mdl->templates->template->Add();
    \$tpl->fileid = str_replace('.', '', uniqid('', true));
    \$tpl->name = 'os_sso';
}
\$tpl->content = \$content;
foreach (\$mdl->zones->zone->iterateItems() as \$z) {
    if ((string)\$z->zoneid === '$ZONE') { \$z->template = \$tpl->getAttributes()['uuid']; }
}
\$messages = \$mdl->performValidation();
foreach (\$messages as \$msg) { fwrite(STDERR, 'validation: ' . \$msg->getMessage() . PHP_EOL); }
if (count(\$messages) > 0) { exit(1); }
\$mdl->serializeToConfig();
OPNsense\Core\Config::getInstance()->save();
"

echo ">>> rendering the captive portal templates (writes rc.conf.d + the zone ini)"
configctl template reload OPNsense/Captiveportal >/dev/null

echo ">>> unpacking the template into the zone document root"
(cd /usr/local/opnsense/scripts/captiveportal && python3 overlay_template.py "$ZONE")

echo ">>> starting the service"
configctl captiveportal start >/dev/null
sleep 2
configctl captiveportal status

PORT=$((8000 + ZONE))
echo ">>> zone $ZONE listens on port $PORT:"
sockstat -4l | grep ":$PORT" || echo "    (no listener -- check /var/log/lighttpd)"
echo ">>> our template is in place:"
grep -c 'portal/providers' "/var/captiveportal/zone$ZONE/htdocs/index.html" >/dev/null \
    && echo "    /var/captiveportal/zone$ZONE/htdocs/index.html carries the SSO buttons" \
    || echo "    !! the zone is still serving the default template"
