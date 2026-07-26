#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * End WebGUI sessions os-sso opened that have reached their absolute lifetime, and
 * forget the records of sessions that are gone anyway.
 *
 * The WebGUI's own timeout is an IDLE timeout: someone who keeps a tab open keeps the
 * session, however long ago -- and under whatever group membership -- they logged in.
 * A maximum session lifetime is what forces them back through the IdP, and nothing in
 * a request-driven plugin can enforce it on a session that never makes a request to
 * us. Hence this: schedule it under System > Settings > Cron ("os-sso: expire SSO
 * sessions"), and it also runs opportunistically on every SSO login.
 */

require_once 'config.inc';
require_once 'util.inc';

use OPNsense\SSO\SessionRegistry;

$killed = SessionRegistry::sweep();
if ($killed > 0) {
    syslog(LOG_NOTICE, sprintf('os-sso: ended %d expired SSO session(s)', $killed));
}
echo sprintf("expired %d session(s)\n", $killed);
