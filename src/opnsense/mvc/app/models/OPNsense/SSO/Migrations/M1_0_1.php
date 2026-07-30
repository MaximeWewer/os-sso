<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

/**
 * The single OpenVPN web-auth setting becomes the first of a list of profiles.
 *
 * A firewall runs more than one OpenVPN instance often enough that one global provider,
 * host and timeout was the wrong shape. The old node is read straight from config.xml --
 * the model no longer describes those fields, so the model cannot see them -- and lands
 * as a profile named "default", which is also the profile a server that passes no
 * argument to the script gets. So an upgrade keeps working with nothing to re-enter.
 */
class M1_0_1 extends BaseModelMigration
{
    public function run($model)
    {
        $vpn = Config::getInstance()->object()->OPNsense->SSO->settings->vpn ?? null;
        // Nothing configured, or already migrated (the old fields are gone once the
        // model saves the new shape).
        if ($vpn !== null && trim((string)($vpn->provider ?? '')) !== '') {
            $profile = $model->vpn->profiles->profile->Add();
            $profile->name = 'default';
            $profile->enabled = (string)($vpn->enabled ?? '0') === '1' ? '1' : '0';
            $profile->protocol = (string)($vpn->protocol ?? 'oidc');
            $profile->provider = (string)$vpn->provider;
            $profile->host = (string)($vpn->host ?? '');
            $profile->enforce_username = (string)($vpn->enforce_username ?? '0') === '1' ? '1' : '0';
            $timeout = (int)($vpn->timeout ?? 180);
            $profile->timeout = (string)($timeout >= 30 && $timeout <= 900 ? $timeout : 180);
        }

        parent::run($model);
    }
}
