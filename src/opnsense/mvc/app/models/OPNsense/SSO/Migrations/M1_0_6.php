<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;
use OPNsense\SSO\AccountStamps;

/**
 * Move os-sso's account stamps out of <system><user>, where core's user model erases
 * them on every save (issue #13), and bring back the ones it already erased.
 * run_migrations.php saves config.xml.
 */
class M1_0_6 extends BaseModelMigration
{
    /** Where core keeps its config.xml revisions. */
    public const BACKUPS = '/conf/backup/config-*.xml';

    public function run($model)
    {
        foreach (Config::getInstance()->object()->system->user ?? [] as $user) {
            AccountStamps::adopt($user);
        }

        $backups = glob(self::BACKUPS) ?: [];
        rsort($backups); // config-<unix time>.xml: newest first
        foreach (AccountStamps::recover($backups) as $name) {
            syslog(LOG_NOTICE, sprintf(
                "os-sso: restored the SSO binding of '%s' from a configuration backup (lost to issue #13)",
                $name
            ));
        }

        AccountStamps::prune();
        parent::run($model);
    }
}
