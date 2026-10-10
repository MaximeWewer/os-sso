<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;
use OPNsense\SSO\LocalAccountWriter;

/**
 * Give the accounts os-sso created before this version the uuid they were missing.
 *
 * create() used to write <user> without a uuid attribute, which leaves the account
 * listed but impossible to open or delete in System > Access > Users (issue #8).
 * Only os-sso's own accounts are touched; run_migrations.php saves config.xml.
 */
class M1_0_4 extends BaseModelMigration
{
    public function run($model)
    {
        $accounts = new LocalAccountWriter();
        foreach (Config::getInstance()->object()->system->user ?? [] as $user) {
            if ($accounts->isSsoManaged($user)) {
                LocalAccountWriter::ensureUuid($user);
            }
        }

        parent::run($model);
    }
}
