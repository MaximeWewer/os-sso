<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\SSO\LocalAccountWriter;

/**
 * Report the accounts an earlier os-sso gave an uid already in use (GHSA-wvvw-f723-h7ph).
 *
 * Nothing is changed: accounts on one uid share their group memberships, and there is
 * no record of which membership was meant for which of them, so separating them is an
 * operator decision. Until then logins and SCIM refuse them (LocalAccountWriter::
 * sharesUid()), and SSO Diagnostics lists them.
 */
class M1_0_7 extends BaseModelMigration
{
    public function run($model)
    {
        foreach ((new LocalAccountWriter())->sharedUids() as $uid => $names) {
            syslog(LOG_WARNING, sprintf(
                'os-sso: uid %s is shared by the local accounts %s, which therefore share their group '
                . 'memberships; SSO logins and SCIM refuse them until each has a uid of its own '
                . '(see System > Access > SSO Diagnostics)',
                $uid,
                implode(', ', $names)
            ));
        }
        parent::run($model);
    }
}
