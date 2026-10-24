<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\SSO\SessionSweeperJob;

/**
 * Schedule the session sweeper on configurations that are past M1_0_2 without it.
 *
 * M1_0_2 asked core's Cron model for a job under the origin "os-sso", which the model
 * refuses; the error was only logged, and the model moved on to 1.0.2 regardless, so
 * every installation upgraded through it has no sweeper job (issue #12). ensure() is
 * idempotent: a fresh install runs both migrations and still ends up with one job.
 */
class M1_0_5 extends BaseModelMigration
{
    public function run($model)
    {
        SessionSweeperJob::ensure();
        parent::run($model);
    }
}
