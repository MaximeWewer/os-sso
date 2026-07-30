<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Backend;
use OPNsense\Cron\Cron;

/**
 * Schedule the session sweeper, instead of documenting that somebody should.
 *
 * "Maximum session lifetime" is the one setting that cannot enforce itself: a session
 * that makes no request to us is never looked at, so something has to come round and
 * end it. That something was a cron job the operator had to know to add -- and a
 * lifetime silently not being applied is worse than not offering one, because the
 * setting says otherwise on the provider page.
 *
 * Added once, disabled-proof (an operator who deletes it is not fought over it on the
 * next upgrade: the job is only created when no job of ours is there at all), and
 * cheap: the sweeper reads a directory of small files and usually ends nothing.
 */
class M1_0_2 extends BaseModelMigration
{
    private const COMMAND = 'sso expire_sessions';
    private const ORIGIN = 'os-sso';

    public function run($model)
    {
        try {
            $cron = new Cron();
            foreach ($cron->jobs->job->iterateItems() as $job) {
                if ((string)$job->origin === self::ORIGIN && (string)$job->command === self::COMMAND) {
                    parent::run($model);
                    return;
                }
            }
            $uuid = $cron->newDailyJob(
                self::ORIGIN,
                self::COMMAND,
                'os-sso: end SSO sessions past their maximum lifetime',
                '*',
                '1'
            );
            $job = $cron->getNodeByReference('jobs.job.' . $uuid);
            if ($job !== null) {
                // Every ten minutes, all day: a session lifetime is a deadline, and a
                // daily sweep would make "one hour" mean "some time tomorrow".
                $job->minutes = '*/10';
                $job->hours = '*';
            }
            $cron->serializeToConfig();
            \OPNsense\Core\Config::getInstance()->save();
            (new Backend())->configdRun('template reload OPNsense/Cron');
            (new Backend())->configdRun('cron restart');
        } catch (\Throwable $e) {
            // A scheduling problem must not stop the plugin from loading; the sweeper
            // also runs opportunistically on every SSO login.
            syslog(LOG_WARNING, 'os-sso: could not schedule the session sweeper: ' . $e->getMessage());
        }

        parent::run($model);
    }
}
