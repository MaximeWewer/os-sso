<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Cron\Cron;

/**
 * The cron job that runs the session sweeper (SessionRegistry::sweep) every 10 minutes.
 *
 * Without it the sweep only happens on an SSO login, so on a quiet firewall nothing
 * retires a WebGUI session past its maximum lifetime, a captive-portal or VPN grant
 * past its deadline, or what a since-disabled account was granted.
 *
 * Shared by the migrations that schedule it: the first one used the origin "os-sso",
 * which core's Cron model refuses (its mask is /^([a-z,A-Z,1-9]){0,30}$/), so the job
 * was never created and the failure only reached the log (issue #12).
 */
final class SessionSweeperJob
{
    public const COMMAND = 'sso expire_sessions';
    /** Must pass core's Cron origin mask: letters and 1-9 only, no hyphen, no 0. */
    public const ORIGIN = 'sso';

    /**
     * Make sure a job runs the sweeper. Any existing job for the command counts, under
     * whatever origin -- an operator who scheduled it by hand in the Cron GUI meanwhile
     * keeps theirs, rather than ending up with two.
     *
     * Never throws: a migration that failed here would hold the whole model back.
     *
     * @return bool whether a job was added
     */
    public static function ensure(): bool
    {
        try {
            $cron = new Cron();
            foreach ($cron->jobs->job->iterateItems() as $job) {
                if (trim((string)$job->command) === self::COMMAND) {
                    return false;
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
                $job->minutes = '*/10';
                $job->hours = '*';
            }
            $cron->serializeToConfig();
            Config::getInstance()->save();
            (new Backend())->configdRun('template reload OPNsense/Cron');
            (new Backend())->configdRun('cron restart');
            return true;
        } catch (\Throwable $e) {
            syslog(LOG_WARNING, 'os-sso: could not schedule the session sweeper: ' . $e->getMessage());
            return false;
        }
    }
}
