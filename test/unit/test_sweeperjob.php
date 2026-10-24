<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\Cron\Cron;
use OPNsense\SSO\SessionSweeperJob;

T::group('SessionSweeperJob: the sweeper gets scheduled, once');

// The regression itself: the first migration used "os-sso", which core's mask refuses,
// and the job was never created (issue #12).
truthy(preg_match(Cron::ORIGIN_MASK, SessionSweeperJob::ORIGIN) === 1, 'the origin passes core\'s Cron mask');
falsy(preg_match(Cron::ORIGIN_MASK, 'os-sso') === 1, 'the old one did not');

Cron::$store = [];
truthy(SessionSweeperJob::ensure(), 'a job is added when there is none');
$jobs = array_values(Cron::$store);
eq(1, count($jobs), 'exactly one');
eq('sso expire_sessions', $jobs[0]->command ?? '', 'running the sweeper');
eq('*/10', $jobs[0]->minutes ?? '', 'every ten minutes');
eq('1', $jobs[0]->enabled ?? '', 'and enabled');

// Both migrations call ensure(): a fresh install runs the two of them back to back.
falsy(SessionSweeperJob::ensure(), 'a second call adds nothing');
eq(1, count(Cron::$store), 'so a fresh install still has one job');

// An operator who scheduled it by hand while the migration was broken keeps theirs.
Cron::$store = ['manual' => (object)['origin' => 'cron', 'command' => 'sso expire_sessions']];
falsy(SessionSweeperJob::ensure(), 'a job the operator made, under any origin, counts');
eq(['manual'], array_keys(Cron::$store), 'and no duplicate appears');
