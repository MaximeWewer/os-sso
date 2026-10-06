<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;

/**
 * Introduce managed OpenVPN instance ownership.
 *
 * Existing profiles intentionally keep an empty instance: their manually installed
 * hook continues to work until the operator selects an instance and applies the page.
 */
class M1_0_3 extends BaseModelMigration
{
}
