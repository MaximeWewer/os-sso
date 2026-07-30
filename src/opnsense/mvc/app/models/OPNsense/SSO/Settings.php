<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\BaseModel;

/**
 * os-sso settings model (see Settings.xml). Backs the OpenVPN web-auth profiles, which
 * are written out to /usr/local/etc/sso/vpn.conf by the service template.
 *
 * No cross-field rules of its own any more: a profile is a row that either exists or
 * does not, so every field it needs is simply Required. The old single setting had to
 * be validated against its own "enabled" flag, which is what an operator who left the
 * feature off would otherwise be nagged about.
 */
class Settings extends BaseModel
{
}
