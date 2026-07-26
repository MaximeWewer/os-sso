<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

/**
 * Settings API for the OpenVPN web-auth wiring. get/set come from the base class;
 * applying means regenerating /usr/local/etc/sso/vpn.conf from the service template,
 * which is the file the auth-user-pass-verify script reads on every VPN connection.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = 'OPNsense\SSO\Settings';

    /** POST /api/sso/settings/reconfigure -- write vpn.conf from the saved settings. */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $output = (new Backend())->configdRun('template reload OPNsense/SSO');
        return ['status' => trim((string)$output) === 'OK' ? 'ok' : 'failed', 'output' => trim((string)$output)];
    }
}
