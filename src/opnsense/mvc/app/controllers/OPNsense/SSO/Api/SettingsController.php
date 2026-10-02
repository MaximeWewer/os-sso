<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

/**
 * Settings API for the OpenVPN web-auth profiles. The CRUD actions are the base class's
 * grid helpers; applying writes vpn.conf, reconciles managed OpenVPN instances, lets
 * core regenerate their runtime configuration, and starts the fail-closed guard.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = 'OPNsense\SSO\Settings';

    /** GET /api/sso/settings/searchProfile */
    public function searchProfileAction()
    {
        return $this->searchBase(
            'vpn.profiles.profile',
            ['enabled', 'name', 'protocol', 'provider', 'openvpn_instance', 'host', 'timeout'],
            'name'
        );
    }

    /** GET /api/sso/settings/getProfile[/$uuid] */
    public function getProfileAction($uuid = null)
    {
        return $this->getBase('profile', 'vpn.profiles.profile', $uuid);
    }

    /** POST /api/sso/settings/addProfile */
    public function addProfileAction()
    {
        return $this->addBase('profile', 'vpn.profiles.profile');
    }

    /** POST /api/sso/settings/setProfile/$uuid */
    public function setProfileAction($uuid)
    {
        return $this->setBase('profile', 'vpn.profiles.profile', $uuid);
    }

    /** POST /api/sso/settings/delProfile/$uuid */
    public function delProfileAction($uuid)
    {
        return $this->delBase('vpn.profiles.profile', $uuid);
    }

    /** POST /api/sso/settings/toggleProfile/$uuid */
    public function toggleProfileAction($uuid, $enabled = null)
    {
        return $this->toggleBase('vpn.profiles.profile', $uuid, $enabled);
    }

    /** POST /api/sso/settings/reconfigure -- apply profiles and their OpenVPN wiring. */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $backend = new Backend();
        $templateOutput = trim((string)$backend->configdRun('template reload OPNsense/SSO'));
        if ($templateOutput !== 'OK') {
            return ['status' => 'failed', 'output' => $templateOutput];
        }

        $syncOutput = trim((string)$backend->configdRun('sso sync_openvpn'));
        if (!str_starts_with($syncOutput, 'OK:')) {
            return ['status' => 'failed', 'output' => $syncOutput];
        }

        $backend->configdRun('openvpn configure');
        $backend->configdRun('sso guard_start');
        return ['status' => 'ok', 'output' => $syncOutput];
    }
}
