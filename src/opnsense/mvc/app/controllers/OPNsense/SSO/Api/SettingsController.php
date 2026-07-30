<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

/**
 * Settings API for the OpenVPN web-auth profiles. The CRUD actions are the base class's
 * grid helpers; applying means regenerating /usr/local/etc/sso/vpn.conf from the service
 * template, which is the file the auth-user-pass-verify script reads on every VPN
 * connection attempt.
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
            ['enabled', 'name', 'protocol', 'provider', 'host', 'timeout'],
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

    /** POST /api/sso/settings/reconfigure -- write vpn.conf from the saved profiles. */
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
