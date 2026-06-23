<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiControllerBase;

/**
 * Unified logout entry point that the WebGUI "Logout" menu item is re-pointed to
 * (see models/OPNsense/SSO/Menu/Menu.xml). It inspects how the current session was
 * established and dispatches to the matching Single Logout flow; a local-password
 * session falls through to the normal core logout. Pre-auth + CSRF-exempt: it only
 * triggers logout, never authenticates.
 */
class LogoutController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    public function beforeExecuteRoute($dispatcher)
    {
        return true;
    }

    /** GET /api/sso/logout */
    public function indexAction()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $type = is_array($_SESSION['sso_logout'] ?? null) ? ($_SESSION['sso_logout']['type'] ?? '') : '';
        session_write_close();

        switch ($type) {
            case 'oidc':
                $this->response->redirect('/api/sso/oidc/logout', true);
                break;
            case 'saml':
                $this->response->redirect('/api/sso/saml/slo', true);
                break;
            default:
                // Not an SSO session -> let the core handle the local logout.
                $this->response->redirect('/index.php?logout', true);
        }
        return 'Logging out...';
    }
}
