<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\SSO\LogoutGuard;

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

    /** GET|POST /api/sso/logout */
    public function indexAction()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        // A third-party page must not be able to end the session for the user.
        if (!LogoutGuard::allow()) {
            $page = LogoutGuard::confirm('/api/sso/logout');
            session_write_close();
            $this->response->setContentType('text/html', 'UTF-8');
            return $page;
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
