<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\IndexController;

/**
 * UI shell for the OpenVPN web-auth form (System > Access > SSO VPN web-auth).
 *
 * The model behind it is called "settings" because it is the plugin's settings
 * document, but the only thing in it today is the OpenVPN deferred web-auth wiring --
 * everything else in os-sso is configured per authentication server. The page is
 * named after what it actually holds, not after the model.
 */
class SettingsController extends IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('OpenVPN web-auth');
        $this->view->formDialogProfile = $this->getForm('dialogProfile');
        $this->view->pick('OPNsense/SSO/settings');
    }
}
