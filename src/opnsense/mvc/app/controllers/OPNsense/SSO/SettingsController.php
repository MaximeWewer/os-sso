<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\IndexController;

/** UI shell for the os-sso settings form (System > Access > SSO Settings). */
class SettingsController extends IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('SSO Settings');
        $this->view->formSettings = $this->getForm('settings');
        $this->view->pick('OPNsense/SSO/settings');
    }
}
