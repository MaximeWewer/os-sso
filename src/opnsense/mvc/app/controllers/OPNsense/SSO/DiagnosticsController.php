<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\IndexController;

/**
 * UI shell for the SSO diagnostics page (System > Access > SSO Diagnostics).
 * All the data comes from /api/sso/diagnostics/* -- this only picks the view.
 */
class DiagnosticsController extends IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('SSO Diagnostics');
        $this->view->pick('OPNsense/SSO/diagnostics');
    }
}
