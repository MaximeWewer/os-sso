<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\BaseModel;

/**
 * os-sso settings model (see Settings.xml). Backs the OpenVPN web-auth section, which
 * is written out to /usr/local/etc/sso/vpn.conf by the service template.
 */
class Settings extends BaseModel
{
    /**
     * Cross-field rules the XML cannot express: the VPN fields are only required once
     * the feature is switched on, so an operator who leaves it off is never nagged.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        if ((string)$this->vpn->enabled !== '1') {
            return $messages;
        }
        foreach (['provider' => 'an SSO authentication server', 'host' => 'the firewall host'] as $field => $what) {
            if (trim((string)$this->vpn->$field) === '') {
                $messages->appendMessage(new \Phalcon\Messages\Message(
                    sprintf('Select %s: OpenVPN web-auth cannot be enabled without it.', $what),
                    $this->vpn->$field->__reference()
                ));
            }
        }
        return $messages;
    }
}
