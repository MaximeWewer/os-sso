<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\OpenVPN\OpenVPN;

/**
 * os-sso settings model (see Settings.xml). Backs the OpenVPN web-auth profiles, which
 * are written out to /usr/local/etc/sso/vpn.conf by the service template.
 *
 * Profiles may own OpenVPN server instances. Cross-model validation keeps ownership
 * unambiguous and prevents core's password authenticator from being emitted alongside
 * the deferred browser authenticator.
 */
class Settings extends BaseModel
{
	/** {@inheritdoc} */
	public function performValidation($validateFullModel = false)
	{
		$messages = parent::performValidation($validateFullModel);
		$instances = [];
		foreach ((new OpenVPN())->Instances->Instance->iterateItems() as $uuid => $instance) {
			$instances[$uuid] = $instance;
		}

		$owners = [];
		foreach ($this->vpn->profiles->profile->iterateItems() as $profile) {
			if ((string)$profile->enabled !== '1' || $profile->openvpn_instance->isEmpty()) {
				continue;
			}
			$field = $profile->__reference . '.openvpn_instance';
			$uuids = array_unique(array_filter(array_map(
				'trim',
				explode(',', (string)$profile->openvpn_instance),
			), 'strlen'));
			foreach ($uuids as $uuid) {
				if (isset($owners[$uuid])) {
					$message = gettext('This OpenVPN instance is already assigned to another enabled SSO profile.');
					$messages->appendMessage(new Message($message, $owners[$uuid]));
					$messages->appendMessage(new Message($message, $field));
					continue;
				}
				$owners[$uuid] = $field;
				if (!isset($instances[$uuid])) {
					$messages->appendMessage(new Message(
						gettext('A selected OpenVPN instance does not exist.'),
						$field,
					));
					continue;
				}

				$instance = $instances[$uuid];
				if ((string)$instance->enabled !== '1' || (string)$instance->role !== 'server') {
					$messages->appendMessage(new Message(
						gettext('Select enabled OpenVPN server instances only.'),
						$field,
					));
				}
				if (!$instance->authmode->isEmpty()) {
					$messages->appendMessage(new Message(
						gettext('Clear Authentication on every selected OpenVPN instance; os-sso supplies its authentication hook.'),
						$field,
					));
				}
			}
		}

		return $messages;
	}
}
