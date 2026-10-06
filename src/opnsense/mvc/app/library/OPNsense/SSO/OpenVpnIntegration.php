<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;
use RuntimeException;
use SimpleXMLElement;

/**
 * Owns the small part of an OpenVPN instance that enables deferred web authentication.
 *
 * OpenVPN's `various_flags` model field is deliberately a closed list, while its
 * generator emits every persisted value as a directive. The WebGUI therefore drops
 * our directives whenever an instance is saved. Reconciliation immediately before
 * OpenVPN generates its files restores the values without patching OPNsense core.
 */
final class OpenVpnIntegration
{
	public const HOOK = '/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh';

	private const OPTIONAL_DIRECTIVE = 'auth-user-pass-optional';


	/**
	 * Reconcile config.xml under the configuration lock.
	 *
	 * @return array{changed: bool, instances: array<string, array{profile: string}>, errors: string[]}
	 */
	public static function synchronize(): array
	{
		return ConfigLock::with(function (): array {
			$config = Config::getInstance();
			$result = self::reconcile($config->object());
			if ($result['changed'] && $config->save() === false) {
				throw new RuntimeException('OpenVPN integration could not save config.xml');
			}

			return $result;
		});
	}


	/**
	 * Apply the desired os-sso profiles to an in-memory config.xml tree.
	 *
	 * Public as a test seam: production callers should use synchronize(), which also
	 * serializes concurrent writes.
	 *
	 * Invalid selections are reported and left untouched, while independent valid
	 * instances are still reconciled.
	 *
	 * @return array{changed: bool, instances: array<string, array{profile: string}>, errors: string[]}
	 */
	public static function reconcile(SimpleXMLElement $config): array
	{
		[$desired, $blocked, $errors] = self::desiredInstances($config);
		$instances = self::openVpnInstances($config);

		foreach ($desired as $uuid => $profile) {
			if (!isset($instances[$uuid])) {
				$errors[] = "OpenVPN instance '{$uuid}' selected by profile '{$profile}' does not exist";
				$blocked[$uuid] = $profile;
				unset($desired[$uuid]);
				continue;
			}
			$instance = $instances[$uuid];
			if ((string)($instance->enabled ?? '') !== '1') {
				$errors[] = "OpenVPN instance '{$uuid}' selected by profile '{$profile}' is disabled";
				$blocked[$uuid] = $profile;
				unset($desired[$uuid]);
				continue;
			}
			if ((string)($instance->role ?? '') !== 'server') {
				$errors[] = "OpenVPN instance '{$uuid}' selected by profile '{$profile}' is not a server";
				$blocked[$uuid] = $profile;
				unset($desired[$uuid]);
				continue;
			}
			if (trim((string)($instance->authmode ?? '')) !== '') {
				$errors[] = "OpenVPN instance '{$uuid}' already has Authentication configured; "
					. "clear it before enabling profile '{$profile}'";
				$blocked[$uuid] = $profile;
				unset($desired[$uuid]);
			}
		}

		$changed = false;
		foreach ($instances as $uuid => $instance) {
			if (isset($blocked[$uuid])) {
				continue;
			}
			$original = self::flags($instance);
			$hadOwnedHook = false;
			$flags = [];
			foreach ($original as $flag) {
				if (self::isOwnedHook($flag)) {
					$hadOwnedHook = true;
					continue;
				}
				$flags[] = $flag;
			}
			if ($hadOwnedHook) {
				$flags = array_values(array_filter(
					$flags,
					static fn(string $flag): bool => $flag !== self::OPTIONAL_DIRECTIVE,
				));
			}

			if (isset($desired[$uuid])) {
				$flags[] = self::hookDirective($desired[$uuid]);
				$flags[] = self::OPTIONAL_DIRECTIVE;
			}
			$flags = array_values(array_unique($flags));

			if ($flags !== $original) {
				self::setFlags($instance, $flags);
				$changed = true;
			}
		}

		return [
			'changed' => $changed,
			'instances' => self::manifest($desired),
			'errors' => array_values(array_unique($errors)),
		];
	}


	private static function hookDirective(string $profile): string
	{
		return sprintf('auth-user-pass-verify "%s %s" via-file', self::HOOK, $profile);
	}


	/**
	 * @param array<string, string> $desired
	 * @return array<string, array{profile: string}>
	 */
	private static function manifest(array $desired): array
	{
		$result = [];
		foreach ($desired as $uuid => $profile) {
			$result[$uuid] = ['profile' => $profile];
		}

		return $result;
	}


	private static function isOwnedHook(string $flag): bool
	{
		$path = preg_quote(self::HOOK, '~');
		return preg_match('~^auth-user-pass-verify "' . $path . '(?: [A-Za-z0-9_]{1,32})?" via-file$~D', $flag) === 1;
	}


	/**
	 * @return array{array<string, string>, array<string, string>, string[]}
	 *     desired instances, blocked instances and validation errors
	 */
	private static function desiredInstances(SimpleXMLElement $config): array
	{
		$desired = [];
		$blocked = [];
		$errors = [];
		$profiles = $config->xpath('/opnsense/OPNsense/SSO/settings/vpn/profiles/profile') ?: [];
		foreach ($profiles as $profile) {
			if ((string)($profile->enabled ?? '') !== '1') {
				continue;
			}
			$name = trim((string)($profile->name ?? ''));
			$uuids = array_unique(array_filter(array_map(
				'trim',
				explode(',', (string)($profile->openvpn_instance ?? '')),
			), 'strlen'));
			if ($uuids === []) {
				continue;
			}
			foreach ($uuids as $uuid) {
				if (preg_match('/^[0-9a-f-]{36}$/D', $uuid) !== 1) {
					$errors[] = "Invalid OpenVPN instance UUID '{$uuid}' in profile '{$name}'";
					continue;
				}
				if (preg_match('/^[A-Za-z0-9_]{1,32}$/D', $name) !== 1) {
					$errors[] = "Invalid os-sso OpenVPN profile name '{$name}'";
					$blocked[$uuid] = $name;
					unset($desired[$uuid]);
					continue;
				}
				if (isset($desired[$uuid]) || isset($blocked[$uuid])) {
					$owner = $desired[$uuid] ?? $blocked[$uuid];
					$errors[] = sprintf(
						"OpenVPN instance '{$uuid}' is selected by both '{$owner}' and '{$name}'"
					);
					$blocked[$uuid] = $owner;
					unset($desired[$uuid]);
					continue;
				}
				$desired[$uuid] = $name;
			}
		}

		return [$desired, $blocked, array_values(array_unique($errors))];
	}


	/** @return array<string, SimpleXMLElement> */
	private static function openVpnInstances(SimpleXMLElement $config): array
	{
		$result = [];
		$instances = $config->xpath('/opnsense/OPNsense/OpenVPN/Instances/Instance') ?: [];
		foreach ($instances as $instance) {
			$uuid = trim((string)($instance->attributes()['uuid'] ?? ''));
			if ($uuid !== '') {
				$result[$uuid] = $instance;
			}
		}

		return $result;
	}


	/** @return string[] */
	private static function flags(SimpleXMLElement $instance): array
	{
		$value = trim((string)($instance->various_flags ?? ''));
		if ($value === '') {
			return [];
		}

		return array_values(array_filter(array_map('trim', explode(',', $value)), 'strlen'));
	}


	/** @param string[] $flags */
	private static function setFlags(SimpleXMLElement $instance, array $flags): void
	{
		$value = implode(',', $flags);
		if (isset($instance->various_flags)) {
			$instance->various_flags = $value;
		} else {
			$instance->addChild('various_flags', $value);
		}
	}

}
