<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Closure;
use OPNsense\Core\Backend;
use Throwable;

/** Repairs running instances whose generated configuration lost the managed verifier. */
final class OpenVpnRuntime
{
	private Closure $running;
	private Closure $readConfig;
	private Closure $command;


	public function __construct(?Closure $running = null, ?Closure $readConfig = null, ?Closure $command = null)
	{
		$this->running = $running ?? static fn(string $uuid): bool => (bool)isvalidpid('/var/run/ovpn-instance-' . $uuid . '.pid');
		$this->readConfig = $readConfig ?? static function (string $uuid): string|false {
			// @ - a missing/unreadable generated configuration needs repair as well.
			return @file_get_contents('/var/etc/openvpn/instance-' . $uuid . '.conf');
		};
		$this->command = $command ?? static fn(string $action, string $uuid): string => (string)(new Backend())->configdpRun('openvpn ' . $action, [$uuid]);
	}


	/**
	 * Runs after successful reconciliation, including when config.xml was already repaired.
	 *
	 * @param array<string, array{profile: string}> $instances Valid managed selections only.
	 * @return array{restarted: string[], errors: string[]}
	 */
	public function repair(array $instances): array
	{
		$restarted = [];
		$errors = [];
		foreach ($instances as $uuid => $settings) {
			$profile = (string)($settings['profile'] ?? '');
			if (!is_string($uuid) || preg_match('/^[0-9a-f-]{36}$/D', $uuid) !== 1 || preg_match('/^[A-Za-z0-9_]{1,32}$/D', $profile) !== 1 || ($settings['blocked'] ?? '') === '1') {
				$errors[] = 'Skipped an invalid managed OpenVPN selection';
				continue;
			}
			try {
				if (!(($this->running)($uuid)) || self::configurationValid(($this->readConfig)($uuid), $profile)) {
					continue;
				}
				// An operator may have stopped it since the first check. Never start
				// a stopped instance merely because its saved configuration changed.
				if (!(($this->running)($uuid))) {
					continue;
				}
			} catch (Throwable $error) {
				$errors[] = "Could not inspect OpenVPN instance '{$uuid}': " . $error->getMessage();
				continue;
			}

			try {
				$response = trim(($this->command)('restart', $uuid));
				if ($response === 'OK' && ($this->running)($uuid) && self::configurationValid(($this->readConfig)($uuid), $profile)) {
					$restarted[] = $uuid;
					continue;
				}
				$errors[] = "OpenVPN instance '{$uuid}' did not restart with the managed verifier";
			} catch (Throwable $error) {
				$errors[] = "Could not repair OpenVPN instance '{$uuid}': " . $error->getMessage();
			}
			try {
				if (($this->running)($uuid) && trim(($this->command)('stop', $uuid)) !== 'OK') {
					$errors[] = "Could not stop unsafe OpenVPN instance '{$uuid}'";
				}
			} catch (Throwable $error) {
				$errors[] = "Could not stop unsafe OpenVPN instance '{$uuid}': " . $error->getMessage();
			}
		}
		return ['restarted' => $restarted, 'errors' => $errors];
	}


	public static function configurationValid(string|false $configuration, string $profile): bool
	{
		if ($configuration === false) {
			return false;
		}
		$lines = array_map('trim', preg_split('/\R/', $configuration) ?: []);
		$verifiers = array_values(array_filter($lines, static fn(string $line): bool => preg_match('/^(?:--)?auth-user-pass-verify(?:\s|$)/', $line) === 1));
		$expected = sprintf('auth-user-pass-verify "%s %s" via-file', OpenVpnIntegration::HOOK, $profile);
		return $verifiers === [$expected] && in_array('auth-user-pass-optional', $lines, true);
	}
}
