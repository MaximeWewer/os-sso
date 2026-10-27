<?php

declare(strict_types=1);

use OPNsense\SSO\OpenVpnIntegration;
use OPNsense\SSO\OpenVpnRuntime;

T::group('OpenVPN runtime: only damaged running instances are restarted');
$runtimeA = '11111111-1111-4111-8111-111111111111';
$runtimeB = '22222222-2222-4222-8222-222222222222';
$validRuntime = 'auth-user-pass-verify "' . OpenVpnIntegration::HOOK . ' staff" via-file' . "\nauth-user-pass-optional\n";
truthy(OpenVpnRuntime::configurationValid($validRuntime, 'staff'), 'the generated managed configuration is accepted');
falsy(OpenVpnRuntime::configurationValid($validRuntime, 'other'), 'another profile is not the expected verifier');
falsy(OpenVpnRuntime::configurationValid($validRuntime . "auth-user-pass-verify /other via-env\n", 'staff'), 'a second verifier is refused');
falsy(OpenVpnRuntime::configurationValid(false, 'staff'), 'a missing runtime file needs repair');

$fixture = function (array $running, array $configs, string $restart = 'repair') use ($validRuntime): array {
	$state = (object)['running' => $running, 'configs' => $configs, 'commands' => []];
	$guard = new OpenVpnRuntime(
		static fn(string $uuid): bool => $state->running[$uuid] ?? false,
		static fn(string $uuid): string|false => $state->configs[$uuid] ?? false,
		static function (string $action, string $uuid) use ($state, $restart, $validRuntime): string {
			$state->commands[] = [$action, $uuid];
			if ($action === 'stop') {
				$state->running[$uuid] = false;
			} elseif ($restart === 'repair') {
				$state->configs[$uuid] = $validRuntime;
			} elseif ($restart === 'throw') {
				throw new RuntimeException('backend unavailable');
			}
			return $restart === 'error' && $action === 'restart' ? '' : 'OK';
		},
	);
	return [$guard, $state];
};
$instances = [$runtimeA => ['profile' => 'staff'], $runtimeB => ['profile' => 'staff']];
[$guard, $state] = $fixture([$runtimeA => true, $runtimeB => true], [$runtimeA => $validRuntime, $runtimeB => 'dev tun']);
$result = $guard->repair($instances);
eq([['restart', $runtimeB]], $state->commands, 'an ordinary form save does not touch the healthy instance');
eq([$runtimeB], $result['restarted'], 'the instance that restarted in the save/repair window comes back hooked');
eq([], $result['errors'], 'a verified repair reports no errors');
$guard->repair($instances);
eq([['restart', $runtimeB]], $state->commands, 'the next event is idempotent even if saved config changed=0');

[$guard, $state] = $fixture([$runtimeA => false], [$runtimeA => 'dev tun']);
$guard->repair([$runtimeA => ['profile' => 'staff']]);
eq([], $state->commands, 'a stopped instance is never started');
[$guard, $state] = $fixture([$runtimeA => true, $runtimeB => true], [$runtimeA => 'dev tun', $runtimeB => 'dev tun']);
$guard->repair([$runtimeA => ['profile' => 'staff']]);
eq([['restart', $runtimeA]], $state->commands, 'an unrelated running instance is not touched');

T::group('OpenVPN runtime: failed repair is stopped, partial selections remain isolated');
foreach (['unchanged', 'error', 'throw'] as $failure) {
	[$guard, $state] = $fixture([$runtimeA => true], [$runtimeA => 'dev tun'], $failure);
	$result = $guard->repair([$runtimeA => ['profile' => 'staff']]);
	eq([['restart', $runtimeA], ['stop', $runtimeA]], $state->commands, 'an unsafe failed repair is stopped: ' . $failure);
	truthy($result['errors'] !== [], 'the failed repair is visible: ' . $failure);
	eq([], $result['restarted'], 'a failed repair is not counted as successful');
}
[$guard, $state] = $fixture([$runtimeA => true, $runtimeB => true], [$runtimeA => 'dev tun', $runtimeB => 'dev tun']);
$result = $guard->repair([$runtimeA => ['profile' => 'staff', 'blocked' => '1'], $runtimeB => ['profile' => 'staff']]);
eq([['restart', $runtimeB]], $state->commands, 'an invalid selection does not cause a global restart or block an independent valid one');
truthy($result['errors'] !== [], 'the invalid selection is reported');

$checks = 0;
$commands = [];
$guard = new OpenVpnRuntime(
	static function (string $uuid) use (&$checks): bool { return ++$checks === 1; },
	static fn(string $uuid): string => 'dev tun',
	static function (string $action, string $uuid) use (&$commands): string { $commands[] = [$action, $uuid]; return 'OK'; },
);
$guard->repair([$runtimeA => ['profile' => 'staff']]);
eq([], $commands, 'an operator stop between inspection and repair is respected');
