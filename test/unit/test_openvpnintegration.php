<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\OpenVpnIntegration;

const VPN_UUID_A = '11111111-1111-4111-8111-111111111111';
const VPN_UUID_B = '22222222-2222-4222-8222-222222222222';


/**
 * @param array<int, array<string, string>> $profiles
 * @param array<int, array<string, string>> $instances
 */
function vpnTree(array $profiles, array $instances): SimpleXMLElement
{
	$xml = '<opnsense><OPNsense><SSO><settings><vpn><profiles/></vpn></settings></SSO>'
		. '<OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>';
	$root = new SimpleXMLElement($xml);
	foreach ($profiles as $profile) {
		$node = $root->OPNsense->SSO->settings->vpn->profiles->addChild('profile');
		foreach ($profile as $key => $value) {
			$node->addChild($key, htmlspecialchars($value, ENT_XML1));
		}
	}
	foreach ($instances as $instance) {
		$node = $root->OPNsense->OpenVPN->Instances->addChild('Instance');
		$node->addAttribute('uuid', $instance['uuid']);
		foreach (array_diff_key($instance, ['uuid' => true]) as $key => $value) {
			$node->addChild($key, htmlspecialchars($value, ENT_XML1));
		}
	}

	return $root;
}


/** @return string[] */
function vpnFlags(SimpleXMLElement $root, string $uuid): array
{
	foreach ($root->OPNsense->OpenVPN->Instances->Instance as $instance) {
		if ((string)$instance->attributes()['uuid'] === $uuid) {
			$value = trim((string)($instance->various_flags ?? ''));
			return $value === '' ? [] : explode(',', $value);
		}
	}

	return [];
}


function vpnProfile(string $name, string $uuid = VPN_UUID_A, string $enabled = '1'): array
{
	return ['enabled' => $enabled, 'name' => $name, 'openvpn_instance' => $uuid];
}


function vpnInstance(
	string $uuid,
	string $flags = 'float',
	string $authmode = '',
	string $enabled = '1',
	string $role = 'server',
): array {
	return [
		'uuid' => $uuid,
		'enabled' => $enabled,
		'role' => $role,
		'authmode' => $authmode,
		'various_flags' => $flags,
	];
}


T::group('OpenVpnIntegration: managed directives');

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A)]);
$result = OpenVpnIntegration::reconcile($tree);
truthy($result['changed'], 'the first reconciliation changes config.xml');
eq(
	[
		'float',
		'auth-user-pass-verify "' . OpenVpnIntegration::HOOK . ' staff" via-file',
		'auth-user-pass-optional',
	],
	vpnFlags($tree, VPN_UUID_A),
	'it preserves native flags and appends the two managed directives',
);
eq('staff', $result['instances'][VPN_UUID_A]['profile'], 'the guard manifest names the profile');
eq(
	'/var/etc/openvpn/instance-' . VPN_UUID_A . '.conf',
	$result['instances'][VPN_UUID_A]['config_file'],
	'the guard manifest names the generated config',
);

$second = OpenVpnIntegration::reconcile($tree);
falsy($second['changed'], 'reconciliation is idempotent');
eq(3, count(vpnFlags($tree, VPN_UUID_A)), 'it never duplicates directives');

$tree = vpnTree(
	[vpnProfile('staff', VPN_UUID_A . ',' . VPN_UUID_B)],
	[vpnInstance(VPN_UUID_A), vpnInstance(VPN_UUID_B, 'client-to-client')],
);
$result = OpenVpnIntegration::reconcile($tree);
eq('staff', $result['instances'][VPN_UUID_A]['profile'], 'the first selected instance uses the shared profile');
eq('staff', $result['instances'][VPN_UUID_B]['profile'], 'the second selected instance uses the shared profile');
eq(3, count(vpnFlags($tree, VPN_UUID_A)), 'the first selected instance receives the managed directives');
eq(3, count(vpnFlags($tree, VPN_UUID_B)), 'the second selected instance receives the managed directives');

T::group('OpenVpnIntegration: moving and disabling profiles');

$owned = 'auth-user-pass-verify "' . OpenVpnIntegration::HOOK . ' staff" via-file,auth-user-pass-optional';
$tree = vpnTree(
	[vpnProfile('staff', VPN_UUID_B)],
	[vpnInstance(VPN_UUID_A, "float,{$owned}"), vpnInstance(VPN_UUID_B, 'client-to-client')],
);
OpenVpnIntegration::reconcile($tree);
eq(['float'], vpnFlags($tree, VPN_UUID_A), 'moving a profile removes directives from its old instance');
eq(
	[
		'client-to-client',
		'auth-user-pass-verify "' . OpenVpnIntegration::HOOK . ' staff" via-file',
		'auth-user-pass-optional',
	],
	vpnFlags($tree, VPN_UUID_B),
	'and adds them to the new instance',
);

$tree = vpnTree([vpnProfile('staff', VPN_UUID_A, '0')], [vpnInstance(VPN_UUID_A, $owned)]);
$result = OpenVpnIntegration::reconcile($tree);
eq([], vpnFlags($tree, VPN_UUID_A), 'disabling a profile removes the managed directives');
eq([], $result['instances'], 'a disabled profile is absent from the guard manifest');

T::group('OpenVpnIntegration: refusing ambiguous or unsafe ownership');

$tree = vpnTree(
	[vpnProfile('staff'), vpnProfile('contractors')],
	[vpnInstance(VPN_UUID_A)],
);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'selected by both',
	'one OpenVPN instance cannot belong to two enabled profiles',
);

$tree = vpnTree(
	[
		vpnProfile('staff', VPN_UUID_A . ',' . VPN_UUID_B),
		vpnProfile('contractors', VPN_UUID_B),
	],
	[vpnInstance(VPN_UUID_A), vpnInstance(VPN_UUID_B)],
);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'selected by both',
	'an instance in a multi-selection cannot belong to a second enabled profile',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', 'Local Database')]);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'already has Authentication configured',
	'core password authentication cannot run alongside web-auth',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', '', '0')]);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'is disabled',
	'a disabled instance cannot be managed',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', '', '1', 'client')]);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'is not a server',
	'an OpenVPN client instance cannot be managed',
);

$tree = vpnTree([vpnProfile('staff', VPN_UUID_B)], [vpnInstance(VPN_UUID_A)]);
throws(
	fn() => OpenVpnIntegration::reconcile($tree),
	'does not exist',
	'a missing selected instance is refused',
);

T::group('OpenVpnIntegration: backwards compatible manual profiles');

$tree = vpnTree([vpnProfile('legacy', '')], [vpnInstance(VPN_UUID_A, 'float')]);
$result = OpenVpnIntegration::reconcile($tree);
falsy($result['changed'], 'a legacy profile without an instance keeps manual wiring untouched');
eq([], $result['instances'], 'a legacy manual profile is not guarded as managed');
