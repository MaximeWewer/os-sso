<?php

declare(strict_types=1);

T::group('HA XMLRPC integration');

require_once dirname(__DIR__, 2) . '/src/etc/inc/plugins.inc.d/sso.inc';

$areas = sso_xmlrpc_sync();
eq(1, count($areas), 'registers exactly one HA synchronization area');

$area = $areas[0];
eq('sso', $area['id'] ?? null, 'uses a stable synchronization identifier');
eq('Single Sign-On', $area['description'] ?? null, 'exposes a recognizable HA option');
eq('OPNsense.SSO', $area['section'] ?? null, 'synchronizes the complete plugin model root');
eq(
	['sso_vpn_guard', 'openvpn'],
	$area['services'] ?? null,
	'reconfigures the guard and OpenVPN after synchronization',
);
truthy(
	str_contains((string) ($area['help'] ?? ''), 'Authentication Servers'),
	'warns that dependent core sections must be selected separately',
);
