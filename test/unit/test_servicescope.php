<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Every configured provider used to be all three doors at once: a server added for the
 * guest wifi also put a button on the firewall's own login page. What matters below is
 * that narrowing one works, and that not narrowing it changes nothing -- an upgrade
 * must not take a login away.
 */

use OPNsense\SSO\ServiceScope;

T::group('ServiceScope: reading the operator list');

eq([], ServiceScope::parse(''), 'empty means no restriction');
eq([], ServiceScope::parse('   '), 'whitespace too');
eq(['webgui'], ServiceScope::parse('webgui'), 'one service');
eq(['webgui', 'vpn'], ServiceScope::parse('webgui, vpn'), 'a comma separated list');
eq(['webgui', 'portal'], ServiceScope::parse("WebGUI\nPORTAL"), 'case and newlines are tolerated');
eq(['portal'], ServiceScope::parse('portal, portal'), 'repeats collapse');
// A typo must not read as "nowhere" and lock a working provider out silently; the form
// validation is what reports it.
eq([], ServiceScope::parse('webgi'), 'a list that names nothing known reads as no restriction');
eq(['vpn'], ServiceScope::parse('vpn, nonsense'), 'while a partly-valid list keeps what it named');

eq([], ServiceScope::unknown('webgui, portal, vpn'), 'a valid list reports nothing unknown');
eq(['webgi'], ServiceScope::unknown('webgi'), 'a typo is reported');
eq(['nonsense'], ServiceScope::unknown('vpn, nonsense'), 'so is one among valid entries');

T::group('ServiceScope: what a provider may be used for');

foreach (ServiceScope::SERVICES as $service) {
    truthy(ServiceScope::allows([], $service), "an unrestricted provider allows {$service}");
}
truthy(ServiceScope::allows(['portal'], 'portal'), 'a portal provider allows the portal');
falsy(ServiceScope::allows(['portal'], 'webgui'), 'and not the WebGUI');
falsy(ServiceScope::allows(['portal'], 'vpn'), 'nor the VPN');
truthy(ServiceScope::allows('webgui,vpn', 'vpn'), 'a raw string is parsed on the way in');

nothrow(fn() => ServiceScope::assert([], 'webgui', 'kc'), 'assert passes when unrestricted');
throws(
    fn() => ServiceScope::assert(['portal'], 'webgui', 'guest-wifi'),
    "provider 'guest-wifi' is not enabled for webgui logins",
    'assert names the provider and the door it refused'
);
throws(
    fn() => ServiceScope::assert(['portal'], 'webgui', "guest\nwifi"),
    'not enabled for webgui',
    'a crafted provider name cannot forge a log line'
);
