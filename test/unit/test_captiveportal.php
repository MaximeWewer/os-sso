<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\CaptivePortal\CaptivePortal;
use OPNsense\Core\Backend;
use OPNsense\SSO\CaptivePortalAuthorizer as CP;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Test\Tree;

/**
 * The captive portal's post-login redirect goes off-site by design -- it is wherever the
 * client was headed when the portal intercepted them. So this is not an allowlist; it is
 * a shape check, and what it has to stop is the redirect being retargeted into something
 * that is not a plain http(s) destination.
 */
T::group('CaptivePortalAuthorizer: redirect shapes that are allowed');

foreach ([
    'http://example.com/' => 'an absolute http URL',
    'https://example.com/a/b?c=1' => 'an absolute https URL with a query',
    'example.com' => 'core\'s scheme-less host',
    'example.com/path' => 'a scheme-less host with a path',
    '/example.com/path' => 'a scheme-less host with a leading slash',
    'example.com:8080/x' => 'a host with a port',
    '192.0.2.1/x' => 'a bare IPv4 host',
] as $input => $why) {
    truthy(CP::sanitizeRedirect($input) !== '', "keeps {$why}");
}
eq('http://example.com', CP::sanitizeRedirect('example.com'), 'a scheme-less host gains http://');
eq('http://example.com/x', CP::sanitizeRedirect('/example.com/x'), 'a leading slash is stripped before that');
eq('https://example.com/', CP::sanitizeRedirect('https://example.com/'), 'an https URL is left alone');

T::group('CaptivePortalAuthorizer: redirect shapes that are refused');

foreach ([
    '' => 'empty',
    '   ' => 'whitespace only',
    'javascript:alert(1)' => 'the javascript scheme',
    'data:text/html;base64,x' => 'the data scheme',
    'file:///etc/passwd' => 'the file scheme',
    'ftp://example.com' => 'a non-http scheme',
    '//evil.example/' => 'protocol-relative',
    'http://user@evil.example/' => 'a userinfo host confusion',
    'example.com@evil.example' => 'an at sign anywhere',
    'http://example.com\\evil' => 'a backslash',
    "http://example.com\r\nX: y" => 'CRLF',
    "http://exa mple.com" => 'an embedded space',
    'http://exa"mple.com' => 'a double quote',
    "http://exa'mple.com" => 'a single quote',
    'http://<script>' => 'angle brackets',
    'http:///nohost' => 'no host at all',
    'mailto:someone@example.com' => 'the mailto scheme',
] as $input => $why) {
    eq('', CP::sanitizeRedirect($input), "refuses {$why}");
}
eq('', CP::sanitizeRedirect('http://example.com/' . str_repeat('a', 600)), 'refuses an over-long value');

// An underscore is not legal in a hostname but occurs in the wild, and parse_url takes
// it. Accepting it is harmless: the value only ever becomes an href or a meta refresh,
// and the shape checks above already ran.
eq(
    'http://exa_mple.com/x',
    CP::sanitizeRedirect('exa_mple.com/x'),
    'an underscore in the host is tolerated'
);
// A scheme-less host:port is the shape core hands over for any non-default port; it must
// not be mistaken for a scheme.
eq('http://example.com:8080/x', CP::sanitizeRedirect('example.com:8080/x'), 'host:port with a path');
eq('http://example.com:8080', CP::sanitizeRedirect('example.com:8080'), 'host:port with nothing after it');
eq('http://example.com:8080?a=1', CP::sanitizeRedirect('example.com:8080?a=1'), 'host:port with a query');

T::group('CaptivePortalAuthorizer: the done page');

$page = CP::donePage('alice', 'http://example.com/');
truthy(str_contains($page, 'alice'), 'it names the user');
truthy(str_contains($page, "content='no-referrer'"), 'it suppresses the referrer');
// The page is rendered BY the callback, whose URL carries the code and state; the
// destination must not receive either through the Referer.
truthy(str_contains($page, "rel='noreferrer noopener'"), 'the link is noreferrer too');
truthy(str_contains($page, 'http-equiv=\'refresh\''), 'it bounces automatically');
truthy(str_contains($page, 'http://example.com/'), 'it names the destination');

// A username is asserted by the IdP, so it is untrusted markup until escaped.
$xss = CP::donePage('<script>alert(1)</script>', '');
falsy(str_contains($xss, '<script>alert(1)</script>'), 'the username is escaped');
truthy(str_contains($xss, '&lt;script&gt;'), 'and shows up escaped');
falsy(str_contains($xss, 'http-equiv=\'refresh\''), 'with no destination there is no bounce');
truthy(str_contains($xss, "content='no-referrer'"), 'but the referrer is still suppressed');

// A destination that fails the shape check must not survive into the page even if the
// caller passed it -- donePage re-validates rather than trusting its argument.
$bad = CP::donePage('alice', 'javascript:alert(1)');
falsy(str_contains($bad, 'javascript:'), 'a refused destination never reaches the markup');
falsy(str_contains($bad, 'http-equiv=\'refresh\''), 'and no bounce is emitted for it');

T::group('CaptivePortalAuthorizer: who gets onto the network');

/** An identity as the OIDC/SAML protocol hands it to the portal path. */
function cpIdentity(string $username, array $groups = [], string $subject = 'sub-1'): NormalizedIdentity
{
    $id = new NormalizedIdentity('kc');
    $id->subject = $subject;
    $id->username = $username;
    $id->groups = $groups;
    return $id;
}

CaptivePortal::useZone('1', 'kc,Local Database');
CaptivePortal::useZone('2', 'other');
CaptivePortal::useZone('3', 'kc', '2000');   // enforces the group with gid 2000
Tree::build([], [['name' => 'wifi', 'gid' => '2000']]);

throws(fn() => CP::authorize('9', 'kc', cpIdentity('alice'), '10.0.0.1'), 'unknown captive portal zone', 'an unknown zone');
throws(fn() => CP::authorize('x', 'kc', cpIdentity('alice'), '10.0.0.1'), 'invalid captive portal zone', 'a non-numeric zone');
throws(
    fn() => CP::authorize('2', 'kc', cpIdentity('alice'), '10.0.0.1'),
    'not enabled for this captive portal zone',
    'a provider the zone does not list -- self-authorizing into any zone'
);
throws(
    fn() => CP::authorize('3', 'kc', cpIdentity('alice', ['staff']), '10.0.0.1'),
    'not in the group required by this zone',
    'an identity without the zone enforce-group'
);
throws(
    fn() => CP::authorize('1', 'kc', cpIdentity("ali\nce"), '10.0.0.1'),
    'invalid characters in the SSO username',
    'a username that would forge a log line'
);

$ok = CP::authorize('1', 'kc', cpIdentity('alice'), '10.0.0.1');
eq('alice', $ok['username'], 'a listed provider authorizes the client');
eq(
    ['captiveportal allow', ['1', 'alice', '10.0.0.1', 'kc']],
    Backend::$calls[count(Backend::$calls) - 1],
    'and configd is asked to allow that IP in that zone'
);
nothrow(fn() => CP::authorize('3', 'kc', cpIdentity('alice', ['WIFI']), '10.0.0.1'), 'the enforce-group matches case-insensitively');

// The revocation gap: SCIM active:false, deprovisioning and the operator's own checkbox
// all end in a disabled local account. The WebGUI and VPN paths refuse it; the portal
// used to hand out network access anyway.
Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-1', 'disabled' => '1'],
    ['name' => 'bob', 'uid' => '2101', 'scrambled_password' => '1', 'expires' => date('m/d/Y', strtotime('-10 days'))],
    ['name' => 'carol', 'uid' => '2102', 'scrambled_password' => '1'],
], [['name' => 'wifi', 'gid' => '2000']]);

throws(
    fn() => CP::authorize('1', 'kc', cpIdentity('alice'), '10.0.0.1'),
    'disabled or expired',
    'a disabled account is refused, found by its subject binding'
);
throws(
    fn() => CP::authorize('1', 'kc', cpIdentity('bob', [], 'sub-bob'), '10.0.0.1'),
    'disabled or expired',
    'an expired account is refused, found by username'
);
nothrow(fn() => CP::authorize('1', 'kc', cpIdentity('carol', [], 'sub-carol'), '10.0.0.1'), 'an enabled account still gets in');
nothrow(fn() => CP::authorize('1', 'kc', cpIdentity('dave', [], 'sub-dave'), '10.0.0.1'), 'and so does an identity with no local account at all');

T::group('CaptivePortalAuthorizer: a grant that cannot be recorded is given back');

// The portal reaches the network without going through IdentityMapper, so it is the one
// door that does not already fail closed on an unusable state directory. The record is
// the only handle anything has on a portal client -- back-channel logout, SCIM, the
// sweeper, the End button -- so an unrecordable grant is an access nothing can revoke.
$grant = ['username' => 'carol', 'zone' => '1', 'session' => ['sessionId' => 'cp-session-1']];
$idpSession = ['provider' => 'kc', 'issuer' => 'https://idp', 'sub' => 'sub-carol'];

if (!stateDirUsable()) {
    T::skip('the whole case', 'needs a writable /var/db/os-sso');
} else {
    nothrow(fn() => CP::recordGrant($grant, $idpSession), 'a recordable grant is kept');

    // Make the record undeliverable the way StateDir itself judges it -- a bucket owned
    // by somebody else is refused rather than written into -- and put it back after.
    $sessions = \OPNsense\SSO\StateDir::path('sessions');
    $nobody = function_exists('posix_getpwnam') ? @posix_getpwnam('nobody') : false;
    if (!(function_exists('posix_geteuid') && posix_geteuid() === 0 && is_array($nobody))) {
        T::skip('the unrecordable case', 'needs root and a "nobody" account to break the bucket');
    } else {
        $owner = fileowner($sessions);
        chown($sessions, (int)$nobody['uid']);
        Backend::$calls = [];
        throws(
            fn() => CP::recordGrant($grant, $idpSession),
            'could not be recorded',
            'an unrecordable grant refuses the login'
        );
        eq(
            ['captiveportal disconnect', ['cp-session-1', 'os-sso: grant not recordable']],
            Backend::$calls[count(Backend::$calls) - 1],
            'and the client is disconnected again rather than left on the network'
        );
        chown($sessions, (int)$owner);
    }
}
