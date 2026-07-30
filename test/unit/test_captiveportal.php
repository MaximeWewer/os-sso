<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\CaptivePortalAuthorizer as CP;

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
