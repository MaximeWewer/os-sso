<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\ReturnUrl;

T::group('ReturnUrl: only same-site paths survive');

foreach ([
    '/ui/dashboard' => '/ui/dashboard',
    '/index.php?logout' => '/index.php?logout',
    '/a/b?x=1&y=2#frag' => '/a/b?x=1&y=2#frag',
    '/' => '/',
] as $input => $expected) {
    eq($expected, ReturnUrl::sanitize($input), "keeps " . json_encode($input));
}

// Everything that leaves the site, or forges a header, collapses to '/'.
foreach ([
    '' => 'empty',
    'https://evil.example/' => 'absolute https',
    'http://evil.example/' => 'absolute http',
    '//evil.example/' => 'protocol-relative',
    '/\\evil.example/' => 'backslash-folded protocol-relative',
    '\\\\evil.example' => 'UNC-style',
    'javascript:alert(1)' => 'javascript scheme',
    'data:text/html,x' => 'data scheme',
    "/ok\r\nLocation: https://evil.example" => 'CRLF header split',
    "/ok\nX: y" => 'bare LF',
    "/ok\tx" => 'tab',
    'ui/dashboard' => 'scheme-less relative without a leading slash',
    ' /ui' => 'leading space',
] as $input => $why) {
    eq('/', ReturnUrl::sanitize($input), "refuses {$why}");
}

T::group('ReturnUrl: landing prefers the requested page');

eq('/ui/x', ReturnUrl::landing('/ui/x', '/ui/default'), 'requested page wins');
eq('/ui/default', ReturnUrl::landing('/', '/ui/default'), 'falls back to the configured default');
eq('/ui/default', ReturnUrl::landing('', '/ui/default'), 'empty request falls back too');
eq('/', ReturnUrl::landing('/', ''), 'no default means the dashboard');
eq('/ui/default', ReturnUrl::landing('/', '  /ui/default  '), 'the default is trimmed');
// A hostile value in EITHER position has to be neutralised, not just the request one:
// the default comes from config.xml, which the GUI validates -- but not exclusively.
eq('/', ReturnUrl::landing('https://evil.example', ''), 'an off-site request is refused');
eq('/', ReturnUrl::landing('/', 'https://evil.example'), 'an off-site default is refused');
eq('/', ReturnUrl::landing('/', '//evil.example'), 'a protocol-relative default is refused');
