<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\HtmlPage;

T::group('HtmlPage: the pages the plugin renders itself');

$h = HtmlPage::headers();
eq('DENY', $h['X-Frame-Options'], 'never a frame');
truthy(str_contains($h['Content-Security-Policy'], "frame-ancestors 'none'"), 'and the CSP says so too');
truthy(str_contains($h['Content-Security-Policy'], "form-action 'self'"), 'a form posts back to us by default');
falsy(str_contains($h['Content-Security-Policy'], 'script-src'), 'no script is allowed unless asked for');
eq('no-store', $h['Cache-Control'], 'and none of it is cached');

$post = HtmlPage::headers('https://idp.example', true);
truthy(str_contains($post['Content-Security-Policy'], "script-src 'unsafe-inline'"), 'the POST binding form may submit itself');
truthy(str_contains($post['Content-Security-Policy'], 'form-action https://idp.example'), 'and post to the IdP');

eq('https://idp.example', HtmlPage::originOf('https://idp.example/saml/sso?x=1'), 'an origin drops the path');
eq('https://idp.example:8443', HtmlPage::originOf('https://IDP.example:8443/x'), 'the port is part of it');
eq('', HtmlPage::originOf('javascript:alert(1)'), 'a non-http URL is not an origin');
eq('', HtmlPage::originOf(''), 'nor is nothing');

T::group('HtmlPage: the signed-out page after an IdP logout');

// It exists to drop the IdP's Referer before the login page (issue #10), so the
// no-referrer marking and the immediate hop to '/' are the whole point of it.
$page = HtmlPage::signedOut();
truthy(str_contains($page, "<meta name='referrer' content='no-referrer'>"), 'the page itself is marked no-referrer');
truthy(str_contains($page, "content='0;url=/'"), 'it moves straight on to the login page');
truthy(str_contains($page, "rel='noreferrer' href='/'"), 'and its fallback link sends no Referer either');

// $to may come from a SAML RelayState: it must stay on this site.
foreach (['https://evil.example/', '//evil.example/', '/\\evil.example', 'javascript:alert(1)'] as $to) {
    truthy(str_contains(HtmlPage::signedOut($to), "content='0;url=/'"), 'an off-site target falls back to /: ' . $to);
}
truthy(str_contains(HtmlPage::signedOut('/ui/core/dashboard'), "url=/ui/core/dashboard'"), 'a same-site path is kept');
falsy(str_contains(HtmlPage::signedOut("/x'><script>"), '<script>'), 'and is escaped');
