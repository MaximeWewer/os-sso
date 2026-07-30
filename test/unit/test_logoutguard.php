<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\LogoutGuard;

/**
 * Logout is a state change reachable by GET, so a third-party page could otherwise end
 * an administrator's session with an <img> tag. The guard proves same-origin intent, and
 * falls back to asking the user when it cannot.
 */
function withRequest(array $server, array $post = [], array $session = []): void
{
    $_SERVER = array_merge(['REQUEST_METHOD' => 'GET'], $server);
    $_POST = $post;
    $_SESSION = $session;
}

T::group('LogoutGuard: Sec-Fetch-Site decides when the browser sends it');

withRequest(['HTTP_SEC_FETCH_SITE' => 'same-origin']);
truthy(LogoutGuard::allow(), 'same-origin is allowed');
withRequest(['HTTP_SEC_FETCH_SITE' => 'none']);
truthy(LogoutGuard::allow(), 'none (a typed URL or bookmark) is allowed');
withRequest(['HTTP_SEC_FETCH_SITE' => 'cross-site']);
falsy(LogoutGuard::allow(), 'cross-site is refused');
withRequest(['HTTP_SEC_FETCH_SITE' => 'same-site']);
falsy(LogoutGuard::allow(), 'same-site (a sibling subdomain) is refused');
withRequest(['HTTP_SEC_FETCH_SITE' => 'SAME-ORIGIN']);
truthy(LogoutGuard::allow(), 'the header is matched case-insensitively');

// The header, when present, is authoritative: a matching Referer must not rescue a
// cross-site request.
withRequest(['HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_REFERER' => 'https://fw.example/ui',
             'HTTP_HOST' => 'fw.example']);
falsy(LogoutGuard::allow(), 'a same-host Referer does not override cross-site');

T::group('LogoutGuard: Referer is the fallback for older browsers');

withRequest(['HTTP_REFERER' => 'https://fw.example/ui/dashboard', 'HTTP_HOST' => 'fw.example']);
truthy(LogoutGuard::allow(), 'a same-host Referer is allowed');
withRequest(['HTTP_REFERER' => 'https://fw.example/ui', 'HTTP_HOST' => 'fw.example:8443']);
truthy(LogoutGuard::allow(), 'the host comparison ignores the port');
withRequest(['HTTP_REFERER' => 'https://FW.EXAMPLE/ui', 'HTTP_HOST' => 'fw.example']);
truthy(LogoutGuard::allow(), 'and is case-insensitive');
withRequest(['HTTP_REFERER' => 'https://evil.example/', 'HTTP_HOST' => 'fw.example']);
falsy(LogoutGuard::allow(), 'a foreign Referer is refused');
withRequest(['HTTP_REFERER' => 'https://fw.example.evil.example/', 'HTTP_HOST' => 'fw.example']);
falsy(LogoutGuard::allow(), 'a lookalike host is refused');
withRequest(['HTTP_REFERER' => 'not a url', 'HTTP_HOST' => 'fw.example']);
falsy(LogoutGuard::allow(), 'an unparseable Referer is refused');

T::group('LogoutGuard: with no evidence at all, ask');

withRequest([]);
falsy(LogoutGuard::allow(), 'no header and no Referer is refused');
withRequest(['HTTP_REFERER' => '', 'HTTP_SEC_FETCH_SITE' => '']);
falsy(LogoutGuard::allow(), 'empty values count as absent');

T::group('LogoutGuard: the confirmation page is a real CSRF gate');

withRequest([]);
$_SESSION = [];
$page = LogoutGuard::confirm('/api/sso/logout');
truthy(str_contains($page, "action='/api/sso/logout'"), 'the form posts back to the action');
truthy(str_contains($page, "method='post'"), 'over POST');
$token = $_SESSION['sso_logout_token'] ?? '';
eq(32, strlen($token), 'a 16-byte token is minted into the session');
truthy(str_contains($page, $token), 'and carried in the form');

// Posting the token back is what proves intent.
withRequest(['REQUEST_METHOD' => 'POST'], ['logout_token' => $token], ['sso_logout_token' => $token]);
truthy(LogoutGuard::allow(), 'the confirmed POST is allowed');
withRequest(['REQUEST_METHOD' => 'POST'], ['logout_token' => 'wrong'], ['sso_logout_token' => $token]);
falsy(LogoutGuard::allow(), 'a wrong token is refused');
withRequest(['REQUEST_METHOD' => 'POST'], ['logout_token' => $token], []);
falsy(LogoutGuard::allow(), 'a token with nothing in the session is refused');
withRequest(['REQUEST_METHOD' => 'POST'], [], ['sso_logout_token' => $token]);
falsy(LogoutGuard::allow(), 'a missing token is refused');
// An empty session token must not make an empty submission valid.
withRequest(['REQUEST_METHOD' => 'POST'], ['logout_token' => ''], ['sso_logout_token' => '']);
falsy(LogoutGuard::allow(), 'two empty tokens are not a match');
// The token only counts on POST, so a GET carrying it in the query changes nothing.
withRequest(['REQUEST_METHOD' => 'GET'], ['logout_token' => $token], ['sso_logout_token' => $token]);
falsy(LogoutGuard::allow(), 'the token does not authorise a GET');

$escaped = LogoutGuard::confirm("/x'\"><script>");
falsy(str_contains($escaped, '<script>'), 'the action is escaped into the markup');

$_SERVER = [];
$_POST = [];
$_SESSION = [];
