<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Response headers for the handful of HTML pages this plugin renders itself: the
 * "you are connected" and "VPN authorized" pages, the sign-out confirmation, and the
 * self-submitting form that carries a SAML AuthnRequest over the HTTP-POST binding.
 *
 * They are served from the firewall's own origin, at moments that matter -- one asks
 * for a click that ends a session, another bounces off-site, the third posts to the
 * IdP. None of them is ever a frame, so say so: a framed sign-out button is a
 * one-click logout for any page that embeds it, and the rest of the policy keeps a
 * page that loads nothing from loading anything.
 */
final class HtmlPage
{
    /**
     * @param string $formAction where this page's form may post: "'self'" for our own
     *               endpoints, an absolute URL for the SAML POST binding, '' when the
     *               page has no form at all
     * @param bool $inlineScript the page carries inline script (the POST binding form
     *             submits itself, so that one does)
     * @return array<string,string>
     */
    public static function headers(string $formAction = "'self'", bool $inlineScript = false): array
    {
        $policy = ["default-src 'none'", "style-src 'unsafe-inline'", "base-uri 'none'", "frame-ancestors 'none'"];
        if ($inlineScript) {
            $policy[] = "script-src 'unsafe-inline'";
        }
        $policy[] = 'form-action ' . ($formAction === '' ? "'none'" : $formAction);

        return [
            'Content-Type' => 'text/html; charset=UTF-8',
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'no-store',
            'Content-Security-Policy' => implode('; ', $policy),
        ];
    }

    /** The origin a URL belongs to, for a form-action policy ('' when unusable). */
    public static function originOf(string $url): string
    {
        $parts = parse_url($url);
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true) || empty($parts['host'])) {
            return '';
        }
        return $scheme . '://' . strtolower((string)$parts['host'])
            . (isset($parts['port']) ? ':' . (int)$parts['port'] : '');
    }
}
