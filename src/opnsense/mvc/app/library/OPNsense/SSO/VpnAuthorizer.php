<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;

/**
 * Authorizes an OpenVPN deferred web-auth attempt, shared by the OIDC and SAML
 * controllers. OpenVPN's control file is root-owned while the WebGUI runs as www,
 * so the privileged write is delegated to configd (vpn_verdict.sh, root). The
 * auth-user-pass-verify script stored the {sid -> control file} mapping; the
 * verdict script resolves and consumes it (single use).
 */
final class VpnAuthorizer
{
    /**
     * @param string $vpn one-time VPN session id (hex)
     * @param string $username verified local username (for audit)
     * @param string $browserIp source IP of the browser completing the SSO login;
     *               must match the VPN client's IP (enforced by vpn_verdict.sh)
     * @return string the common name OpenVPN knows this tunnel by -- the username the
     *         client sent, which is the only handle a later revocation can kill it with
     *         ('' when the client sent none)
     * @throws \RuntimeException on an unknown session, ip mismatch, or failed write
     */
    public static function authorize(string $vpn, string $username, string $browserIp): string
    {
        $sid = preg_replace('/[^a-f0-9]/', '', $vpn);
        if ($sid === '') {
            throw new \RuntimeException('invalid VPN session');
        }
        $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $browserIp);
        // The account that actually signed in, so the verdict script can log it next to
        // the username the client asked for -- and refuse the two differing when the
        // operator enabled that. Reduced to the local-account charset: this crosses
        // configd into a positional shell argument.
        $user = preg_replace('/[^A-Za-z0-9._\- ]/', '', $username);
        $out = trim((string)(new Backend())->configdpRun('sso vpn_verdict', [$sid, '1', $ip, $user]));
        // "ok", or "ok <common name>" when the client sent a username -- which is what
        // OpenVPN goes on using, and therefore what a revocation has to kill.
        $parts = explode(' ', $out, 2);
        if (($parts[0] ?? '') !== 'ok') {
            throw new \RuntimeException('VPN authorization failed: ' . $out);
        }
        syslog(LOG_NOTICE, sprintf("os-sso vpn: authorized tunnel for '%s' from %s", $username, $ip));
        return trim($parts[1] ?? '');
    }

    /** Minimal "close this window" page shown to the VPN client's browser. */
    public static function donePage(string $username): string
    {
        $u = htmlspecialchars($username, ENT_QUOTES);
        $title = htmlspecialchars(gettext('VPN authorized'), ENT_QUOTES);
        $body = sprintf(
            htmlspecialchars(gettext('Signed in as %s. You can close this window and return to your VPN client.')),
            '<strong>' . $u . '</strong>'
        );
        return "<!doctype html><html><head><meta charset='utf-8'><title>{$title}</title>"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em;color:#1b5e20}</style>"
            . "</head><body><h2>&#10003; {$title}</h2>"
            . "<p>{$body}</p>"
            . "</body></html>";
    }
}
