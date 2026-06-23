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
     * @throws \RuntimeException on an unknown session, ip mismatch, or failed write
     */
    public static function authorize(string $vpn, string $username, string $browserIp): void
    {
        $sid = preg_replace('/[^a-f0-9]/', '', $vpn);
        if ($sid === '') {
            throw new \RuntimeException('invalid VPN session');
        }
        $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $browserIp);
        $out = trim((string)(new Backend())->configdpRun('sso vpn_verdict', [$sid, '1', $ip]));
        if ($out !== 'ok') {
            throw new \RuntimeException('VPN authorization failed: ' . $out);
        }
        syslog(LOG_NOTICE, sprintf("os-sso vpn: authorized tunnel for '%s' from %s", $username, $ip));
    }

    /** Minimal "close this window" page shown to the VPN client's browser. */
    public static function donePage(string $username): string
    {
        $u = htmlspecialchars($username, ENT_QUOTES);
        return "<!doctype html><html><head><meta charset='utf-8'><title>VPN authorized</title>"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em;color:#1b5e20}</style>"
            . "</head><body><h2>&#10003; VPN authorized</h2>"
            . "<p>Signed in as <strong>{$u}</strong>. You can close this window and return to your VPN client.</p>"
            . "</body></html>";
    }
}
