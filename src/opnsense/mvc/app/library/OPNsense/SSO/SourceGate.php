<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * "Is this request coming from somewhere we agreed to trust?"
 *
 * Two endpoints answer to a credential carried in a header rather than to a browser
 * session -- JWT forward-auth and SCIM -- and for both, the header alone is not
 * enough: it can be replayed from anywhere. Pinning the TCP peer is what bounds who
 * can even try. The check is always on REMOTE_ADDR, never on a forwardable header,
 * because X-Forwarded-For is written by whoever is calling.
 */
final class SourceGate
{
    /**
     * Is $ip inside any of the configured IPs/CIDRs? IPv4 and IPv6, binary compare.
     *
     * @param string[] $cidrs
     */
    public static function allows(string $ip, array $cidrs): bool
    {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            $cidr = trim((string)$cidr);
            if ($cidr === '') {
                continue;
            }
            if (strpos($cidr, '/') === false) {
                $netBin = @inet_pton($cidr);
                if ($netBin !== false && $netBin === $ipBin) {
                    return true;
                }
                continue;
            }
            [$net, $bitsRaw] = explode('/', $cidr, 2);
            $netBin = @inet_pton($net);
            if ($netBin === false || strlen($netBin) !== strlen($ipBin)) {
                continue;
            }
            $bits = (int)$bitsRaw;
            // Reject a prefix length outside the address width: an over-long prefix
            // would index past the address bytes below and spuriously over-match.
            if ($bits < 0 || $bits > strlen($ipBin) * 8) {
                continue;
            }
            $bytes = intdiv($bits, 8);
            $rem = $bits % 8;
            if ($bytes > 0 && strncmp($ipBin, $netBin, $bytes) !== 0) {
                continue;
            }
            if ($rem === 0) {
                return true;
            }
            $mask = chr((0xff << (8 - $rem)) & 0xff);
            if (((ord($ipBin[$bytes]) ^ ord($netBin[$bytes])) & ord($mask)) === 0) {
                return true;
            }
        }
        return false;
    }
}
