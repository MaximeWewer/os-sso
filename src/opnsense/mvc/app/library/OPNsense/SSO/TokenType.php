<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Explicit typing of JWTs (RFC 8725 section 3.11): the `typ` header says what kind of
 * token this is, so one kind cannot be passed off as another.
 *
 * Several kinds are signed by the same IdP keys -- ID tokens, back-channel logout tokens,
 * access tokens, security events -- and each verifier otherwise tells them apart only by
 * their claims. Where the IdP declares a type, it is checked: a token declaring a kind
 * that does not belong somewhere is refused there, and a logout token may declare only
 * logout+jwt (OIDC Back-Channel Logout 1.0) or the generic JWT. An absent `typ`, and
 * the generic "JWT" most JWT libraries write by default, are accepted everywhere:
 * requiring the specific type would refuse IdPs that never set it.
 */
final class TokenType
{
    public const LOGOUT = 'logout+jwt';
    public const ACCESS = 'at+jwt';
    public const DPOP = 'dpop+jwt';
    public const SECEVENT = 'secevent+jwt';
    /** The generic type most JWT libraries write by default. */
    public const GENERIC = 'jwt';

    /** The declared type, lowercased and without an "application/" prefix; '' when none. */
    public static function of(string $jwt): string
    {
        $dot = strpos($jwt, '.');
        $header = $dot === false ? null
            : json_decode((string)base64_decode(strtr(substr($jwt, 0, $dot), '-_', '+/')), true);
        $typ = is_array($header) && is_string($header['typ'] ?? null) ? strtolower(trim($header['typ'])) : '';
        return str_starts_with($typ, 'application/') ? substr($typ, strlen('application/')) : $typ;
    }

    /**
     * Refuse a token that declares one of the $foreign kinds.
     *
     * @param string[] $foreign
     */
    public static function refuse(string $jwt, array $foreign, string $what): void
    {
        $typ = self::of($jwt);
        if ($typ !== '' && in_array($typ, $foreign, true)) {
            throw new \RuntimeException(sprintf('%s: a %s token is not accepted here', $what, $typ));
        }
    }

    /**
     * When the token declares a type, it must be one of $allowed.
     *
     * @param string[] $allowed
     */
    public static function allowOnly(string $jwt, array $allowed, string $what): void
    {
        $typ = self::of($jwt);
        if ($typ !== '' && !in_array($typ, $allowed, true)) {
            throw new \RuntimeException(sprintf('%s: typ is %s, expected %s', $what, $typ, implode(' or ', $allowed)));
        }
    }
}
