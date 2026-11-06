<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Signed request objects the IdP fetches by reference (JAR request_uri, RFC 9101
 * section 5.2): the firewall keeps the JWT for a couple of minutes under an unguessable
 * id, and the authorization URL carries only the URL to it.
 *
 * What the store holds is no secret -- the same signed object travels in the browser
 * URL without by-reference mode -- so a fetch does not consume it: an IdP that reads it
 * twice still works, and the short lifetime bounds the rest. The id only has to be
 * unguessable so that nobody can list what is in flight.
 */
final class RequestObjectStore
{
    /** Long enough for a slow IdP; the object's own exp is the real limit. */
    public const TTL = 120;

    private const ID = '/^[A-Za-z0-9_-]{43}$/';

    /** Keep $jwt for TTL seconds; return the id that names it. */
    public static function put(string $jwt, ?int $now = null): string
    {
        $now = $now ?? time();
        $dir = StateDir::path('request');
        self::sweep($dir, $now);
        $id = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $tmp = tempnam($dir, '.tmp');
        $entry = json_encode(['exp' => $now + self::TTL, 'jwt' => $jwt]);
        if ($tmp === false || file_put_contents($tmp, $entry) === false) {
            throw new \RuntimeException('SSO: could not store the request object');
        }
        chmod($tmp, 0600);
        rename($tmp, "$dir/$id.json");
        return $id;
    }

    /** The request object stored under $id, or null when there is none (or no longer). */
    public static function get(string $id, ?int $now = null): ?string
    {
        if (preg_match(self::ID, $id) !== 1) {
            return null;
        }
        $file = StateDir::path('request') . "/$id.json";
        $entry = is_file($file) ? json_decode((string)file_get_contents($file), true) : null;
        if (!is_array($entry) || (int)($entry['exp'] ?? 0) < ($now ?? time())) {
            return null;
        }
        return (string)($entry['jwt'] ?? '') ?: null;
    }

    /** Drop expired entries; called on every put, so the directory stays small. */
    private static function sweep(string $dir, int $now): void
    {
        foreach (glob("$dir/*.json") ?: [] as $file) {
            $entry = json_decode((string)@file_get_contents($file), true);
            if (!is_array($entry) || (int)($entry['exp'] ?? 0) < $now) {
                @unlink($file);
            }
        }
    }
}
