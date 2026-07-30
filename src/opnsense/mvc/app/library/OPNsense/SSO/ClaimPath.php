<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Reads a claim out of a decoded token by name, or by dot-separated path.
 *
 * Shared by the OIDC and JWT paths, which see the same shapes: an ID token decoded to
 * nested stdClass objects, merged with a userinfo document decoded to nested arrays.
 */
final class ClaimPath
{
    /**
     * Value of a claim named by a dot-separated path, or null.
     *
     * The path exists because the group claim is frequently NOT top level. Keycloak puts
     * client roles under `resource_access.<client-id>.roles` and realm roles under
     * `realm_access.roles`; a top-level-only lookup finds neither and the login reads as
     * "the IdP sends no groups at all" -- which, with required groups configured, is a
     * refusal nobody can explain from the logs.
     *
     * A literal dot in a claim NAME still wins: the whole key is tried before the path is
     * split, so an OID-style claim such as `urn:oid:0.9.2342.19200300.100.1.1` keeps
     * resolving as one name.
     *
     * @param array $claims decoded claims (values may be arrays or stdClass)
     * @return mixed
     */
    public static function get(array $claims, string $path)
    {
        if ($path === '') {
            return null;
        }
        if (array_key_exists($path, $claims)) {
            return $claims[$path];
        }
        $node = $claims;
        foreach (explode('.', $path) as $segment) {
            if (is_object($node)) {
                $node = (array)$node;
            }
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return null;
            }
            $node = $node[$segment];
        }
        return $node;
    }

    /**
     * A claim read as a list of group names.
     *
     * Accepts what IdPs actually send: a JSON array, or a single string holding several
     * names separated by commas or whitespace. Non-scalar entries are dropped rather than
     * stringified -- a nested array would otherwise become the literal "Array" and be
     * matched against a group of that name.
     *
     * @return string[]
     */
    public static function groups(array $claims, string $path): array
    {
        $value = self::get($claims, $path);
        if (is_string($value)) {
            $value = preg_split('/[,\s]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        if (is_object($value)) {
            $value = (array)$value;
        }
        if (!is_array($value)) {
            $value = $value === null ? [] : [$value];
        }
        $out = [];
        foreach ($value as $entry) {
            if (is_scalar($entry) && (string)$entry !== '') {
                $out[] = (string)$entry;
            }
        }
        return array_values($out);
    }
}
