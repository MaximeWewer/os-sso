<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

/**
 * The slice of the SCIM filter language this endpoint answers: "eq" comparisons on the
 * attributes it can index, combined with "and", "or" and parentheses.
 *
 * Not the whole grammar, on purpose -- there is no index behind any of this, and a
 * firewall's account list is not a directory. But "eq" alone was too little: a
 * directory that reconciles by two attributes at once (`userName eq "x" and active eq
 * "true"`, or a pair of externalIds joined by `or`) had its request refused and fell
 * back to walking every page.
 *
 * Anything outside the subset is still REFUSED rather than approximated. A client that
 * believes it filtered, and did not, acts on every row that came back -- which on this
 * endpoint means deactivating accounts nobody asked about.
 */
final class ScimFilter
{
    /**
     * Compile a filter into a predicate over an attribute reader.
     *
     * @param callable $read fn(string $attribute): ?string -- the resource's value, or
     *        null when the attribute is not one we can filter on
     * @return callable fn(): bool
     * @throws ScimError on anything the subset does not cover
     */
    public static function compile(string $filter, callable $read): callable
    {
        $tokens = self::tokenize($filter);
        $position = 0;
        $node = self::parseOr($tokens, $position, $read);
        if ($position !== count($tokens)) {
            throw ScimError::badRequest('unsupported filter: ' . $filter, 'invalidFilter');
        }
        return $node;
    }

    /** @return string[] */
    private static function tokenize(string $filter): array
    {
        // Quoted values first, so a value containing "and" or a bracket stays one token.
        preg_match_all('/"(?:[^"\\\\]|\\\\.)*"|[()]|[^\s()]+/', $filter, $matches);
        return $matches[0] ?? [];
    }

    /** @param string[] $tokens */
    private static function parseOr(array $tokens, int &$position, callable $read): callable
    {
        $left = self::parseAnd($tokens, $position, $read);
        while (isset($tokens[$position]) && strcasecmp($tokens[$position], 'or') === 0) {
            $position++;
            $right = self::parseAnd($tokens, $position, $read);
            $left = fn() => $left() || $right();
        }
        return $left;
    }

    /** @param string[] $tokens */
    private static function parseAnd(array $tokens, int &$position, callable $read): callable
    {
        $left = self::parseTerm($tokens, $position, $read);
        while (isset($tokens[$position]) && strcasecmp($tokens[$position], 'and') === 0) {
            $position++;
            $right = self::parseTerm($tokens, $position, $read);
            $left = fn() => $left() && $right();
        }
        return $left;
    }

    /** @param string[] $tokens */
    private static function parseTerm(array $tokens, int &$position, callable $read): callable
    {
        if (($tokens[$position] ?? '') === '(') {
            $position++;
            $inner = self::parseOr($tokens, $position, $read);
            if (($tokens[$position] ?? '') !== ')') {
                throw ScimError::badRequest('unbalanced parentheses in the filter', 'invalidFilter');
            }
            $position++;
            return $inner;
        }

        $attribute = $tokens[$position] ?? '';
        $operator = $tokens[$position + 1] ?? '';
        $value = $tokens[$position + 2] ?? '';
        if ($attribute === '' || $operator === '' || $value === '') {
            throw ScimError::badRequest('incomplete filter expression', 'invalidFilter');
        }
        if (strcasecmp($operator, 'eq') !== 0) {
            throw ScimError::badRequest(
                'only the "eq" operator is supported (got "' . $operator . '")',
                'invalidFilter'
            );
        }
        $position += 3;

        $wanted = self::unquote($value);
        return function () use ($read, $attribute, $wanted) {
            $actual = $read(strtolower($attribute));
            if ($actual === null) {
                throw ScimError::badRequest(
                    'filtering on ' . $attribute . ' is not supported',
                    'invalidFilter'
                );
            }
            // SCIM string comparison is case-insensitive unless the attribute is
            // caseExact, and none of ours is.
            return strcasecmp($actual, $wanted) === 0;
        };
    }

    private static function unquote(string $token): string
    {
        if (strlen($token) >= 2 && $token[0] === '"' && substr($token, -1) === '"') {
            return stripcslashes(substr($token, 1, -1));
        }
        return $token;
    }
}
