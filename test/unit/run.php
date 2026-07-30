<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * os-sso unit tests.
 *
 *   php test/unit/run.php              # everything
 *   php test/unit/run.php scim         # only files whose name matches
 *
 * Deliberately dependency-free, in the same spirit as the shell suites under
 * test/e2e: `php run.php` is the whole toolchain. What it covers is the logic that
 * decides security and is pure enough to call directly -- which local account an
 * asserted identity may bind to, which group a directory may fill, what counts as a
 * same-site return URL, how a client proves it is the client. Those rules are exactly
 * the ones an e2e suite exercises only through the happy path.
 *
 * A few tests need /var/db/os-sso (the state directory the config lock lives in) and
 * report SKIP rather than fail when it is not writable, so the suite still runs
 * unprivileged. To run all of it:
 *
 *   docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php test/unit/run.php
 */

$root = dirname(__DIR__, 2);
$library = $root . '/src/opnsense/mvc/app/library';

// Stubs for the core services the library talks to (Config, Backend). Must be defined
// before anything else so the autoloader below never looks for them.
require __DIR__ . '/lib/stubs.php';

// The plugin ships no autoloader of its own (OPNsense provides one at runtime), so map
// the two namespaces we test by hand, and hand OPNsense\SSO\* over to composer's for
// the vendored firebase/onelogin classes.
spl_autoload_register(function (string $class) use ($library) {
    if (strncmp($class, 'OPNsense\\', 9) !== 0) {
        return;
    }
    $file = $library . '/' . str_replace('\\', '/', $class) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
$vendor = $library . '/OPNsense/SSO/vendor/autoload.php';
if (is_file($vendor)) {
    require $vendor;
}

/* ---------------------------------------------------------------- harness */

final class T
{
    public static int $pass = 0;
    public static int $fail = 0;
    public static int $skip = 0;
    public static string $group = '';
    /** @var string[] */
    public static array $failures = [];

    public static function group(string $name): void
    {
        self::$group = $name;
        echo "\n>>> {$name}\n";
    }

    public static function ok(string $label): void
    {
        self::$pass++;
        echo "  ok   {$label}\n";
    }

    public static function ko(string $label, string $detail): void
    {
        self::$fail++;
        self::$failures[] = self::$group . ' / ' . $label . ': ' . $detail;
        echo "  FAIL {$label}\n       {$detail}\n";
    }

    public static function skip(string $label, string $why): void
    {
        self::$skip++;
        echo "  skip {$label} ({$why})\n";
    }
}

/** Assert two values are equal, compared structurally. */
function eq($expected, $actual, string $label): void
{
    if ($expected === $actual) {
        T::ok($label);
        return;
    }
    T::ko($label, sprintf('expected %s, got %s', json_encode($expected), json_encode($actual)));
}

function truthy($actual, string $label): void
{
    $actual ? T::ok($label) : T::ko($label, 'expected a truthy value, got ' . json_encode($actual));
}

function falsy($actual, string $label): void
{
    !$actual ? T::ok($label) : T::ko($label, 'expected a falsy value, got ' . json_encode($actual));
}

/**
 * Assert the callable throws, and that the message mentions $needle -- the message is
 * what an operator reads in the log, so it is part of the behaviour.
 */
function throws(callable $fn, string $needle, string $label): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($needle === '' || stripos($e->getMessage(), $needle) !== false) {
            T::ok($label);
            return;
        }
        T::ko($label, sprintf('threw, but the message was "%s" (wanted "%s")', $e->getMessage(), $needle));
        return;
    }
    T::ko($label, 'did not throw');
}

/** Assert the callable does NOT throw, returning whatever it produced. */
function nothrow(callable $fn, string $label)
{
    try {
        $value = $fn();
        T::ok($label);
        return $value;
    } catch (\Throwable $e) {
        T::ko($label, 'threw ' . get_class($e) . ': ' . $e->getMessage());
        return null;
    }
}

/** True when the state directory the config lock needs is usable. */
function stateDirUsable(): bool
{
    static $usable = null;
    if ($usable === null) {
        try {
            \OPNsense\SSO\StateDir::path('unit-probe');
            $usable = true;
        } catch (\Throwable $e) {
            $usable = false;
        }
    }
    return $usable;
}

/* ------------------------------------------------------------------- run */

$filter = $argv[1] ?? '';
$files = glob(__DIR__ . '/test_*.php') ?: [];
sort($files);

echo "=== os-sso unit tests (PHP " . PHP_VERSION . ") ===\n";
foreach ($files as $file) {
    if ($filter !== '' && stripos(basename($file), $filter) === false) {
        continue;
    }
    require $file;
}

echo "\n";
foreach (T::$failures as $failure) {
    echo "FAILED: {$failure}\n";
}
printf(
    ">>> RESULT: %d passed, %d failed, %d skipped\n",
    T::$pass,
    T::$fail,
    T::$skip
);
exit(T::$fail === 0 ? 0 : 1);
