<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;

/**
 * Serialises the config.xml writes os-sso does during a login, across php-fpm
 * workers, and re-reads the file under the lock.
 *
 * Two logins landing at once would otherwise race the nextuid counter or clobber each
 * other's user node -- and a duplicate uid means one user inherits the other's group
 * membership. Failing the login is the correct outcome when the lock cannot be taken:
 * proceeding unserialised is exactly the case we are protecting against.
 */
final class ConfigLock
{
    /**
     * Run $fn with the lock held and config.xml freshly reloaded.
     *
     * @return mixed whatever $fn returns
     * @throws \RuntimeException when the lock cannot be opened or acquired
     */
    public static function with(callable $fn)
    {
        $lock = StateDir::path('run') . '/config.lock';
        $fp = @fopen($lock, 'c');
        if ($fp === false) {
            throw new \RuntimeException('SSO: cannot open the config lock; refusing to proceed unserialized');
        }
        @chmod($lock, 0600);
        try {
            if (!flock($fp, LOCK_EX)) {
                throw new \RuntimeException('SSO: cannot acquire the config lock; refusing to proceed unserialized');
            }
            Config::getInstance()->forceReload();
            return $fn();
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
}
