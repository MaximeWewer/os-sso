<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;

/**
 * SessionEstablisher -- the jewel. The single place that turns "the IdP vouched
 * for this person" into "this browser is now logged in as <localUsername>".
 *
 * It mirrors the core WebGUI success path (src/www/authgui.inc, session_auth()):
 * core sets $_SESSION['Username'], ['last_access'], ['protocol'] and calls
 * session_regenerate_id(). OPNsense's session service is the native PHP session
 * (Phalcon Files adapter writes through to $_SESSION), so writing $_SESSION here
 * is the same store the rest of the GUI reads on the next request.
 *
 * Hard rules:
 *   - session_regenerate_id(true) ALWAYS (anti-fixation). Core does it; Lachee
 *     forgets it -- we do not.
 *   - NEVER write privileges into the session. The ACL resolves them from group
 *     membership in config.xml on every request. Injecting them would create a
 *     stale, forgeable authorization snapshot.
 *   - The local user MUST already exist and be enabled in config.xml, otherwise
 *     the ACL cannot see its groups. Provisioning happens BEFORE this call.
 */
final class SessionEstablisher
{
    /**
     * Establish an authenticated WebGUI session for an existing local user.
     *
     * @param string $localUsername local account name (already provisioned)
     * @param string $authServerName authserver name that authenticated (audit + timeout)
     * @param array $idpSession issuer, sub, sid and lifetime -- recorded so the session
     *              can be ended later by a back-channel logout or by its own deadline
     * @throws \RuntimeException if the user does not exist or is disabled
     */
    public function establish(string $localUsername, string $authServerName, array $idpSession = []): void
    {
        $cnf = Config::getInstance()->object();

        // 1. The local user must exist AND be enabled, or the ACL grants nothing.
        $userNode = $this->findEnabledUser($cnf, $localUsername);
        if ($userNode === null) {
            throw new \RuntimeException(
                sprintf("SSO: refusing to establish session, local user '%s' is missing, disabled or expired", $localUsername)
            );
        }

        // 2. Anti-fixation. Non-negotiable. true => destroy the old session id.
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        // 3. Core success-path session variables (copied from authgui.inc, not guessed).
        $_SESSION['Username'] = $localUsername;
        $_SESSION['last_access'] = time();
        $_SESSION['protocol'] = (string)$cnf->system->webgui->protocol;

        // Password-change / expiry flags: SSO users never authenticate with the
        // local password, so the local change-password ceremony does not apply.
        // We deliberately leave user_shouldChangePassword unset.

        // 4. Record the originating auth server (audit trail + session timeout policy).
        $_SESSION['auth_server'] = $authServerName;

        // 5. Register the session so it can be ended from outside this browser: a
        //    back-channel logout from the IdP, or its own absolute deadline. Also
        //    sweep whatever has meanwhile expired -- a login is a cheap, regular
        //    moment to do it, on top of the scheduled "sso expire_sessions" action.
        SessionRegistry::record([
            'username' => $localUsername,
            'provider' => $authServerName,
            'issuer' => (string)($idpSession['issuer'] ?? ''),
            'sub' => (string)($idpSession['sub'] ?? ''),
            'sid' => (string)($idpSession['sid'] ?? ''),
            'lifetime' => (int)($idpSession['lifetime'] ?? 0),
        ]);
        SessionRegistry::sweep();

        // 6. Audit, matching the core wording so log tooling stays uniform.
        $this->audit($localUsername, $authServerName);

        // 7. Privileges: intentionally untouched. Resolved by OPNsense\Core\ACL
        //    from group membership on the next request.
    }

    private function findEnabledUser(\SimpleXMLElement $cnf, string $username): ?\SimpleXMLElement
    {
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return null;
        }
        foreach ($cnf->system->user as $user) {
            if ((string)$user->name === $username) {
                // Parity with core Local::_authenticate(): disabled or past <expires>
                // is refused on the password path, so SSO is not a way around it.
                return LocalAccount::isUsable($user) ? $user : null;
            }
        }
        return null;
    }

    /**
     * End the current browser's WebGUI session, the mirror of establish().
     *
     * Drops the registry record first so a swept-away session file cannot be mistaken for
     * a live one, then wipes the data, expires the cookie and destroys the store. Mirrors
     * what core's own logout does; the two SSO logout paths had a copy each.
     */
    public static function destroyCurrent(): void
    {
        SessionRegistry::forget((string)session_id());
        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000, '/', '', true, true);
        }
        @session_destroy();
    }

    private function audit(string $username, string $authServerName): void
    {
        openlog("audit", LOG_ODELAY, LOG_AUTH);
        syslog(
            LOG_NOTICE,
            sprintf("Successful login for user '%s' via SSO (%s)", $username, $authServerName)
        );
        closelog();
    }
}
