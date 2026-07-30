<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Every read and write os-sso performs on a config.xml user node.
 *
 * Two very different callers need the same primitives: IdentityMapper, which acts on
 * an identity asserted during a login, and the SCIM endpoint, which acts on a
 * directory push with no login and no assertion at all. The account rules -- what a
 * username may look like, which accounts are privileged, which ones os-sso is allowed
 * to touch -- must not be duplicated between them, because a rule enforced on only
 * one of the two paths is a rule that can be walked around by using the other.
 *
 * Nothing here decides policy. It finds, creates and edits nodes; the callers decide
 * whether they are allowed to.
 */
final class LocalAccountWriter
{
    /** @return \SimpleXMLElement[] */
    public function users(): array
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return [];
        }
        $out = [];
        foreach ($cnf->system->user as $user) {
            $out[] = $user;
        }
        return $out;
    }

    public function findByName(string $username): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ((string)$user->name === $username) {
                return $user;
            }
        }
        return null;
    }

    public function findByUid(string $uid): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ($uid !== '' && (string)($user->uid ?? '') === $uid) {
                return $user;
            }
        }
        return null;
    }

    public function findByEmail(string $email): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if (isset($user->email) && (string)$user->email === $email) {
                return $user;
            }
        }
        return null;
    }

    /**
     * Every IdP binding recorded on an account, as "provider|subject" strings.
     *
     * Repeated <sso_subject> children rather than one: a single local account is
     * routinely reachable through more than one provider -- the same directory fronted
     * by OIDC for the WebGUI and by SAML for something else is an ordinary setup, and
     * each protocol calls the same person by a different subject. One binding PER
     * PROVIDER is the invariant that matters; one binding in total is not.
     *
     * @return string[]
     */
    public function subjectBindings(\SimpleXMLElement $node): array
    {
        $out = [];
        foreach ($node->sso_subject as $binding) {
            $value = trim((string)$binding);
            if ($value !== '') {
                $out[] = $value;
            }
        }
        return $out;
    }

    /** The account carrying this exact binding, or null. */
    public function findBySubject(string $subjectKey): ?\SimpleXMLElement
    {
        if ($subjectKey === '') {
            return null;
        }
        foreach ($this->users() as $user) {
            foreach ($this->subjectBindings($user) as $binding) {
                if (hash_equals($binding, $subjectKey)) {
                    return $user;
                }
            }
        }
        return null;
    }

    /**
     * The binding this account carries for one provider, '' when it has none.
     *
     * Split on the FIRST separator only: the provider name is what precedes it, and a
     * subject is free to contain one.
     */
    public function bindingFor(\SimpleXMLElement $node, string $provider): string
    {
        $prefix = $provider . '|';
        foreach ($this->subjectBindings($node) as $binding) {
            if (str_starts_with($binding, $prefix)) {
                return $binding;
            }
        }
        return '';
    }

    /** Record a binding, unless one is already present for that provider. */
    public function addBinding(\SimpleXMLElement $node, string $subjectKey): bool
    {
        $provider = explode('|', $subjectKey, 2)[0];
        if ($subjectKey === '' || $provider === '' || $this->bindingFor($node, $provider) !== '') {
            return false;
        }
        $node->addChild('sso_subject', $this->xml($subjectKey));
        return true;
    }

    public function findByStamp(string $field, string $value): ?\SimpleXMLElement
    {
        if ($value === '') {
            return null;
        }
        foreach ($this->users() as $user) {
            $stamp = (string)($user->{$field} ?? '');
            if ($stamp !== '' && hash_equals($stamp, $value)) {
                return $user;
            }
        }
        return null;
    }

    /**
     * Enforce a strict local-username shape before the name is used to match an
     * account or written to config.xml. We bypass the core User model (to stay
     * dependency-light), so we must re-apply its constraint here: a username
     * carrying control characters or newlines would forge syslog/audit lines, and
     * leading/trailing whitespace or interior runs invite homoglyph collisions
     * with existing accounts. Allowed: letters, digits, '.', '-', '_', and single
     * interior spaces; 1-64 chars; no edge whitespace.
     */
    public function assertValidUsername(string $username): void
    {
        if (
            $username !== trim($username)
            || strlen($username) > 64
            || !preg_match('/^[A-Za-z0-9._-]+( [A-Za-z0-9._-]+)*$/', $username)
        ) {
            throw new \RuntimeException(
                "SSO: '" . preg_replace('/[^\x20-\x7e]/', '', $username) . "' is not a valid local " .
                "account name (allowed: letters, digits, '.', '-', '_', single interior spaces; 1-64 chars)"
            );
        }
    }

    /** Built-in/system account, or a member of the admins group. */
    public function isPrivileged(\SimpleXMLElement $node): bool
    {
        return Privilege::isPrivilegedAccount($node);
    }

    /**
     * An account os-sso itself owns: one it created or has already claimed, carrying
     * our binding stamp.
     *
     * Deliberately NOT "has no local password". A scrambled password is the WebGUI's
     * own "prevent local database logins" checkbox, which is exactly how an operator
     * configures an LDAP- or RADIUS-backed account -- including an administrator's.
     * Reading that as "os-sso manages this" handed every such account, `admins`
     * members included, straight past guardBinding(): only accounts we own may be
     * (re)bound to an asserted identity without further proof.
     *
     * Whether an account can be bound at all is a separate question, answered by
     * hasUsableLocalPassword() below.
     */
    public function isSsoManaged(\SimpleXMLElement $node): bool
    {
        return (string)($node->{self::OWNED_FIELD} ?? '') === '1'
            || (string)($node->sso_subject ?? '') !== ''
            || (string)($node->scim_ref ?? '') !== '';
    }

    /** Set on every account create(): "os-sso made this one". */
    private const OWNED_FIELD = 'sso_owned';

    /**
     * True if the account logs in with a real local password -- i.e. a human-owned
     * account. A scrambled password (IdP-only), an empty one, or the classic unix
     * lock ("*" / "!...") is NOT usable, so such accounts are safe for SSO to bind.
     */
    public function hasUsableLocalPassword(\SimpleXMLElement $node): bool
    {
        if ((string)($node->scrambled_password ?? '') === '1') {
            return false;
        }
        $pw = (string)($node->password ?? '');
        return $pw !== '' && $pw !== '*' && ($pw[0] ?? '') !== '!';
    }

    /**
     * Create a local user node. No usable local password: the only way in is the IdP.
     *
     * @param array $attrs name (required), descr, email, comment, and any extra
     *                     scalar children to stamp (sso_subject, scim_ref, ...)
     */
    public function create(array $attrs): \SimpleXMLElement
    {
        $username = (string)($attrs['name'] ?? '');
        $this->assertValidUsername($username);

        $cnf = Config::getInstance()->object();
        $node = $cnf->system->addChild('user');
        $node->addChild('name', $this->xml($username));
        $node->addChild('descr', $this->xml((string)($attrs['descr'] ?? '') ?: $username));
        if (!empty($attrs['email'])) {
            $node->addChild('email', $this->xml((string)$attrs['email']));
        }
        $node->addChild('comment', $this->xml((string)($attrs['comment'] ?? 'Created by os-sso')));
        $node->addChild('scope', 'user');
        $node->addChild('disabled', empty($attrs['disabled']) ? '0' : '1');
        $node->addChild('password', '*');
        $node->addChild('scrambled_password', '1');
        // Ownership marker, independent of the optional binding stamps below: an
        // account provisioned over SCIM without an externalId, or from an identity
        // carrying no `sub`, has no stamp to speak of but is still ours.
        $node->addChild(self::OWNED_FIELD, '1');
        $node->addChild('uid', (string)$this->nextUid($cnf));
        foreach (['sso_subject', 'scim_ref'] as $stamp) {
            if (!empty($attrs[$stamp])) {
                $node->addChild($stamp, $this->xml((string)$attrs[$stamp]));
            }
        }
        return $node;
    }

    /** Set a scalar child, adding it when absent. Returns whether anything changed. */
    public function setField(\SimpleXMLElement $node, string $field, string $value): bool
    {
        if ((string)($node->{$field} ?? '') === $value) {
            return false;
        }
        unset($node->{$field});
        if ($value !== '') {
            $node->addChild($field, $this->xml($value));
        }
        return true;
    }

    /** Stamp an external identifier once; never overwrite an existing one. */
    public function stampOnce(\SimpleXMLElement $node, string $field, string $value): bool
    {
        if ($value === '' || (string)($node->{$field} ?? '') !== '') {
            return false;
        }
        $node->addChild($field, $this->xml($value));
        return true;
    }

    /** @return bool whether the flag changed */
    public function setDisabled(\SimpleXMLElement $node, bool $disabled): bool
    {
        $current = !empty((string)($node->disabled ?? ''));
        if ($current === $disabled) {
            return false;
        }
        return $this->setField($node, 'disabled', $disabled ? '1' : '0');
    }

    /**
     * Persist config.xml and tell the rest of the system about it.
     *
     * @param bool $syncAccount the account appeared or changed name, so the unix side
     *                          has to be reconciled ("auth sync user", which also drops
     *                          a local entry left behind under the old name); an
     *                          ordinary edit only needs "auth user changed"
     */
    public function persist(string $username, bool $syncAccount = false): void
    {
        Config::getInstance()->save();
        (new Backend())->configdpRun($syncAccount ? 'auth sync user' : 'auth user changed', [$username]);
        if ($syncAccount) {
            Config::getInstance()->forceReload();
        }
    }

    private function nextUid(\SimpleXMLElement $cnf): int
    {
        $next = (int)($cnf->system->nextuid ?? 2000);
        $cnf->system->nextuid = (string)($next + 1);
        return $next;
    }

    /**
     * A value safe to hand to SimpleXML::addChild().
     *
     * Escaping the markup characters is only half of it. SimpleXML writes what it is
     * given byte for byte, and config.xml is re-parsed on every load -- so a value
     * carrying a control character or a broken UTF-8 sequence produces a document
     * nothing can read afterwards, and OPNsense falls back to a backup config. Every
     * string that lands here comes from outside: a display name or an email out of an
     * ID token, a SCIM payload, an IdP subject. Display names in particular are
     * self-service at most directories, so this is reachable by any account the IdP
     * will authenticate.
     *
     * So: drop invalid UTF-8 first (a lone continuation byte is not "a character" the
     * regex below can even see), then everything XML 1.0 does not admit as a character
     * -- the C0 controls other than tab/LF/CR, the surrogate range, and the two
     * non-characters -- and only then escape.
     */
    private function xml(string $value): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            // Drop the offending bytes rather than let mbstring substitute its "?" --
            // a stamp we match on later must not gain characters it never had.
            $substitute = mb_substitute_character();
            mb_substitute_character('none');
            $value = (string)mb_convert_encoding($value, 'UTF-8', 'UTF-8');
            mb_substitute_character($substitute);
        }
        $clean = preg_replace(
            '/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u',
            '',
            $value
        );
        return htmlspecialchars($clean ?? '', ENT_XML1);
    }
}
