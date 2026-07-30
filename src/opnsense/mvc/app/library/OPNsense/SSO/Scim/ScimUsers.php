<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

use OPNsense\Core\Config;
use OPNsense\SSO\ConfigLock;
use OPNsense\SSO\GroupMembers;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\SessionRegistry;

/**
 * The /Users half of the SCIM endpoint: the directory pushes account lifecycle here
 * instead of os-sso inferring it from a login.
 *
 * This is what closes the deprovisioning gap. Without SCIM, a revoked account stays
 * usable on the firewall until its owner happens to attempt a login -- the only
 * moment a login-driven plugin hears anything. With it, `active: false` arrives when
 * the directory says so, and the open sessions go with it.
 *
 * It is also a write API into the account database of a firewall, so the same three
 * rules as the login path apply, and for the same reasons:
 *   - a privileged account (system, uid 0, admins member) is never touched;
 *   - an account with a real local password is never taken over;
 *   - "delete" means disable. Removing a user that owns rules, certificates or API
 *     keys is not something a directory sync should be able to do by accident.
 */
final class ScimUsers
{
    public const MAX_RESULTS = 200;

    private LocalAccountWriter $accounts;
    private string $provider;
    private string $base;

    public function __construct(string $provider, string $base, ?LocalAccountWriter $accounts = null)
    {
        $this->provider = $provider;
        $this->base = $base;
        $this->accounts = $accounts ?? new LocalAccountWriter();
    }

    /* ---- reads ------------------------------------------------------- */

    public function get(string $id): array
    {
        return $this->toResource($this->requireNode($id));
    }

    /**
     * @param string $filter raw SCIM filter, only "<attr> eq \"value\"" is supported
     * @return array a ListResponse
     */
    public function search(string $filter, int $startIndex, int $count): array
    {
        $matches = [];
        foreach ($this->accounts->users() as $node) {
            if (!$this->isOurs($node)) {
                continue;
            }
            if ($filter === '' || $this->matches($node, $filter)) {
                $matches[] = $node;
            }
        }
        $total = count($matches);
        // count=0 means "just tell me how many" (RFC 7644 section 3.4.2.4), which is how
        // a client sizes a sync before walking it -- it must not come back with a row.
        $page = $count <= 0
            ? []
            : array_slice($matches, max(0, $startIndex - 1), min($count, self::MAX_RESULTS));
        return ScimSchema::listResponse(array_map([$this, 'toResource'], $page), $total, $startIndex);
    }

    /* ---- writes ------------------------------------------------------ */

    /**
     * Whether the last create() on THIS instance actually made an account, as opposed to
     * adopting one that already carried the userName. The caller answers 201 or 200
     * accordingly: reporting "Created" for a resource that was already there tells the
     * directory something untrue about its own state.
     */
    public function createdNew(): bool
    {
        return $this->createdNew;
    }

    private bool $createdNew = false;

    public function create(array $payload): array
    {
        return ConfigLock::with(function () use ($payload) {
            $userName = trim((string)($payload['userName'] ?? ''));
            if ($userName === '') {
                throw ScimError::badRequest('userName is required', 'invalidValue');
            }
            $this->accounts->assertValidUsername($userName);

            $externalId = trim((string)($payload['externalId'] ?? ''));
            $ref = $this->ref($externalId);

            // Already provisioned? SCIM says 409, and a client that gets it will PATCH
            // instead of retrying forever.
            if ($ref !== '' && $this->accounts->findByStamp('scim_ref', $ref) !== null) {
                throw ScimError::conflict('a user with this externalId already exists');
            }
            $existing = $this->accounts->findByName($userName);
            if ($existing !== null) {
                $this->createdNew = false;
                // An account with that name is already here. Adopt it only if os-sso
                // may -- otherwise this is someone's real local account.
                $this->assertMayTouch($existing);
                $changed = $this->accounts->stampOnce($existing, 'scim_ref', $ref);
                $changed = $this->applyAttributes($existing, $payload) || $changed;
                // A POST states the whole resource, so its "active" applies here as much
                // as it does on a fresh create -- and re-creating a user is how several
                // directories (Okta among them) reactivate one they deactivated earlier.
                // Ignoring it answered 200 for an account that stayed disabled, which
                // tells the directory something untrue and locks the person out with
                // nothing to see on either side.
                $changed = $this->setActive($existing, $this->activeFlag($payload, true)) || $changed;
                if ($changed) {
                    $this->touch($existing);
                    $this->accounts->persist($userName);
                }
                return $this->toResource($existing);
            }

            $this->createdNew = true;
            $node = $this->accounts->create([
                'name' => $userName,
                'descr' => $this->displayName($payload),
                'email' => $this->email($payload),
                'comment' => 'Provisioned over SCIM (' . $this->provider . ')',
                'scim_ref' => $ref,
                'disabled' => !$this->activeFlag($payload, true),
            ]);
            $this->touch($node, true);
            $this->accounts->persist($userName, true);
            return $this->toResource($node);
        });
    }

    /** PUT: the client sends the whole resource, we apply what we can hold. */
    public function replace(string $id, array $payload): array
    {
        return ConfigLock::with(function () use ($id, $payload) {
            $node = $this->requireNode($id);
            $this->assertMayTouch($node);
            // A PUT states the whole resource, userName included: ignoring a renamed one
            // left the directory and the firewall disagreeing about who this account is,
            // and the login path falls back to the username when the subject does not
            // match, so that disagreement is not cosmetic.
            $renamed = $this->rename($node, (string)($payload['userName'] ?? ''));
            $changed = $this->applyAttributes($node, $payload) || $renamed;
            $changed = $this->setActive($node, $this->activeFlag($payload, true)) || $changed;
            if ($changed) {
                $this->touch($node);
                $this->accounts->persist((string)$node->name, $renamed);
            }
            return $this->toResource($node);
        });
    }

    /**
     * PATCH: a list of add/replace/remove operations (RFC 7644 section 3.5.2).
     *
     * Only the paths an account here actually has are honoured. An unknown path is
     * ignored rather than refused: directories send attributes we simply do not
     * store (locale, timezone, name.givenName...), and failing the whole operation
     * because of one of them would stall the sync.
     */
    public function patch(string $id, array $operations): array
    {
        return ConfigLock::with(function () use ($id, $operations) {
            $node = $this->requireNode($id);
            $this->assertMayTouch($node);
            $changed = false;
            $renamed = false;

            foreach ($operations as $operation) {
                $op = strtolower((string)($operation['op'] ?? ''));
                $path = strtolower(trim((string)($operation['path'] ?? '')));
                $value = $operation['value'] ?? null;

                if ($op === 'remove' && $path === 'active') {
                    $changed = $this->setActive($node, false) || $changed;
                    continue;
                }
                if (!in_array($op, ['add', 'replace'], true)) {
                    continue;
                }
                // No path: the value is a map of attributes to apply.
                if ($path === '' && is_array($value)) {
                    $changed = $this->applyAttributes($node, $value) || $changed;
                    if (array_key_exists('active', $value)) {
                        $changed = $this->setActive($node, $this->truthy($value['active'])) || $changed;
                    }
                    continue;
                }
                switch ($path) {
                    case 'active':
                        $changed = $this->setActive($node, $this->truthy($value)) || $changed;
                        break;
                    case 'username':
                        $renamed = $this->rename($node, (string)$value) || $renamed;
                        $changed = $renamed || $changed;
                        break;
                    case 'displayname':
                        $changed = $this->accounts->setField($node, 'descr', (string)$value) || $changed;
                        break;
                    case 'externalid':
                        $changed = $this->accounts->stampOnce($node, 'scim_ref', $this->ref((string)$value)) || $changed;
                        break;
                    case 'emails':
                    case 'emails[primary eq true].value':
                        $changed = $this->accounts->setField($node, 'email', $this->emailFromValue($value)) || $changed;
                        break;
                }
            }

            if ($changed) {
                $this->touch($node);
                // A rename needs the account reconciled, not just announced: core's
                // sync drops whatever local entry the old name left behind.
                $this->accounts->persist((string)$node->name, $renamed);
            }
            return $this->toResource($node);
        });
    }

    /**
     * DELETE. Deliberately a deactivation: on a firewall an account can own firewall
     * rules, certificates and API keys, and a directory sync must not be able to take
     * those with it. The account stops working immediately, which is what the client
     * actually asked for.
     */
    public function deactivate(string $id): void
    {
        ConfigLock::with(function () use ($id) {
            $node = $this->requireNode($id);
            $this->assertMayTouch($node);
            if ($this->setActive($node, false)) {
                $this->touch($node);
                $this->accounts->persist((string)$node->name);
            }
            return true;
        });
    }

    /* ---- mapping ----------------------------------------------------- */

    public function toResource(\SimpleXMLElement $node): array
    {
        $id = (string)($node->uid ?? '');
        $meta = [
            'resourceType' => 'User',
            'location' => $this->base . '/Users/' . rawurlencode($id),
        ];
        // config.xml keeps no per-account timestamps, so os-sso keeps its own on the
        // accounts it owns. A client that reconciles by lastModified was told nothing
        // at all before, and had to re-read every resource on every run.
        foreach (['created' => 'scim_created', 'lastModified' => 'scim_modified'] as $key => $field) {
            $stamp = (int)((string)($node->{$field} ?? ''));
            if ($stamp > 0) {
                $meta[$key] = gmdate('Y-m-d\TH:i:s\Z', $stamp);
            }
        }
        $out = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $id,
            'userName' => (string)$node->name,
            'displayName' => (string)($node->descr ?? ''),
            'active' => empty((string)($node->disabled ?? '')),
            'groups' => $this->groupsOf($node),
            'meta' => $meta,
        ];
        $externalId = $this->externalIdOf($node);
        if ($externalId !== '') {
            $out['externalId'] = $externalId;
        }
        if ((string)($node->email ?? '') !== '') {
            $out['emails'] = [['value' => (string)$node->email, 'primary' => true]];
        }
        // The entity tag is over the resource we just built, so it changes exactly when
        // something a client can see changes -- which is what makes If-Match mean
        // "nobody edited this behind me".
        $out['meta']['version'] = self::version($out);
        return $out;
    }

    /** The weak entity tag of a rendered resource. */
    public static function version(array $resource): string
    {
        unset($resource['meta']['version']);
        return 'W/"' . substr(hash('sha256', (string)json_encode($resource)), 0, 32) . '"';
    }

    /**
     * The groups this account is in, as SCIM expects them on a User: read-only, and
     * only the ones os-sso would manage. Membership is changed through /Groups.
     *
     * @return array<int,array<string,string>>
     */
    private function groupsOf(\SimpleXMLElement $node): array
    {
        $uid = (string)($node->uid ?? '');
        if ($uid === '') {
            return [];
        }
        $out = [];
        foreach ((Config::getInstance()->object()->system->group ?? []) as $group) {
            if (!GroupMembers::contains($group, $uid)) {
                continue;
            }
            $gid = (string)($group->gid ?? '');
            $out[] = [
                'value' => $gid,
                'display' => (string)$group->name,
                '$ref' => $this->base . '/Groups/' . rawurlencode($gid),
                'type' => 'direct',
            ];
        }
        return $out;
    }

    /* ---- helpers ----------------------------------------------------- */

    /**
     * The account behind a resource id, or 404.
     *
     * isOurs() is part of the lookup, not a separate check the write paths remember to
     * make: uids are sequential from nextuid, so without it a token holder walks
     * /Users/0, /Users/2000, ... and reads back the userName, description, email and
     * enabled state of every local account on the firewall -- root included. Search
     * already filtered; a direct id must too, and it answers 404 rather than 403 so the
     * response says nothing about whether the account exists.
     */
    private function requireNode(string $id): \SimpleXMLElement
    {
        $node = $this->accounts->findByUid($id);
        if ($node === null || !$this->isOurs($node)) {
            throw ScimError::notFound('user');
        }
        return $node;
    }

    /**
     * Only accounts os-sso owns are visible over SCIM. A directory has no business
     * listing (or being told about) the firewall's own local accounts.
     */
    private function isOurs(\SimpleXMLElement $node): bool
    {
        return $this->accounts->isSsoManaged($node);
    }

    /**
     * Refuse an account that belongs to another provider and not to us.
     *
     * This is the authorization boundary between directories: enabling SCIM on one
     * authentication server must not hand it the accounts of another. The bearer token
     * says which provider a request belongs to, and this is what makes that mean
     * something on writes as well as on reads.
     *
     * Both kinds of binding answer the question -- a scim_ref from a directory, an
     * sso_subject from a login flow -- and an account may legitimately carry several,
     * since one directory is often fronted by more than one protocol. So the test is not
     * "is any binding foreign" but "is every binding foreign": if this provider is among
     * them, the account is ours to manage too.
     */
    private function assertNotClaimedElsewhere(\SimpleXMLElement $node): void
    {
        $prefix = $this->provider . '|';
        $foreign = [];
        foreach (['scim_ref', 'sso_subject'] as $field) {
            foreach ($node->{$field} as $binding) {
                $ref = trim((string)$binding);
                if ($ref === '') {
                    continue;
                }
                if (str_starts_with($ref, $prefix)) {
                    return; // one of them is ours
                }
                $foreign[explode('|', $ref)[0]] = true;
            }
        }
        if ($foreign !== []) {
            throw ScimError::conflict(sprintf(
                "'%s' belongs to another provider (%s)",
                (string)$node->name,
                implode(', ', array_keys($foreign))
            ));
        }
    }

    private function assertMayTouch(\SimpleXMLElement $node): void
    {
        if ($this->accounts->isPrivileged($node)) {
            throw new ScimError(403, sprintf(
                "refusing to modify privileged account '%s' over SCIM",
                (string)$node->name
            ));
        }
        if (!$this->accounts->isSsoManaged($node) && $this->accounts->hasUsableLocalPassword($node)) {
            throw new ScimError(403, sprintf(
                "'%s' is a local account with its own password; SCIM does not take those over",
                (string)$node->name
            ));
        }
        // Every write goes through here, so the cross-provider boundary does too --
        // replace(), patch() and deactivate() used to skip it entirely.
        $this->assertNotClaimedElsewhere($node);
    }

    /**
     * Record when this account was made and when it last changed.
     *
     * config.xml has no timestamps of its own, so these are ours, kept only on the
     * accounts os-sso owns and only for what SCIM reports. Called on every write that
     * actually changed something, which is also when a new entity tag is due.
     */
    private function touch(\SimpleXMLElement $node, bool $created = false): void
    {
        $now = (string)time();
        if ($created) {
            $this->accounts->stampOnce($node, 'scim_created', $now);
        }
        $this->accounts->setField($node, 'scim_modified', $now);
    }

    /** Namespaced by provider: two directories may well use the same external ids. */
    private function ref(string $externalId): string
    {
        return $externalId === '' ? '' : $this->provider . '|' . $externalId;
    }

    private function externalIdOf(\SimpleXMLElement $node): string
    {
        $ref = (string)($node->scim_ref ?? '');
        $prefix = $this->provider . '|';
        return str_starts_with($ref, $prefix) ? substr($ref, strlen($prefix)) : '';
    }

    private function applyAttributes(\SimpleXMLElement $node, array $payload): bool
    {
        $changed = false;
        $display = $this->displayName($payload);
        if ($display !== '') {
            $changed = $this->accounts->setField($node, 'descr', $display) || $changed;
        }
        $email = $this->email($payload);
        if ($email !== '') {
            $changed = $this->accounts->setField($node, 'email', $email) || $changed;
        }
        if (!empty($payload['externalId'])) {
            $changed = $this->accounts->stampOnce($node, 'scim_ref', $this->ref((string)$payload['externalId'])) || $changed;
        }
        return $changed;
    }

    /**
     * Renaming is allowed but never onto an account that already exists: the username
     * is what the login path falls back to when the subject does not match, so a
     * collision here would hand one person another person's account.
     */
    private function rename(\SimpleXMLElement $node, string $userName): bool
    {
        $userName = trim($userName);
        if ($userName === '' || $userName === (string)$node->name) {
            return false;
        }
        $this->accounts->assertValidUsername($userName);
        if ($this->accounts->findByName($userName) !== null) {
            throw ScimError::conflict("a user named '" . $userName . "' already exists");
        }
        return $this->accounts->setField($node, 'name', $userName);
    }

    /** Deactivating also ends the sessions -- that is the whole point of SCIM here. */
    private function setActive(\SimpleXMLElement $node, bool $active): bool
    {
        $changed = $this->accounts->setDisabled($node, !$active);
        if ($changed && !$active) {
            $username = (string)$node->name;
            $ended = SessionRegistry::destroyWhere(
                fn(array $entry) => (string)($entry['username'] ?? '') === $username
            );
            syslog(LOG_NOTICE, sprintf(
                'os-sso scim: deactivated %s, ended %d session(s)',
                $username,
                $ended
            ));
        }
        return $changed;
    }

    private function displayName(array $payload): string
    {
        if (!empty($payload['displayName'])) {
            return (string)$payload['displayName'];
        }
        if (!empty($payload['name']['formatted'])) {
            return (string)$payload['name']['formatted'];
        }
        $given = (string)($payload['name']['givenName'] ?? '');
        $family = (string)($payload['name']['familyName'] ?? '');
        return trim($given . ' ' . $family);
    }

    private function email(array $payload): string
    {
        foreach ((array)($payload['emails'] ?? []) as $entry) {
            if (is_array($entry) && !empty($entry['primary']) && !empty($entry['value'])) {
                return (string)$entry['value'];
            }
        }
        foreach ((array)($payload['emails'] ?? []) as $entry) {
            if (is_array($entry) && !empty($entry['value'])) {
                return (string)$entry['value'];
            }
        }
        return '';
    }

    private function emailFromValue($value): string
    {
        if (is_string($value)) {
            return $value;
        }
        return is_array($value) ? $this->email(['emails' => is_array($value[0] ?? null) ? $value : [$value]]) : '';
    }

    private function activeFlag(array $payload, bool $default): bool
    {
        return array_key_exists('active', $payload) ? $this->truthy($payload['active']) : $default;
    }

    private function truthy($value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? (bool)$value;
    }

    /**
     * Only "<attr> eq \"value\"" on the attributes we can actually index. Anything
     * else is refused rather than silently answered with the wrong set -- a client
     * that believes it filtered, and did not, would act on every user we returned.
     */
    private function matches(\SimpleXMLElement $node, string $filter): bool
    {
        $predicate = ScimFilter::compile($filter, function (string $attribute) use ($node) {
            switch ($attribute) {
                case 'username':
                    return (string)$node->name;
                case 'externalid':
                    return $this->externalIdOf($node);
                case 'id':
                    return (string)($node->uid ?? '');
                case 'displayname':
                    return (string)($node->descr ?? '');
                case 'emails.value':
                case 'emails':
                    return (string)($node->email ?? '');
                case 'active':
                    return empty((string)($node->disabled ?? '')) ? 'true' : 'false';
                default:
                    return null; // not indexable here: the filter is refused, not guessed
            }
        });
        return $predicate();
    }
}
