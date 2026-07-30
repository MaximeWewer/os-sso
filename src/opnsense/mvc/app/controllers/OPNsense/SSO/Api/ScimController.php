<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\SSO\RateLimiter;
use OPNsense\SSO\SiteUrl;
use OPNsense\SSO\SourceGate;
use OPNsense\SSO\Scim\ScimError;
use OPNsense\SSO\Scim\ScimGroups;
use OPNsense\SSO\Scim\ScimSchema;
use OPNsense\SSO\Scim\ScimUsers;

/**
 * SCIM 2.0 endpoint: the IdP pushes account lifecycle instead of os-sso inferring it
 * from a login. Base URL to register at the directory:
 *
 *     https://<firewall>/api/sso/scim
 *
 * so the client's own /Users, /Groups and /ServiceProviderConfig land on the actions
 * below (PHP method names are case-insensitive, which is what makes "/Users" reach
 * usersAction).
 *
 * This is an unauthenticated-by-the-WebGUI, write-capable API into the firewall's
 * account database, so three things gate it before any resource code runs, in this
 * order: the source address, the bearer token, and a rate limit. The token also
 * selects WHICH provider the request belongs to -- external ids are namespaced per
 * provider, and two directories may well use the same ones.
 *
 * What it deliberately will not do is in ScimUsers/ScimGroups: no privileged account
 * is ever touched, no local password account is taken over, DELETE means deactivate,
 * and a group carrying administrative privileges takes no membership from a directory.
 */
class ScimController extends ApiControllerBase
{
    /** Bearer + source gate replace the WebGUI session entirely. */
    public function doAuth()
    {
        return true;
    }

    /**
     * Pre-auth AND CSRF-exempt, like the other machine-facing endpoints. A SCIM
     * client is a server, not a browser: it carries no session and no CSRF token,
     * and it uses PUT/PATCH/DELETE, which the base gate would reject outright.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        return true;
    }

    /** GET /api/sso/scim/ServiceProviderConfig */
    public function serviceProviderConfigAction()
    {
        return $this->run(function () {
            $this->authenticate();
            return ScimSchema::serviceProviderConfig($this->baseUrl());
        });
    }

    /** GET /api/sso/scim/ResourceTypes */
    public function resourceTypesAction()
    {
        return $this->run(function () {
            $this->authenticate();
            return ScimSchema::resourceTypes($this->baseUrl());
        });
    }

    /** GET /api/sso/scim/Schemas */
    public function schemasAction()
    {
        return $this->run(function () {
            $this->authenticate();
            return ScimSchema::schemas($this->baseUrl());
        });
    }

    /** /api/sso/scim/Users[/<id>] -- GET, POST, PUT, PATCH, DELETE */
    public function usersAction($id = null)
    {
        return $this->run(function () use ($id) {
            $provider = $this->authenticate();
            $users = new ScimUsers($provider, $this->baseUrl());
            $id = (string)($id ?? '');

            switch ($this->method()) {
                case 'GET':
                    return $id === ''
                        ? $users->search($this->filter(), $this->startIndex(), $this->count())
                        : $users->get($id);
                case 'POST':
                    $this->requireCollection($id);
                    $this->response->setStatusCode(201, 'Created');
                    return $users->create($this->body());
                case 'PUT':
                    $this->requireResource($id);
                    return $users->replace($id, $this->body());
                case 'PATCH':
                    $this->requireResource($id);
                    return $users->patch($id, $this->operations());
                case 'DELETE':
                    $this->requireResource($id);
                    $users->deactivate($id);
                    $this->response->setStatusCode(204, 'No Content');
                    return null;
                default:
                    throw new ScimError(405, 'method not allowed on /Users');
            }
        });
    }

    /** /api/sso/scim/Groups[/<id>] -- GET and PATCH (membership only) */
    public function groupsAction($id = null)
    {
        return $this->run(function () use ($id) {
            $this->authenticate();
            $groups = new ScimGroups($this->baseUrl());
            $id = (string)($id ?? '');

            switch ($this->method()) {
                case 'GET':
                    return $id === ''
                        ? $groups->search($this->filter(), $this->startIndex(), $this->count())
                        : $groups->get($id);
                case 'PATCH':
                    $this->requireResource($id);
                    return $groups->patch($id, $this->operations());
                case 'POST':
                case 'PUT':
                case 'DELETE':
                    throw new ScimError(
                        403,
                        'groups are not created, replaced or deleted over SCIM; only their membership is'
                    );
                default:
                    throw new ScimError(405, 'method not allowed on /Groups');
            }
        });
    }

    /* ------------------------------------------------------------------ */

    /**
     * Run a resource handler and render whatever comes back the SCIM way: the right
     * content type, and errors as an Error resource with the status the client is
     * meant to act on rather than a generic 500.
     */
    private function run(callable $handler)
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        try {
            $result = $handler();
        } catch (ScimError $e) {
            syslog(LOG_NOTICE, 'os-sso scim: ' . $e->getMessage());
            $this->response->setStatusCode($e->status(), 'SCIM error');
            return $this->render($e->toResource());
        } catch (\Throwable $e) {
            // Detail to the log, a generic body to the caller -- the client is
            // authenticated, but it is still a machine on the other side of a token.
            syslog(LOG_ERR, 'os-sso scim: ' . $e->getMessage());
            $this->response->setStatusCode(500, 'Internal Server Error');
            return $this->render((new ScimError(500, 'the request could not be processed'))->toResource());
        }
        return $result === null ? '' : $this->render($result);
    }

    private function render(array $document): string
    {
        $this->response->setContentType('application/scim+json', 'UTF-8');
        return json_encode($document, JSON_UNESCAPED_SLASHES);
    }

    /** The auth connector whose token authenticated this request. */
    private $authenticated = null;

    /**
     * Source address, then bearer token, then rate limit.
     *
     * @return string the provider the presented token belongs to
     */
    private function authenticate(): string
    {
        $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        $token = $this->bearerToken();
        if ($token === '') {
            $this->response->setHeader('WWW-Authenticate', 'Bearer');
            throw new ScimError(401, 'a bearer token is required');
        }

        foreach ($this->scimProviders() as $name => $auth) {
            $expected = trim((string)($auth->ssoScimToken ?? ''));
            if ($expected === '' || !hash_equals($expected, $token)) {
                continue;
            }
            // Right token: now check it was presented from an agreed source. Doing it
            // in this order means an attacker probing from elsewhere cannot use the
            // response to tell a valid token from an invalid one.
            //
            // The allowlist is required, not advisory -- an empty one refuses everything
            // rather than allowing everything. This is a write API into the account
            // database whose entire authentication is one shared secret in config.xml,
            // so it gets the same fail-closed treatment as the JWT header: the source
            // restriction is what bounds who can even attempt to use the token.
            $trusted = (array)($auth->ssoScimTrusted ?? []);
            if (empty($trusted)) {
                syslog(LOG_WARNING, sprintf(
                    'os-sso scim: provider %s has no source allowlist, refusing the request -- '
                    . 'set "SCIM source IPs/CIDRs" on the authentication server',
                    $name
                ));
                break;
            }
            if (!SourceGate::allows($peer, $trusted)) {
                syslog(LOG_WARNING, sprintf(
                    'os-sso scim: valid token for provider %s presented from untrusted source %s',
                    $name,
                    preg_replace('/[^0-9a-fA-F.:]/', '', $peer)
                ));
                break;
            }
            RateLimiter::hit('scim', $peer, 600);
            $this->authenticated = $auth;
            return $name;
        }

        RateLimiter::hit('scim-denied', $peer, 20);
        $this->response->setHeader('WWW-Authenticate', 'Bearer');
        throw new ScimError(401, 'invalid credentials');
    }

    /**
     * SSO providers with SCIM switched on.
     *
     * @return array<string,object> provider name => auth connector
     */
    private function scimProviders(): array
    {
        $out = [];
        foreach ((Config::getInstance()->object()->system->authserver ?? []) as $server) {
            if (!in_array((string)$server->type, ['oidc', 'saml', 'jwt'], true)) {
                continue;
            }
            $name = (string)$server->name;
            $auth = (new AuthenticationFactory())->get($name);
            if ($auth !== null && !empty($auth->ssoScimEnabled)) {
                $out[$name] = $auth;
            }
        }
        return $out;
    }

    private function bearerToken(): string
    {
        $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        return stripos($header, 'Bearer ') === 0 ? trim(substr($header, 7)) : '';
    }

    /**
     * Base URL for the "location" of every resource we hand back.
     *
     * Built from the Base URL of the provider that authenticated, not of whichever SCIM
     * provider happens to be first in config.xml: with two directories registered on
     * different Base URLs, the location pointed at the other one, so a client following
     * it called an endpoint its token is not valid for.
     */
    private function baseUrl(): string
    {
        return ($this->authenticated !== null
            ? SiteUrl::forProvider($this->authenticated)
            : SiteUrl::detect()) . '/api/sso/scim';
    }

    private function method(): string
    {
        return strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    }

    private function requireResource(string $id): void
    {
        if ($id === '') {
            throw ScimError::badRequest('this method needs a resource id in the path');
        }
    }

    private function requireCollection(string $id): void
    {
        if ($id !== '') {
            throw ScimError::badRequest('POST goes to the collection, not to a resource');
        }
    }

    /** @return array the decoded request body */
    private function body(): array
    {
        $raw = (string)$this->request->getRawBody();
        if (trim($raw) === '') {
            throw ScimError::badRequest('empty request body');
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw ScimError::badRequest('request body is not valid JSON');
        }
        return $decoded;
    }

    /** @return array the Operations of a PatchOp document */
    private function operations(): array
    {
        $body = $this->body();
        $operations = $body['Operations'] ?? $body['operations'] ?? null;
        if (!is_array($operations) || empty($operations)) {
            throw ScimError::badRequest('a PATCH needs a non-empty Operations list', 'invalidSyntax');
        }
        return $operations;
    }

    private function filter(): string
    {
        return trim((string)($this->request->get('filter') ?? ''));
    }

    private function startIndex(): int
    {
        return max(1, (int)($this->request->get('startIndex') ?? 1));
    }

    private function count(): int
    {
        $count = $this->request->get('count');
        return $count === null || $count === '' ? ScimUsers::MAX_RESULTS : max(0, (int)$count);
    }
}
