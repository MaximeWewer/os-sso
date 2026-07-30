<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\SSO\AccessPolicy;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\SessionEstablisher;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\VpnAuthorizer;
use OPNsense\SSO\CaptivePortalAuthorizer;
use OPNsense\SSO\FaviconProxy;
use OPNsense\SSO\HtmlPage;
use OPNsense\SSO\LogoutGuard;
use OPNsense\SSO\NavigationGuard;
use OPNsense\SSO\RateLimiter;
use OPNsense\SSO\ReturnUrl;
use OPNsense\SSO\SamlMetadata;
use OPNsense\SSO\ServiceScope;
use OPNsense\SSO\SiteUrl;
use OPNsense\SSO\Protocol\SamlProtocol;

/**
 * SAML SP endpoints: login (AuthnRequest), acs (assertion consumer), metadata, slo.
 * Pre-auth via doAuth()=>true; security rests on the assertion signature and the
 * single-use InResponseTo check inside SamlProtocol.
 */
class SamlController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    /**
     * The SAML endpoints are intentionally pre-auth AND CSRF-exempt. The ACS is a
     * cross-site HTTP-POST from the IdP that cannot carry the WebGUI CSRF token;
     * its integrity is guaranteed instead by the assertion's XML-DSig signature
     * and the single-use InResponseTo check in SamlProtocol. Bypass the base
     * auth/CSRF gate (which would 403 the IdP POST) for this controller.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        return true;
    }

    /** GET /api/sso/saml/login?provider=<name> */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        // No session needed here: SamlProtocol persists in-flight state server-side
        // keyed by the AuthnRequest id (the assertion POST is cross-site, so the
        // SameSite=Lax session cookie would not survive the round-trip anyway).
        try {
            // Pre-auth endpoint: cap how often one source can start a ceremony (each
            // one writes an in-flight state file). Generous on purpose: one source is
            // often a whole NATed office logging in at the same time.
            NavigationGuard::assertNavigation();
            RateLimiter::hit('saml-login', $this->clientIp(), 60);
            $provider = $this->request->get('provider');
            $auth = $this->authServer($provider);
            // OpenVPN deferred web-auth: carry the one-time VPN session id in the
            // server-side state so the ACS can authorize the tunnel. Captive Portal:
            // carry the zone id + the client's original destination likewise.
            $vpn = (string)$this->request->get('vpn');
            $cp = (string)($this->request->get('cp') ?? '');
            // Which of the three doors this login is for, and whether this provider was
            // offered for it. Checked again at the ACS, which is where it binds.
            ServiceScope::assert((array)$auth->ssoServices, self::serviceFor($vpn, $cp), (string)$provider);
            $protocol = $this->protocolFor($provider, $auth);
            // Validated here, at the door: the portal page filters it too, but a
            // crafted login link never goes through the portal page.
            $cpurl = CaptivePortalAuthorizer::sanitizeRedirect((string)($this->request->get('cpurl') ?? ''));
            $begin = $protocol->beginLogin((string)($this->request->get('url') ?? '/'), $vpn, $cp, $cpurl);
            if ($begin['binding'] === 'post') {
                // HTTP-POST binding: the request travels in a self-submitting form, so
                // this is the one page of ours that needs its script and a form-action
                // pointing somewhere other than here.
                $this->html(HtmlPage::originOf((string)$begin['url']) ?: "'none'", true);
                return $begin['html'];
            }
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        $this->response->redirect($begin['url'], true);
        return 'Redirecting to identity provider...';
    }

    /** POST /api/sso/saml/acs */
    public function acsAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        try {
            // Pre-auth endpoint: XML parsing and signature verification are not free.
            RateLimiter::hit('saml-acs', $this->clientIp(), 60);
            // Recover in-flight state via the response InResponseTo (single use).
            $inResponseTo = SamlProtocol::peekInResponseTo($_POST);
            $state = SamlProtocol::consumeState($inResponseTo);
            if ($state === null) {
                // No state: either a replay, or an IdP-initiated response -- which has
                // no InResponseTo at all and is only accepted when the provider named
                // on our own per-provider ACS URL opted into it.
                $provider = $this->knownSamlProvider((string)($this->request->get('provider') ?? ''));
                if ($inResponseTo !== '' || $provider === '' || empty($this->authServer($provider)->ssoAllowIdpInitiated)) {
                    throw new \RuntimeException('unknown or replayed SAML response');
                }
                $inResponseTo = '';
                $state = ['provider' => $provider, 'return' => '/'];
            }
            $provider = $state['provider'];
            $auth = $this->authServer($provider);
            $protocol = $this->protocolFor($provider, $auth);

            $identity = $protocol->handleCallback($_POST, $inResponseTo, $state);
            $identity->authServer = (string)$provider;

            // The door this assertion is about to open has to be one this provider was
            // offered for. The state was written by our own /login, but an operator can
            // narrow a provider between the two.
            ServiceScope::assert(
                (array)$auth->ssoServices,
                self::serviceFor((string)($state['vpn'] ?? ''), (string)($state['cp'] ?? '')),
                (string)$provider
            );

            // Provider-level door policy, before ANY path below (captive portal, VPN
            // or WebGUI) and before any local account is touched or created.
            AccessPolicy::assert((array)$auth->ssoRequiredGroups, $identity, (bool)$auth->ssoDeprovision);

            // Captive Portal path: authorize the captive client's IP in its zone
            // straight from the verified assertion (no WebGUI session, no local account
            // required -- but a disabled one is still refused), before any mapping.
            $cp = (string)($state['cp'] ?? '');
            if ($cp !== '') {
                $cpRes = CaptivePortalAuthorizer::authorize(
                    $cp,
                    (string)$provider,
                    $identity,
                    (string)($_SERVER['REMOTE_ADDR'] ?? '')
                );
                // This page bounces off-site; keep our own URL out of the Referer.
                $this->html("'self'", false, ['Referrer-Policy' => 'no-referrer']);
                return CaptivePortalAuthorizer::donePage($cpRes['username'], (string)($state['cpurl'] ?? ''));
            }

            $username = (new IdentityMapper(new GroupMapper(
                GroupMapper::parseMap((string)$auth->ssoGroupMap),
                (bool)$auth->ssoGroupSync
            )))->resolve(
                $identity,
                (bool)$auth->ssoCreateUsers,
                (array)$auth->ssoDefaultGroups
            );

            // OpenVPN deferred web-auth path: authorize the tunnel, no WebGUI session.
            $vpn = (string)($state['vpn'] ?? '');
            if ($vpn !== '') {
                VpnAuthorizer::authorize($vpn, $username, (string)($_SERVER['REMOTE_ADDR'] ?? ''));
                $this->html();
                return VpnAuthorizer::donePage($username);
            }

            $this->startSession();
            (new SessionEstablisher())->establish($username, (string)$provider, [
                // The RESOLVED EntityID: with a metadata-only provider the form field is
                // empty, and an empty issuer makes the registry unmatchable at logout.
                'issuer' => $protocol->getIdpEntityId(),
                'sub' => $identity->subject,
                'sid' => $protocol->getLastSessionIndex(),
                'lifetime' => (int)$auth->ssoSessionLifetime,
            ]);
            // Keep what Single Logout needs, in the fresh session.
            $_SESSION['sso_logout'] = [
                'type' => 'saml',
                'provider' => (string)$provider,
                'nameid' => $protocol->getLastNameId(),
                'sessionindex' => $protocol->getLastSessionIndex(),
                'nameid_format' => $protocol->getLastNameIdFormat(),
            ];
            session_write_close();
            $returnUrl = $this->landing((string)($state['return'] ?? '/'), $auth);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        $this->response->redirect($returnUrl, true);
        return 'Login successful, redirecting...';
    }

    /** GET /api/sso/saml/icon?provider=<name> -- proxied IdP favicon. */
    public function iconAction()
    {
        try {
            // Pre-auth, and on a cache miss it reaches out to the IdP (DNS plus up to
            // two HTTPS fetches). Generous, because one login page pulls one icon per
            // configured provider; a failed hit just renders as a missing icon.
            RateLimiter::hit('sso-icon', $this->clientIp(), 60);
            $auth = $this->authServer($this->request->get('provider'));
            // Via idpSettings so a metadata-only provider (nothing typed in the form)
            // still has a host to take the icon from; both lookups are cached.
            $idp = $this->idpSettings($auth);
            $icon = FaviconProxy::fetch($idp['sso_url'] ?: $idp['entity_id']);
        } catch (\Throwable $e) {
            $this->response->setStatusCode(404, 'Not Found');
            return '';
        }
        foreach (FaviconProxy::headers($icon['type']) as $header => $value) {
            $this->response->setHeader($header, $value);
        }
        return $icon['data'];
    }

    /** GET /api/sso/saml/metadata?provider=<name> */
    public function metadataAction()
    {
        try {
            // Pre-auth, and building the document may pull the IdP metadata document to
            // fill in whatever the operator left empty. An IdP reads this rarely.
            RateLimiter::hit('saml-metadata', $this->clientIp(), 20);
            $protocol = $this->protocolFor($this->request->get('provider'));
            $this->response->setHeader('Content-Type', 'application/samlmetadata+xml');
            return $protocol->metadata();
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
    }

    /**
     * GET /api/sso/saml/slo -- Single Logout.
     *   - no SAML param  : SP-initiated (build LogoutRequest, redirect to IdP)
     *   - SAMLResponse   : the IdP's answer to our LogoutRequest (validate, finish)
     *   - SAMLRequest    : IdP-initiated logout (process, answer with LogoutResponse)
     */
    public function sloAction()
    {
        $this->startSession();

        // Incoming SLO message (response to ours, or IdP-initiated request).
        if (!empty($_GET['SAMLResponse']) || !empty($_GET['SAMLRequest'])) {
            $redirect = '/';
            try {
                // Pre-auth endpoint, like login and acs: inflating and parsing an
                // attacker-supplied message then verifying a signature is not free.
                RateLimiter::hit('saml-slo', $this->clientIp(), 20);
                // Prefer the provider whose IdP EntityID matches the message Issuer
                // (correct for IdP-initiated SLO with several SAML providers), then
                // the one named on our own per-provider SLO endpoint, then the
                // session, then the first configured SAML provider. Only a selector:
                // whichever we land on, the message is validated against ITS cert.
                $provider = $this->samlProviderByIssuer(SamlProtocol::peekSloIssuer($_GET))
                    ?: ($this->knownSamlProvider((string)($_GET['provider'] ?? ''))
                        ?: (($_SESSION['sso_logout']['provider'] ?? '') ?: $this->firstSamlProvider()));
                $protocol = $this->protocolFor($provider);
                // Single use, and dropped before validation rather than after: the
                // session is destroyed further down on the happy path, but a
                // LogoutResponse that fails to validate returns early, and the id it
                // was matched against must not still be sitting there for the next try.
                $reqId = (string)($_SESSION['sso_saml_logout_reqid'] ?? '');
                unset($_SESSION['sso_saml_logout_reqid']);
                $slo = $protocol->processSlo($reqId);
                $redirect = $slo['redirect'] ?: '/';
                // Front-channel SLO only logs out the browser that followed the
                // redirect. End the subject's other sessions on this firewall too --
                // otherwise "logged out at the IdP" leaves the second tab, or the
                // session opened from another machine, working until it idles out.
                $this->endSessionsFor($protocol, $slo['subject']);
                // ... and end this browser's own session, unless the message is about
                // somebody else. An IdP-initiated LogoutRequest names its subject, and
                // it arrives in whatever browser followed the redirect: logging that
                // browser out when it belongs to a different user is somebody else's
                // logout landing on them. The sessions that really are the subject's
                // were ended above, by their recorded binding rather than by who
                // happens to be holding the cookie.
                $mine = $this->currentSessionIsFor((string)($slo['subject']['name_id'] ?? ''));
            } catch (\Throwable $e) {
                return $this->fail($e);
            }
            if ($mine) {
                SessionEstablisher::destroyCurrent();
            }
            $this->response->redirect($redirect, true);
            return 'Logged out.';
        }

        // SP-initiated logout. (Only this branch is guarded: the branch above is an
        // IdP message, cross-site by design and validated by its signature.)
        if (!LogoutGuard::allow()) {
            $page = LogoutGuard::confirm('/api/sso/logout');
            session_write_close();
            $this->html();
            return $page;
        }
        $logout = $_SESSION['sso_logout'] ?? null;
        $url = '';
        try {
            if (is_array($logout) && ($logout['type'] ?? '') === 'saml' && !empty($logout['provider'])) {
                $auth = $this->authServer($logout['provider']);
                $protocol = $this->protocolFor($logout['provider'], $auth);
                $r = $protocol->buildLogoutRequest(
                    $this->baseUrlFor($auth) . '/',
                    (string)($logout['nameid'] ?? ''),
                    (string)($logout['sessionindex'] ?? ''),
                    (string)($logout['nameid_format'] ?? '')
                );
                $url = $r['url'];
                if ($url !== '') {
                    // Keep the request id + session for the round-trip, but drop the
                    // local login now.
                    $_SESSION['sso_saml_logout_reqid'] = $r['request_id'];
                    unset($_SESSION['Username']);
                    session_write_close();
                    $this->response->redirect($url, true);
                    return 'Logging out...';
                }
            }
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        // No IdP SLO configured: local logout only.
        SessionEstablisher::destroyCurrent();
        $this->response->redirect('/', true);
        return 'Logged out.';
    }

    /* ------------------------------------------------------------------ */

    /**
     * End every recorded session belonging to the subject an SLO message named.
     *
     * Scoped to the issuer that vouched for them, so one IdP can never log users out of
     * another's sessions. With SessionIndexes we end exactly those; with none, the
     * LogoutRequest is asking for the whole subject, which is what an administrator
     * disabling an account expects.
     *
     * @param array{name_id:string,session_indexes:string[]} $subject
     */
    private function endSessionsFor(SamlProtocol $protocol, array $subject): void
    {
        $nameId = (string)($subject['name_id'] ?? '');
        if ($nameId === '') {
            return;
        }
        $issuer = $protocol->getIdpEntityId();
        $indexes = $subject['session_indexes'] ?: [''];
        $ended = 0;
        foreach ($indexes as $index) {
            $ended += SessionRegistry::destroyForSubject($issuer, $nameId, (string)$index);
        }
        if ($ended > 0) {
            syslog(LOG_NOTICE, sprintf('os-sso saml: single logout ended %d session(s)', $ended));
        }
    }


    /**
     * Is the session in this browser the one the SLO message is about?
     *
     * A LogoutResponse names nobody -- it answers a request we made from this very
     * session -- so an unnamed subject means yes. A LogoutRequest does name one, and
     * then the answer is whether it is the NameID this session logged in with.
     */
    private function currentSessionIsFor(string $nameId): bool
    {
        if ($nameId === '') {
            return true;
        }
        $session = $_SESSION['sso_logout'] ?? null;
        $mine = is_array($session) ? (string)($session['nameid'] ?? '') : '';
        // No SAML session here at all: nothing of ours to keep, and destroying an
        // empty session is what the previous behaviour did anyway.
        return $mine === '' || hash_equals($mine, $nameId);
    }

    /** First configured SAML auth server name (for IdP-initiated SLO without a session). */
    private function firstSamlProvider(): string
    {
        foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver as $as) {
            if ((string)$as->type === 'saml') {
                return (string)$as->name;
            }
        }
        throw new \RuntimeException('no SAML provider configured');
    }

    /** $name if it is a configured SAML auth server, '' otherwise. */
    private function knownSamlProvider(string $name): string
    {
        if ($name === '') {
            return '';
        }
        foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver as $as) {
            if ((string)$as->type === 'saml' && (string)$as->name === $name) {
                return $name;
            }
        }
        return '';
    }

    /** SAML auth server whose IdP EntityID matches $issuer, or '' if none. */
    private function samlProviderByIssuer(string $issuer): string
    {
        if ($issuer === '') {
            return '';
        }
        foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver as $as) {
            if ((string)$as->type === 'saml' && (string)$as->sso_idp_entity_id === $issuer) {
                return (string)$as->name;
            }
        }
        return '';
    }

    /**
     * The IdP half of the trust relationship: whatever the operator typed in the
     * form, with anything left empty filled in from the IdP metadata document when
     * one is configured. Typed values win -- an operator pinning a certificate by
     * hand must not have it silently replaced by a fetched document.
     *
     * @return array{entity_id:string,sso_url:string,slo_url:string,x509:string,x509_signing:string[]}
     */
    private function idpSettings($auth): array
    {
        $idp = [
            'entity_id' => trim((string)$auth->ssoIdpEntityId),
            'sso_url' => trim((string)$auth->ssoIdpSsoUrl),
            'slo_url' => trim((string)$auth->ssoIdpSloUrl),
            'x509' => trim((string)$auth->ssoIdpX509),
            'x509_signing' => [],
        ];
        $url = trim((string)($auth->ssoIdpMetadataUrl ?? ''));
        if ($url !== '') {
            $meta = SamlMetadata::fetch($url, $idp['entity_id']);
            foreach (['entity_id', 'sso_url', 'slo_url', 'x509'] as $key) {
                if ($idp[$key] === '') {
                    $idp[$key] = (string)$meta[$key];
                }
            }
            // Only take the multi-cert list when the operator pinned no certificate:
            // it is what lets an IdP key rotation land without an edit here.
            if (trim((string)$auth->ssoIdpX509) === '') {
                $idp['x509_signing'] = $meta['x509_signing'];
            }
        }
        if ($idp['entity_id'] === '' || $idp['sso_url'] === '' || ($idp['x509'] === '' && empty($idp['x509_signing']))) {
            throw new \RuntimeException(
                'SAML provider is incomplete: set an IdP metadata URL, or fill the ' .
                'IdP EntityID, SSO URL and x509 certificate by hand'
            );
        }
        return $idp;
    }

    private function protocolFor($provider, $auth = null): SamlProtocol
    {
        $auth = $auth ?? $this->authServer($provider);
        $base = $this->baseUrlFor($auth);
        // One EntityID/ACS/SLO per provider. Sharing them across several SAML servers
        // would give every IdP the same SP identity: the Audience restriction would no
        // longer say WHICH trust relationship an assertion was minted for, and the SLO
        // endpoint could not tell whose logout it is answering.
        $suffix = '?provider=' . rawurlencode((string)$provider);
        $idp = $this->idpSettings($auth);
        return new SamlProtocol([
            'provider_name' => (string)$provider,
            'base_url' => $base,
            'endpoint_suffix' => $suffix,
            'sp_entity_id' => $base . '/api/sso/saml/metadata' . $suffix,
            'acs_url' => $base . '/api/sso/saml/acs' . $suffix,
            'idp_entity_id' => $idp['entity_id'],
            'idp_sso_url' => $idp['sso_url'],
            // Default the SLO endpoint to the SSO URL (Keycloak/Authentik serve both
            // at /protocol/saml) when neither the form nor the metadata names one.
            'idp_slo_url' => $idp['slo_url'] ?: $idp['sso_url'],
            'idp_x509' => $idp['x509'],
            'idp_x509_signing' => $idp['x509_signing'],
            'sp_cert' => $auth->ssoSpCert,
            'sp_key' => $auth->ssoSpKey,
            'name_id_format' => $auth->ssoNameIdFormat,
            'groups_attribute' => $auth->ssoGroupsAttribute,
            'username_attribute' => $auth->ssoUsernameAttribute,
            'email_attribute' => $auth->ssoEmailAttribute,
            'display_name_attribute' => $auth->ssoDisplayNameAttribute,
            'want_messages_signed' => (bool)$auth->ssoWantMessagesSigned,
            'allow_sha1' => (bool)$auth->ssoAllowSha1,
            'authn_post_binding' => (bool)$auth->ssoAuthnPostBinding,
            'authn_requests_signed' => (bool)$auth->ssoAuthnRequestsSigned,
            'force_authn' => (bool)$auth->ssoForceAuthn,
            'max_age' => (int)$auth->ssoMaxAge,
            'required_acr' => (array)$auth->ssoRequiredAcr,
            'allow_idp_initiated' => (bool)$auth->ssoAllowIdpInitiated,
            'want_assertions_encrypted' => (bool)$auth->ssoWantAssertionsEncrypted,
            'want_nameid_encrypted' => (bool)$auth->ssoWantNameIdEncrypted,
        ]);
    }

    private function authServer($provider)
    {
        if (empty($provider)) {
            throw new \RuntimeException('missing provider');
        }
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth === null || $auth->getType() !== 'saml') {
            throw new \RuntimeException('unknown SAML provider');
        }
        return $auth;
    }

    /** Direct TCP peer -- never a forwardable header. */
    private function clientIp(): string
    {
        return (string)($_SERVER['REMOTE_ADDR'] ?? '');
    }

    /** Which door a flow is for, from the two parameters that mark the other two. */
    private static function serviceFor(string $vpn, string $cp): string
    {
        if ($cp !== '') {
            return ServiceScope::PORTAL;
        }
        return $vpn !== '' ? ServiceScope::VPN : ServiceScope::WEBGUI;
    }

    /**
     * Send the headers for one of our own HTML pages: content type, no framing, no
     * loading anything.
     *
     * @param array<string,string> $extra headers to add on top
     */
    private function html(string $formAction = "'self'", bool $inlineScript = false, array $extra = []): void
    {
        foreach (HtmlPage::headers($formAction, $inlineScript) + $extra as $header => $value) {
            $this->response->setHeader($header, $value);
        }
    }

    /** Reopen the native PHP session (the Mvc wrapper aborts it at dispatch). */
    private function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    /** Post-login landing path: requested page, else the configured default (ReturnUrl). */
    private function landing(string $returnUrl, $auth): string
    {
        return ReturnUrl::landing($returnUrl, (string)($auth->ssoLoginRedirect ?? ''));
    }

    /** Configured Base URL override for this provider, else a vetted auto-detect. */
    private function baseUrlFor($auth): string
    {
        return SiteUrl::forProvider($auth);
    }

    private function fail(\Throwable $e): string
    {
        // Detail goes to the log only; the unauthenticated caller gets a generic
        // message (avoid reflecting internal error text).
        syslog(LOG_ERR, 'os-sso saml: ' . $e->getMessage());
        $this->response->setStatusCode(400, 'Bad Request');
        return 'SSO login failed. See the firewall system log for details.';
    }
}
