<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use OneLogin\Saml2\Auth as Saml2Auth;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\ReturnUrl;
use OPNsense\SSO\StateDir;

/**
 * SAML 2.0 Service Provider on top of SAML-Toolkits/php-saml (onelogin/php-saml).
 *
 * The toolkit does XML-DSig verification, but the SP settings decide WHAT must be signed
 * and validated -- the security lives in the settings() array below and in the
 * post-conditions asserted after processResponse():
 *   - wantAssertionsSigned / wantMessagesSigned (response AND/OR assertion).
 *   - NotBefore / NotOnOrAfter, Audience, Destination.
 *   - InResponseTo replay protection (single-use request id), plus a consumed-assertion
 *     cache covering the window before the victim's browser delivers the response.
 *   - AuthnInstant against the configured maximum authentication age.
 *   - IdP x509 CERTIFICATE registered (never just a fingerprint).
 *   - return URLs reduced to a same-site path (open redirect / CWE-601, see ReturnUrl).
 */
final class SamlProtocol implements ProtocolInterface
{
    private array $cfg;

    /* captured from the last validated assertion, for Single Logout */
    private string $lastNameId = '';
    private string $lastSessionIndex = '';
    private string $lastNameIdFormat = '';

    /* return URL recovered from the server-side state at the ACS (ProtocolInterface) */
    private string $returnUrl = '/';

    /**
     * @param array $cfg sp_entity_id, idp_entity_id, idp_sso_url, idp_x509,
     *                    sp_cert, sp_key, acs_url, name_id_format, groups_attribute
     */
    public function __construct(array $cfg)
    {
        $this->cfg = $cfg;
        // Pull in the composer-vendored onelogin/php-saml (Makefile post-extract).
        if (!class_exists(\OneLogin\Saml2\Auth::class)) {
            require_once __DIR__ . "/../vendor/autoload.php";
        }
        // Pin php-saml's self-URL detection to our known base. Behind a port
        // forward (e.g. 8443->443) $_SERVER reports the wrong port, which would
        // break the Destination check; setBaseURL makes ACS-URL generation and
        // the received-URL check agree.
        if (!empty($cfg["base_url"])) {
            // host-only base; php-saml appends REQUEST_URI to form the received URL.
            \OneLogin\Saml2\Utils::setBaseURL($cfg["base_url"]);
        }
    }

    /** server-side state store: the SAML assertion POST is cross-site, so the
     *  WebGUI session cookie (SameSite=Lax) is withheld. We key in-flight request
     *  state by the AuthnRequest ID instead, recovered at the ACS via InResponseTo.
     *  Lives under StateDir (root-owned /var/db, not world-writable /var/tmp). */
    private const STATE_TTL = 600; // seconds

    /** Ceiling on an inflated redirect-binding message (they run a few KiB). */
    private const MAX_INFLATE = 1048576;

    /** Tolerated clock difference when judging how old an authentication is. */
    private const CLOCK_SKEW = 60;

    private static function stateDir(): string
    {
        return StateDir::path("saml");
    }

    public function startLogin(string $returnUrl, string $vpn = '', string $cp = '', string $cpurl = ''): string
    {
        return (string) $this->beginLogin($returnUrl, $vpn, $cp, $cpurl)["url"];
    }

    /**
     * Build the AuthnRequest and record its in-flight state.
     *
     * @return array{binding:string,url:string,html:string} binding "redirect" (send
     *         the browser to url) or "post" (render html, a self-submitting form --
     *         some IdPs only accept the request over HTTP-POST)
     */
    public function beginLogin(string $returnUrl, string $vpn = '', string $cp = '', string $cpurl = ''): array
    {
        $auth = new Saml2Auth($this->settings());
        // login() with stay=true returns the redirect URL instead of redirecting.
        // ForceAuthn asks the IdP to re-authenticate rather than reuse its session; what
        // it actually did is checked back in assertAuthnAge().
        $url = (string) $auth->login(null, [], !empty($this->cfg["force_authn"]), false, true);
        // Persist {provider, return, vpn, cp} keyed by the AuthnRequest id for
        // recovery + single-use InResponseTo replay protection at the ACS. The vpn
        // sid / captive-portal zone ride here (not in the session) because the ACS
        // POST is cross-site.
        $this->saveState((string) $auth->getLastRequestID(), [
            "provider" => (string) ($this->cfg["provider_name"] ?? ""),
            "return" => ReturnUrl::sanitize($returnUrl),
            "vpn" => preg_replace('/[^a-f0-9]/', '', $vpn),
            "cp" => preg_replace('/[^0-9]/', '', $cp),
            "cpurl" => $cpurl,
            "ts" => time(),
        ]);

        if (empty($this->cfg["authn_post_binding"])) {
            return ["binding" => "redirect", "url" => $url, "html" => ""];
        }
        // HTTP-POST binding: same request, base64 of the raw XML (the redirect
        // binding's DEFLATE is a property of that binding, not of the message).
        return [
            "binding" => "post",
            "url" => (string) ($this->cfg["idp_sso_url"] ?? ""),
            "html" => $this->postBindingForm(
                (string) ($this->cfg["idp_sso_url"] ?? ""),
                base64_encode((string) $auth->getLastRequestXML())
            ),
        ];
    }

    /** Self-submitting form carrying the AuthnRequest over the HTTP-POST binding. */
    private function postBindingForm(string $ssoUrl, string $samlRequest): string
    {
        $u = htmlspecialchars($ssoUrl, ENT_QUOTES);
        $r = htmlspecialchars($samlRequest, ENT_QUOTES);
        return "<!doctype html><html><head><meta charset='utf-8'><title>Signing in</title></head>"
            . "<body onload='document.forms[0].submit()'>"
            . "<form method='post' action='{$u}'>"
            . "<input type='hidden' name='SAMLRequest' value='{$r}'>"
            . "<noscript><button type='submit'>Continue to the identity provider</button></noscript>"
            . "</form></body></html>";
    }

    /**
     * @param array $request POST data
     * @param string $requestId the expected AuthnRequest id (= response InResponseTo)
     */
    public function handleCallback(
        array $request,
        string $requestId = "",
        array $state = [],
    ): NormalizedIdentity {
        // Stash the recovered return URL so consumeReturnUrl() satisfies the
        // ProtocolInterface contract uniformly with the OIDC protocol.
        $this->returnUrl = ReturnUrl::sanitize((string) ($state["return"] ?? "/"));
        if ($requestId === "" && empty($this->cfg["allow_idp_initiated"])) {
            // No AuthnRequest of ours to tie this to. Unless the operator opted into
            // IdP-initiated SSO, that is an unsolicited response and we refuse it:
            // accepting one means anyone able to obtain an assertion can post it into
            // a victim's browser and silently log them in as somebody else.
            throw new \RuntimeException(
                "SAML: no in-flight request id (possible unsolicited response)",
            );
        }
        $auth = new Saml2Auth($this->settings());
        // processResponse validates signature, conditions, destination and that the
        // response InResponseTo equals $requestId.
        // null => IdP-initiated: php-saml then still refuses a response that carries
        // an InResponseTo (rejectUnsolicitedResponsesWithInResponseTo), so a real
        // reply to somebody else's AuthnRequest cannot slip in through this door.
        $auth->processResponse($requestId !== "" ? $requestId : null);

        $errors = $auth->getErrors();
        if (!empty($errors)) {
            throw new \RuntimeException(
                "SAML: response validation failed: " .
                    implode(", ", $errors) .
                    " (" .
                    $auth->getLastErrorReason() .
                    ")",
            );
        }
        if (!$auth->isAuthenticated()) {
            throw new \RuntimeException("SAML: assertion not authenticated");
        }

        // Reject an assertion ID already consumed within the replay window. The
        // single-use InResponseTo stops post-consumption replay; this additionally
        // closes the window where an attacker replays the response before the
        // victim's browser delivers it.
        $this->guardAssertionReplay((string) $auth->getLastAssertionId());
        $this->assertStrongSignature((string) $auth->getLastResponseXML());
        $this->assertAuthnAge($auth);
        $this->assertAuthnContext((string) $auth->getLastResponseXML());

        // Keep what Single Logout needs from the (verified) assertion.
        $this->lastNameId = (string) $auth->getNameId();
        $this->lastSessionIndex = (string) $auth->getSessionIndex();
        $this->lastNameIdFormat = (string) $auth->getNameIdFormat();

        return $this->toIdentity($auth);
    }

    /** XML-DSig algorithm URIs that end in one of these are not evidence of anything. */
    private const WEAK_ALG_SUFFIXES = ['sha1', 'md5', 'ripemd160'];

    /**
     * Refuse a response whose signature or digest uses a broken algorithm.
     *
     * php-saml verifies whatever the message declares in SignatureMethod: the certificate
     * has to be the right one, but the hash it commits to may still be SHA-1, and this
     * vendored version has no option to say otherwise. A signature over a broken hash
     * proves the IdP signed *some* document, not this one -- chosen-prefix collisions on
     * SHA-1 have been practical for years, and an assertion is exactly the kind of
     * attacker-influenced document (NameID, attributes) they need.
     *
     * Checked on the signatures php-saml actually validated -- the response's and the
     * assertion's -- and on the digest of each Reference under them, because a SHA-256
     * signature over a SHA-1 digest is no better than the digest. Off only if the
     * operator ticks the legacy box, which is there for an IdP that cannot be moved yet.
     */
    private function assertStrongSignature(string $xml): void
    {
        if (!empty($this->cfg['allow_sha1'])) {
            return;
        }
        $weak = self::weakAlgorithm($xml);
        if ($weak !== '') {
            throw new \RuntimeException(sprintf(
                'SAML: the assertion is signed with a broken algorithm (%s) -- configure the IdP for '
                . 'RSA-SHA256, or tick "Accept SHA-1 signatures" on this server if it cannot be moved',
                $weak
            ));
        }
    }

    /**
     * The first broken signature or digest algorithm a validated response carries, ''
     * when it carries none.
     *
     * Namespaces are matched by URI, not by the prefix the IdP happened to pick, and
     * only the two signature positions php-saml validates are looked at.
     */
    public static function weakAlgorithm(string $xml): string
    {
        return self::weakAlgorithmAt($xml, [
            '/samlp:Response/ds:Signature',
            '/samlp:Response/saml:Assertion/ds:Signature',
        ]);
    }

    /**
     * Same question at whichever signature positions the caller validated.
     *
     * @param string[] $signaturePaths xpaths of the ds:Signature elements that count
     */
    private static function weakAlgorithmAt(string $xml, array $signaturePaths): string
    {
        if ($xml === '') {
            return '';
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($xml, LIBXML_NONET | LIBXML_NSCLEAN)) {
            return ''; // php-saml parsed and verified it; we cannot second-guess it
        }
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        // Spelled out rather than composed: "|" unions whole paths, so appending one
        // suffix to a union only reaches its last branch.
        $paths = [];
        foreach ($signaturePaths as $signature) {
            $paths[] = $signature . '//ds:SignatureMethod';
            $paths[] = $signature . '//ds:DigestMethod';
        }
        $nodes = $xpath->query(implode('|', $paths));
        foreach ($nodes ?: [] as $node) {
            $alg = strtolower(trim((string) $node->getAttribute('Algorithm')));
            foreach (self::WEAK_ALG_SUFFIXES as $weak) {
                if ($alg !== '' && str_ends_with($alg, $weak)) {
                    return $alg;
                }
            }
        }
        return '';
    }

    /**
     * Same question for a redirect-binding Single Logout message, where the algorithm
     * travels as a query parameter rather than inside the XML.
     */
    private function assertStrongSloSignature(array $request): void
    {
        $sigAlg = strtolower(trim((string) ($request['SigAlg'] ?? '')));
        if (!empty($this->cfg['allow_sha1']) || $sigAlg === '') {
            return;
        }
        foreach (self::WEAK_ALG_SUFFIXES as $weak) {
            if (str_ends_with($sigAlg, $weak)) {
                throw new \RuntimeException(
                    'SAML: the logout message is signed with a broken algorithm (' . $sigAlg . ')'
                );
            }
        }
    }

    /**
     * Enforce the configured authentication context class.
     *
     * The SAML half of what OIDC does with acr_values and the acr claim, and needed for
     * the same reason: RequestedAuthnContext is a request, and an IdP that will not
     * honour it answers with an ordinary session rather than an error. So asking is not
     * enforcing -- what the assertion says it did is the only evidence there is, and an
     * assertion with no AuthnContextClassRef at all is a failure rather than a reason to
     * accept an authentication of unknown strength.
     *
     * The comparison is exact, as for acr: a context is an identifier, not a level.
     */
    private function assertAuthnContext(string $xml): void
    {
        $required = array_values(array_filter(array_map('strval', (array) ($this->cfg['required_acr'] ?? []))));
        if ($required === []) {
            return;
        }
        $got = self::authnContexts($xml);
        foreach ($got as $context) {
            if (in_array($context, $required, true)) {
                return;
            }
        }
        throw new \RuntimeException(sprintf(
            'SAML: the assertion authentication context (%s) is none of the required values (%s)',
            $got !== [] ? implode(', ', $got) : 'absent',
            implode(', ', $required)
        ));
    }

    /**
     * The AuthnContextClassRef values of a (validated) response.
     *
     * php-saml surfaces neither, so read them off the document it kept -- the same
     * decrypted, signature-checked XML assertAuthnAge() reads AuthnInstant from.
     *
     * @return string[]
     */
    public static function authnContexts(string $xml): array
    {
        if ($xml === '') {
            return [];
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($xml, LIBXML_NONET | LIBXML_NSCLEAN)) {
            return [];
        }
        $out = [];
        $nodes = $doc->getElementsByTagNameNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'AuthnContextClassRef'
        );
        for ($i = 0; $i < $nodes->length; $i++) {
            $value = trim((string) $nodes->item($i)->textContent);
            if ($value !== '' && !in_array($value, $out, true)) {
                $out[] = $value;
            }
        }
        return $out;
    }

    /**
     * Enforce the configured maximum age of the IdP authentication.
     *
     * The SAML counterpart of the OIDC max_age / auth_time pair, and needed for the same
     * reason: ForceAuthn is a *request*, and an IdP is free to answer it with a session
     * from this morning. AuthnInstant is the only evidence of when the user actually
     * authenticated, so a missing one is a failure rather than a reason to accept an
     * authentication of unknown age.
     */
    private function assertAuthnAge(Saml2Auth $auth): void
    {
        $maxAge = (int) ($this->cfg["max_age"] ?? 0);
        if ($maxAge <= 0) {
            return;
        }
        $instant = self::authnInstant((string) $auth->getLastResponseXML());
        if ($instant === null) {
            throw new \RuntimeException(
                "SAML: a maximum authentication age is configured but the assertion carries no AuthnInstant"
            );
        }
        if ((time() - $instant) > $maxAge + self::CLOCK_SKEW) {
            throw new \RuntimeException(
                "SAML: the IdP authentication is older than the configured maximum age"
            );
        }
    }

    /**
     * AuthnInstant of the assertion, as a unix timestamp.
     *
     * php-saml surfaces SessionNotOnOrAfter but not AuthnInstant, so read it off the
     * document it kept. Safe to trust: _lastResponse is only set once processResponse()
     * has verified the signature, and it holds the DECRYPTED assertion, so this is the
     * same XML the toolkit validated -- not the raw POST body.
     */
    private static function authnInstant(string $xml): ?int
    {
        if ($xml === "") {
            return null;
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($xml, LIBXML_NONET | LIBXML_NSCLEAN)) {
            return null;
        }
        $nodes = $doc->getElementsByTagNameNS(
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "AuthnStatement",
        );
        for ($i = 0; $i < $nodes->length; $i++) {
            $value = trim((string) $nodes->item($i)->getAttribute("AuthnInstant"));
            if ($value === "") {
                continue;
            }
            try {
                $ts = \OneLogin\Saml2\Utils::parseSAML2Time($value);
            } catch (\Throwable $e) {
                return null;
            }
            return is_int($ts) ? $ts : null;
        }
        return null;
    }

    public function getLastNameId(): string
    {
        return $this->lastNameId;
    }

    public function getLastSessionIndex(): string
    {
        return $this->lastSessionIndex;
    }

    public function getLastNameIdFormat(): string
    {
        return $this->lastNameIdFormat;
    }

    /** ProtocolInterface: the return URL recovered from the ACS state (sanitised). */
    public function consumeReturnUrl(): string
    {
        $url = $this->returnUrl;
        $this->returnUrl = '/';
        return ReturnUrl::sanitize($url);
    }

    /**
     * SP-initiated Single Logout: build the LogoutRequest redirect URL.
     * @return array{url:string,request_id:string} ('' url if the IdP has no SLO)
     */
    public function buildLogoutRequest(string $returnTo, string $nameId, string $sessionIndex, string $nameIdFormat): array
    {
        if (empty($this->cfg['idp_slo_url'])) {
            return ['url' => '', 'request_id' => ''];
        }
        $auth = new Saml2Auth($this->settings(true));
        $url = (string) $auth->logout($returnTo, [], $nameId, $sessionIndex, true, $nameIdFormat);
        return ['url' => $url, 'request_id' => (string) $auth->getLastRequestID()];
    }

    /**
     * Process an incoming SLO message: a LogoutResponse (SP-initiated round-trip,
     * validated against $requestId) or a LogoutRequest (IdP-initiated -- returns
     * the LogoutResponse redirect to send back). Throws on validation failure.
     */
    /**
     * The HTTP-POST counterpart: the same message, in the request body, signed inside
     * the XML instead of over the query string.
     *
     * php-saml only knows the redirect binding here -- it demands a Signature query
     * parameter and never looks at an embedded ds:Signature on a logout message -- so
     * an IdP that posts its SLO could not be answered at all. What it does know is
     * everything else that has to be checked (issuer, destination, InResponseTo, status,
     * NotOnOrAfter) and how to build the LogoutResponse to send back. So the signature
     * is verified here, against the same certificates the assertions are, and the
     * message is then handed to the toolkit with the query-signature requirement lifted
     * -- lifted only after this method has proved the message is signed.
     *
     * @param array $post the request body ($_POST)
     */
    public function processSloPost(string $requestId, array $post): array
    {
        $type = !empty($post['SAMLRequest']) ? 'SAMLRequest' : 'SAMLResponse';
        $raw = (string) ($post[$type] ?? '');
        $root = $type === 'SAMLRequest' ? 'LogoutRequest' : 'LogoutResponse';
        $this->assertPostSloSigned($root, self::decodeMessage($raw));

        // php-saml reads the message off $_GET whatever the binding; give it the one we
        // just verified, and nothing else from the body.
        $_GET[$type] = $raw;
        if (isset($post['RelayState'])) {
            $_GET['RelayState'] = (string) $post['RelayState'];
        }
        return $this->processSlo($requestId, false);
    }

    /**
     * Verify the XML signature of a posted logout message against the IdP certificate.
     *
     * @throws \RuntimeException when it is unsigned, signed by somebody else, or signed
     *         with an algorithm that proves nothing
     */
    private function assertPostSloSigned(string $root, string $xml): void
    {
        $path = '/samlp:' . $root . '/ds:Signature';
        if ($xml === '' || \OneLogin\Saml2\Utils::query(self::parse($xml), $path)->length === 0) {
            throw new \RuntimeException('SAML SLO: the posted ' . $root . ' carries no signature');
        }
        $weak = $this->cfg['allow_sha1'] ?? false ? '' : self::weakAlgorithmAt($xml, [$path]);
        if ($weak !== '') {
            throw new \RuntimeException(
                'SAML SLO: the posted ' . $root . ' is signed with a broken algorithm (' . $weak . ')'
            );
        }
        foreach ($this->idpCerts() as $cert) {
            try {
                if (\OneLogin\Saml2\Utils::validateSign($xml, $cert, null, 'sha256', $path)) {
                    return;
                }
            } catch (\Throwable $e) {
                // try the next certificate: an IdP mid key-rotation publishes several
            }
        }
        throw new \RuntimeException('SAML SLO: the posted ' . $root . ' signature does not verify');
    }

    /** Every certificate this provider accepts an IdP signature from. @return string[] */
    private function idpCerts(): array
    {
        $certs = array_values(array_filter((array) ($this->cfg['idp_x509_signing'] ?? [])));
        $pinned = trim((string) ($this->cfg['idp_x509'] ?? ''));
        if ($pinned !== '') {
            array_unshift($certs, $pinned);
        }
        return $certs;
    }

    /** base64, deflated or not, with the same DTD guard as every other message. */
    private static function decodeMessage(string $raw): string
    {
        $decoded = base64_decode($raw, true);
        if ($decoded === false || $decoded === '') {
            return '';
        }
        $xml = @gzinflate($decoded, self::MAX_INFLATE);
        if ($xml === false) {
            $xml = $decoded;
        }
        return preg_match('/<!DOCTYPE|<!ENTITY/i', $xml) ? '' : $xml;
    }

    /** A parsed document, or an empty one when it will not parse. */
    private static function parse(string $xml): \DOMDocument
    {
        $doc = new \DOMDocument();
        if ($xml === '' || !@$doc->loadXML($xml, LIBXML_NONET | LIBXML_NSCLEAN) || $doc->doctype !== null) {
            return new \DOMDocument();
        }
        return $doc;
    }

    /**
     * @param bool $querySigned whether the signature travelled on the query string, as
     *        the redirect binding puts it -- false when this class already verified an
     *        embedded one (processSloPost)
     */
    public function processSlo(string $requestId, bool $querySigned = true): array
    {
        if ($querySigned) {
            $this->assertStrongSloSignature($_GET);
        }
        $auth = new Saml2Auth($this->settings(true, $querySigned));
        $url = $auth->processSLO(false, $requestId !== '' ? $requestId : null, false, null, true);
        $errors = $auth->getErrors();
        if (!empty($errors)) {
            throw new \RuntimeException(
                'SAML SLO failed: ' . implode(', ', $errors) . ' (' . $auth->getLastErrorReason() . ')'
            );
        }
        return [
            'redirect' => (string) $url,
            // Who the logout is for. Only an IdP-initiated LogoutRequest names anyone: a
            // LogoutResponse is the answer to a request we made, so the caller already
            // knows. Read after the error check, so off the validated message.
            'subject' => isset($_GET['SAMLRequest'])
                ? $this->logoutSubject((string) $auth->getLastRequestXML())
                : ['name_id' => '', 'session_indexes' => []],
        ];
    }

    /**
     * NameID and SessionIndexes of a (validated) LogoutRequest.
     *
     * An SLO message ends a session at the IdP for a named subject, but front-channel is
     * the only binding here: whatever browser happens to follow the redirect gets logged
     * out, and every OTHER session that subject holds on this firewall survives -- which
     * is the opposite of what a logout is for. Naming the subject lets the caller reach
     * those through SessionRegistry, the same way OIDC back-channel logout does.
     *
     * @return array{name_id:string,session_indexes:string[]}
     */
    private function logoutSubject(string $xml): array
    {
        $empty = ['name_id' => '', 'session_indexes' => []];
        if ($xml === '') {
            return $empty;
        }
        try {
            // The SP key is needed only when the IdP encrypted the NameID.
            $nameId = (string) \OneLogin\Saml2\LogoutRequest::getNameId(
                $xml,
                (string) ($this->cfg['sp_key'] ?? '') ?: null
            );
            $indexes = \OneLogin\Saml2\LogoutRequest::getSessionIndexes($xml);
        } catch (\Throwable $e) {
            // An encrypted NameID with no key, or a shape we cannot read: the local
            // logout below still happens, we just cannot widen it.
            syslog(LOG_NOTICE, 'os-sso saml: cannot read the logout subject: ' . $e->getMessage());
            return $empty;
        }
        return [
            'name_id' => $nameId,
            'session_indexes' => array_values(array_filter(array_map('strval', (array) $indexes))),
        ];
    }

    /** The IdP EntityID this provider trusts, resolved from metadata when not typed. */
    public function getIdpEntityId(): string
    {
        return (string) ($this->cfg['idp_entity_id'] ?? '');
    }

    /**
     * Read the InResponseTo of a SAML POST response without trusting it yet
     * (signature is verified later in handleCallback). Entity expansion is left at
     * the libxml default (disabled in PHP 8), and no network is allowed.
     */
    public static function peekInResponseTo(array $request): string
    {
        $raw = base64_decode((string) ($request["SAMLResponse"] ?? ""), true);
        if ($raw === false || $raw === "") {
            return "";
        }
        // This parses UNVERIFIED, attacker-controlled XML before any signature
        // check, and runs pre-auth + CSRF-exempt. LIBXML_NONET blocks external
        // entities but NOT internal-entity expansion ("billion laughs"), so refuse
        // any DTD outright -- no legitimate SAMLResponse carries one.
        if (preg_match('/<!DOCTYPE|<!ENTITY/i', $raw)) {
            return "";
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($raw, LIBXML_NONET | LIBXML_NSCLEAN)) {
            return "";
        }
        if ($doc->doctype !== null) {
            return "";
        }
        return (string) $doc->documentElement->getAttribute("InResponseTo");
    }

    /**
     * Read the <Issuer> (IdP EntityID) of an incoming SLO message (LogoutRequest or
     * LogoutResponse) without trusting it, so the controller can pick the right
     * provider for an IdP-initiated logout. Redirect-binding messages are base64 +
     * raw-DEFLATE. Same XXE guard as peekInResponseTo (pre-auth, attacker XML).
     */
    public static function peekSloIssuer(array $request): string
    {
        $blob = (string) ($request["SAMLRequest"] ?? ($request["SAMLResponse"] ?? ""));
        if ($blob === "") {
            return "";
        }
        $decoded = base64_decode($blob, true);
        if ($decoded === false || $decoded === "") {
            return "";
        }
        // Redirect binding deflates the payload; POST binding does not. Inflate under a
        // hard ceiling: this runs pre-auth on an unauthenticated GET, and DEFLATE
        // compresses well enough that a few kilobytes of query string expand into as
        // much memory as the worker will give. Past the limit gzinflate truncates, the
        // XML no longer parses, and the message is refused -- which is the right answer
        // for anything that far outside a real SLO message.
        $xml = @gzinflate($decoded, self::MAX_INFLATE);
        if ($xml === false) {
            $xml = $decoded;
        }
        if ($xml === "" || preg_match('/<!DOCTYPE|<!ENTITY/i', $xml)) {
            return "";
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($xml, LIBXML_NONET | LIBXML_NSCLEAN)) {
            return "";
        }
        if ($doc->doctype !== null) {
            return "";
        }
        $nodes = $doc->getElementsByTagNameNS(
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "Issuer",
        );
        return $nodes->length ? trim((string) $nodes->item(0)->textContent) : "";
    }

    /**
     * Load and DELETE (single-use) the in-flight state for a request id.
     * @return array{provider:string,return:string}|null
     */
    public static function consumeState(string $requestId): ?array
    {
        $file = self::stateFile($requestId);
        if ($requestId === "" || !is_file($file)) {
            return null;
        }
        $data = json_decode((string) file_get_contents($file), true);
        @unlink($file); // single use: consumed exactly once
        if (
            !is_array($data) ||
            time() - (int) ($data["ts"] ?? 0) > self::STATE_TTL
        ) {
            return null;
        }
        return $data;
    }

    /**
     * Refuse a SAML assertion ID already accepted within the replay window.
     * php-saml keeps no replay cache of its own. Keyed by the (verified) assertion
     * ID; the window reuses STATE_TTL and the markers are swept by sweepStale().
     * Expired assertions are already rejected by php-saml (NotOnOrAfter), so this
     * only needs to cover the live window.
     */
    private function guardAssertionReplay(string $assertionId): void
    {
        if ($assertionId === "") {
            return; // nothing to key on; single-use InResponseTo still applies
        }
        $file = self::stateDir() . "/seen-" . hash("sha256", $assertionId) . ".json";
        // Drop a stale marker so a long-since-expired ID does not block forever.
        if (is_file($file) && time() - (int) @filemtime($file) > self::STATE_TTL) {
            @unlink($file);
        }
        // Exclusive create: succeeds exactly once per assertion ID in the window;
        // a concurrent or later replay fails the open and is rejected.
        $fp = @fopen($file, "x");
        if ($fp === false) {
            throw new \RuntimeException("SAML: assertion replay detected");
        }
        fwrite($fp, json_encode(["ts" => time()]));
        fclose($fp);
        @chmod($file, 0600);
    }

    private function saveState(string $requestId, array $data): void
    {
        $this->sweepStale();
        file_put_contents(
            self::stateFile($requestId),
            json_encode($data),
            LOCK_EX,
        );
        @chmod(self::stateFile($requestId), 0600);
    }

    /** Drop state files from abandoned logins (never consumed) past the TTL. */
    private function sweepStale(): void
    {
        foreach (glob(self::stateDir() . '/*.json') ?: [] as $f) {
            if ((time() - (int) @filemtime($f)) > self::STATE_TTL) {
                @unlink($f);
            }
        }
    }

    private static function stateFile(string $requestId): string
    {
        return self::stateDir() . "/" . hash("sha256", $requestId) . ".json";
    }

    /**
     * Generate SP metadata XML (served at /api/sso/saml/metadata).
     */
    public function metadata(): string
    {
        $settings = new \OneLogin\Saml2\Settings($this->settings(), true);
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);
        if (!empty($errors)) {
            throw new \RuntimeException(
                "SAML: invalid SP metadata: " . implode(", ", $errors),
            );
        }
        return $metadata;
    }

    private function toIdentity(Saml2Auth $auth): NormalizedIdentity
    {
        $attrs = $auth->getAttributes();
        $id = new NormalizedIdentity("");
        $id->subject = (string) $auth->getNameId();
        $groupsAttr = (string) ($this->cfg["groups_attribute"] ?? "groups");

        // The conventional friendly names cover Keycloak/Authentik out of the box,
        // but plenty of IdPs only emit OID-style names (urn:oid:0.9.2342.19200300.
        // 100.1.1 and friends) or a site-specific one -- hence the configurable
        // attribute, which always wins over the guesses below.
        $id->username =
            $this->attr($attrs, $this->cfg["username_attribute"] ?? "", [
                "uid",
                "username",
                "preferred_username",
            ]) ?:
            $id->subject;
        $id->email = $this->attr($attrs, $this->cfg["email_attribute"] ?? "", [
            "email",
            "mail",
        ]);
        $id->displayName = $this->attr($attrs, $this->cfg["display_name_attribute"] ?? "", [
            "displayName",
            "cn",
            "name",
        ]);
        $id->groups = array_values(
            array_map("strval", $attrs[$groupsAttr] ?? []),
        );
        $id->raw = $attrs;
        return $id;
    }

    /**
     * Value of the operator-configured attribute, else the first of the conventional
     * fallback names that carries one.
     */
    private function attr(array $attrs, string $configured, array $fallbacks): string
    {
        $configured = trim($configured);
        if ($configured !== "") {
            return $this->firstAttr($attrs, [$configured]);
        }
        return $this->firstAttr($attrs, $fallbacks);
    }

    private function firstAttr(array $attrs, array $names): string
    {
        foreach ($names as $n) {
            if (!empty($attrs[$n][0])) {
                return (string) $attrs[$n][0];
            }
        }
        return "";
    }

    /**
     * Build the php-saml settings array. wantAssertionsSigned handles the common
     * "assertion signed" case; signatureAlgorithm pinned to RSA-SHA256.
     *
     * @param bool $forSlo when true, REQUIRE incoming Single Logout messages to be
     *   signed (an unsigned LogoutRequest is otherwise a forced-logout / CSRF lever)
     *   and sign our own outgoing SLO messages when an SP key is configured.
     * @param bool $sloQuerySigned whether that requirement is php-saml's to enforce.
     *   It only knows the redirect binding's query signature; for a posted message
     *   processSloPost() has already verified the embedded one, and leaving the flag on
     *   would reject it for lacking a signature it does not carry by construction.
     */
    private function settings(bool $forSlo = false, bool $sloQuerySigned = true): array
    {
        // Encryption is decided by the IdP (it encrypts to our SP certificate) and
        // merely REQUIRED here; php-saml decrypts with the SP private key either way.
        // Requiring it without a key would reject every assertion, so say why.
        $wantEncrypted = !empty($this->cfg["want_assertions_encrypted"]);
        $wantNameIdEncrypted = !empty($this->cfg["want_nameid_encrypted"]);
        if (($wantEncrypted || $wantNameIdEncrypted) && empty($this->cfg["sp_key"])) {
            throw new \RuntimeException(
                "SAML: encrypted assertions require an SP certificate and private key"
            );
        }

        // Signing the AuthnRequest is the IdP's call, not ours: some require it and
        // refuse an unsigned request outright. Setting it here also makes the generated
        // SP metadata declare AuthnRequestsSigned, which is how an IdP that reads
        // metadata learns to expect one -- and which certificate to check it with.
        $signAuthn = !empty($this->cfg["authn_requests_signed"]);
        if ($signAuthn && (empty($this->cfg["sp_key"]) || empty($this->cfg["sp_cert"]))) {
            throw new \RuntimeException(
                "SAML: signing the AuthnRequest requires an SP certificate and private key"
            );
        }

        $requiredAcr = array_values(array_filter(array_map('strval', (array) ($this->cfg["required_acr"] ?? []))));

        $security = [
            "wantAssertionsSigned" => true,
            "authnRequestsSigned" => $signAuthn,
            // The assertion is always required signed; optionally also require the
            // response message signed (stronger, mitigates XSW) when the IdP supports it.
            "wantMessagesSigned" => !empty($this->cfg["want_messages_signed"]),
            "wantAssertionsEncrypted" => $wantEncrypted,
            "wantNameIdEncrypted" => $wantNameIdEncrypted,
            // Ask for the context we are going to insist on in assertAuthnContext().
            // false = ask for nothing, which is the right request when nothing is
            // required: php-saml's own default asks for PasswordProtectedTransport,
            // which several IdPs answer by refusing anything stronger.
            "requestedAuthnContext" => $requiredAcr !== [] ? $requiredAcr : false,
            "requestedAuthnContextComparison" => "exact",
            "signatureAlgorithm" =>
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "rejectUnsolicitedResponsesWithInResponseTo" => true,
            "allowRepeatAttributeName" => true,
        ];
        if ($forSlo) {
            $security["wantMessagesSigned"] = $sloQuerySigned;
            if (!empty($this->cfg["sp_key"]) && !empty($this->cfg["sp_cert"])) {
                $security["logoutRequestSigned"] = true;
                $security["logoutResponseSigned"] = true;
            }
        }
        return [
            "strict" => true,
            "sp" => [
                "entityId" => $this->cfg["sp_entity_id"] ?? "",
                "assertionConsumerService" => [
                    "url" => $this->cfg["acs_url"] ?? "",
                    "binding" =>
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                ],
                "NameIDFormat" =>
                    $this->cfg["name_id_format"] ??
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "singleLogoutService" => [
                    "url" => ($this->cfg["base_url"] ?? "") . "/api/sso/saml/slo"
                        . ($this->cfg["endpoint_suffix"] ?? ""),
                    "binding" =>
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                ],
                "x509cert" => $this->cfg["sp_cert"] ?? "",
                "privateKey" => $this->cfg["sp_key"] ?? "",
            ],
            "idp" => array_merge([
                "entityId" => $this->cfg["idp_entity_id"] ?? "",
                "singleSignOnService" => [
                    "url" => $this->cfg["idp_sso_url"] ?? "",
                    "binding" =>
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                ],
                "singleLogoutService" => [
                    "url" => $this->cfg["idp_slo_url"] ?? ($this->cfg["idp_sso_url"] ?? ""),
                    "binding" =>
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                ],
                // Full x509 certificate, NOT a fingerprint.
                "x509cert" => $this->cfg["idp_x509"] ?? "",
            ], $this->idpSigningCerts()),
            "security" => $security,
        ];
    }

    /**
     * Several signing certificates (from IdP metadata) instead of one: php-saml then
     * accepts a signature from any of them, which is how a key rotation stops being
     * an outage. Only used when no single certificate was pinned by hand.
     */
    private function idpSigningCerts(): array
    {
        $certs = array_values(array_filter((array)($this->cfg["idp_x509_signing"] ?? [])));
        if (count($certs) < 2) {
            return [];
        }
        return ["x509certMulti" => ["signing" => $certs]];
    }

}
