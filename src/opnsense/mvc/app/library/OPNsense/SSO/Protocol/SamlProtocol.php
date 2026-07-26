<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use OneLogin\Saml2\Auth as Saml2Auth;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\StateDir;

/**
 * SAML 2.0 Service Provider on top of SAML-Toolkits/php-saml (onelogin/php-saml).
 *
 * Phase 4. The toolkit does XML-DSig verification, but the SP
 * settings decide WHAT must be signed and validated -- the security lives in the
 * settings below and in the post-conditions we assert after processResponse():
 *   - wantAssertionsSigned / wantMessagesSigned (response AND/OR assertion).
 *   - NotBefore / NotOnOrAfter, Audience, Destination.
 *   - InResponseTo replay protection (single-use request id).
 *   - IdP x509 CERTIFICATE registered (never just a fingerprint).
 *   - RelayState validated against a same-host allowlist (open redirect / CWE-601).
 *
 * NOTE: this is the structured shell. The settings array is real; wiring it to
 * the provider config + a request-id store is the remaining Phase 4 work.
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
        $url = (string) $auth->login(null, [], false, false, true);
        // Persist {provider, return, vpn, cp} keyed by the AuthnRequest id for
        // recovery + single-use InResponseTo replay protection at the ACS. The vpn
        // sid / captive-portal zone ride here (not in the session) because the ACS
        // POST is cross-site.
        $this->saveState((string) $auth->getLastRequestID(), [
            "provider" => (string) ($this->cfg["provider_name"] ?? ""),
            "return" => $this->sanitizeReturnUrl($returnUrl),
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
        $this->returnUrl = $this->sanitizeReturnUrl((string) ($state["return"] ?? "/"));
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

        // Keep what Single Logout needs from the (verified) assertion.
        $this->lastNameId = (string) $auth->getNameId();
        $this->lastSessionIndex = (string) $auth->getSessionIndex();
        $this->lastNameIdFormat = (string) $auth->getNameIdFormat();

        return $this->toIdentity($auth);
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
        return $this->sanitizeReturnUrl($url);
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
    public function processSlo(string $requestId): string
    {
        $auth = new Saml2Auth($this->settings(true));
        $url = $auth->processSLO(false, $requestId !== '' ? $requestId : null, false, null, true);
        $errors = $auth->getErrors();
        if (!empty($errors)) {
            throw new \RuntimeException(
                'SAML SLO failed: ' . implode(', ', $errors) . ' (' . $auth->getLastErrorReason() . ')'
            );
        }
        return (string) $url;
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
        // Redirect binding deflates the payload; POST binding does not.
        $xml = @gzinflate($decoded);
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
     */
    private function settings(bool $forSlo = false): array
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

        $security = [
            "wantAssertionsSigned" => true,
            // The assertion is always required signed; optionally also require the
            // response message signed (stronger, mitigates XSW) when the IdP supports it.
            "wantMessagesSigned" => !empty($this->cfg["want_messages_signed"]),
            "wantAssertionsEncrypted" => $wantEncrypted,
            "wantNameIdEncrypted" => $wantNameIdEncrypted,
            "requestedAuthnContext" => false,
            "signatureAlgorithm" =>
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "rejectUnsolicitedResponsesWithInResponseTo" => true,
            "allowRepeatAttributeName" => true,
        ];
        if ($forSlo) {
            $security["wantMessagesSigned"] = true;
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

    private function sanitizeReturnUrl(string $url): string
    {
        // Reject "//host" AND "/\host" (browsers fold "\"->"/" => protocol-relative)
        // and any CR/LF/TAB (header split). Same-host relative paths only (CWE-601).
        if (
            $url === "" || $url[0] !== "/"
            || str_starts_with($url, "//") || str_starts_with($url, "/\\")
            || strpbrk($url, "\\\r\n\t") !== false
        ) {
            return "/";
        }
        return $url;
    }
}
