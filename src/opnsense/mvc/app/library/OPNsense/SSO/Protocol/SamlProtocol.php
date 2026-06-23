<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use OneLogin\Saml2\Auth as Saml2Auth;
use OPNsense\SSO\NormalizedIdentity;

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
     *  state by the AuthnRequest ID instead, recovered at the ACS via InResponseTo. */
    private const STATE_DIR = "/var/tmp/os-sso-saml";
    private const STATE_TTL = 600; // seconds

    public function startLogin(string $returnUrl, string $vpn = '', string $cp = '', string $cpurl = ''): string
    {
        $auth = new Saml2Auth($this->settings());
        // login() with stay=true returns the redirect URL instead of redirecting.
        $url = $auth->login(null, [], false, false, true);
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
        return (string) $url;
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
        if ($requestId === "") {
            throw new \RuntimeException(
                "SAML: no in-flight request id (possible unsolicited response)",
            );
        }
        $auth = new Saml2Auth($this->settings());
        // processResponse validates signature, conditions, destination and that the
        // response InResponseTo equals $requestId.
        $auth->processResponse($requestId);

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

    private function saveState(string $requestId, array $data): void
    {
        if (!is_dir(self::STATE_DIR)) {
            @mkdir(self::STATE_DIR, 0700, true);
        }
        @chmod(self::STATE_DIR, 0700); // reassert mode if the dir pre-existed
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
        foreach (glob(self::STATE_DIR . '/*.json') ?: [] as $f) {
            if ((time() - (int) @filemtime($f)) > self::STATE_TTL) {
                @unlink($f);
            }
        }
    }

    private static function stateFile(string $requestId): string
    {
        return self::STATE_DIR . "/" . hash("sha256", $requestId) . ".json";
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

        $id->username =
            $this->firstAttr($attrs, [
                "uid",
                "username",
                "preferred_username",
            ]) ?:
            $id->subject;
        $id->email = $this->firstAttr($attrs, ["email", "mail"]);
        $id->displayName = $this->firstAttr($attrs, [
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
        $security = [
            "wantAssertionsSigned" => true,
            // The assertion is always required signed; optionally also require the
            // response message signed (stronger, mitigates XSW) when the IdP supports it.
            "wantMessagesSigned" => !empty($this->cfg["want_messages_signed"]),
            "wantNameIdEncrypted" => false,
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
                    "url" => ($this->cfg["base_url"] ?? "") . "/api/sso/saml/slo",
                    "binding" =>
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                ],
                "x509cert" => $this->cfg["sp_cert"] ?? "",
                "privateKey" => $this->cfg["sp_key"] ?? "",
            ],
            "idp" => [
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
            ],
            "security" => $security,
        ];
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
