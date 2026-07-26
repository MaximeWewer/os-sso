<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

/**
 * A failure the SCIM client is meant to see, with the status and scimType RFC 7644
 * section 3.12 expects.
 *
 * Provisioning clients act on these: Authentik retries a 5xx and gives up on a 4xx,
 * and "uniqueness" on a POST is how a client learns to PATCH instead. Collapsing
 * everything to 500 would make a directory sync loop forever on a bad record.
 */
final class ScimError extends \RuntimeException
{
    private string $scimType;

    public function __construct(int $status, string $detail, string $scimType = '')
    {
        parent::__construct($detail, $status);
        $this->scimType = $scimType;
    }

    public function status(): int
    {
        return (int)$this->getCode();
    }

    /** @return array the SCIM Error resource for the response body */
    public function toResource(): array
    {
        $out = [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'status' => (string)$this->status(),
            'detail' => $this->getMessage(),
        ];
        if ($this->scimType !== '') {
            $out['scimType'] = $this->scimType;
        }
        return $out;
    }

    public static function notFound(string $what): self
    {
        return new self(404, $what . ' not found');
    }

    public static function badRequest(string $detail, string $scimType = 'invalidValue'): self
    {
        return new self(400, $detail, $scimType);
    }

    public static function conflict(string $detail): self
    {
        return new self(409, $detail, 'uniqueness');
    }
}
