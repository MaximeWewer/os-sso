<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

/**
 * The discovery documents a SCIM client reads before it will talk to us:
 * /ServiceProviderConfig, /ResourceTypes and /Schemas (RFC 7643 section 6).
 *
 * These are not decoration. A client that cannot read them either refuses to start or
 * assumes a full implementation and then fails on the first unsupported call, so what
 * we advertise here has to match what the endpoint actually does -- notably: PATCH
 * yes, bulk no, filtering only on the two attributes we index, and sort no.
 */
final class ScimSchema
{
    public static function serviceProviderConfig(string $base): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'documentationUri' => 'https://github.com/MaximeWewer/os-sso',
            'patch' => ['supported' => true],
            // No bulk: every write is a config.xml save under a lock, so batching at
            // the protocol level would only hide how expensive that is.
            'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => true, 'maxResults' => ScimUsers::MAX_RESULTS],
            'changePassword' => ['supported' => false],
            'sort' => ['supported' => false],
            'etag' => ['supported' => false],
            'authenticationSchemes' => [[
                'type' => 'oauthbearertoken',
                'name' => 'OAuth Bearer Token',
                'description' => 'Per-provider bearer token, additionally restricted by source address.',
                'primary' => true,
            ]],
            'meta' => [
                'resourceType' => 'ServiceProviderConfig',
                'location' => $base . '/ServiceProviderConfig',
            ],
        ];
    }

    public static function resourceTypes(string $base): array
    {
        $types = [
            [
                'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
                'id' => 'User',
                'name' => 'User',
                'endpoint' => '/Users',
                'description' => 'OPNsense local account provisioned by os-sso',
                'schema' => 'urn:ietf:params:scim:schemas:core:2.0:User',
                'meta' => ['resourceType' => 'ResourceType', 'location' => $base . '/ResourceTypes/User'],
            ],
            [
                'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
                'id' => 'Group',
                'name' => 'Group',
                'endpoint' => '/Groups',
                'description' => 'OPNsense group; membership only, groups are not created over SCIM',
                'schema' => 'urn:ietf:params:scim:schemas:core:2.0:Group',
                'meta' => ['resourceType' => 'ResourceType', 'location' => $base . '/ResourceTypes/Group'],
            ],
        ];
        return self::listResponse($types);
    }

    public static function schemas(string $base): array
    {
        return self::listResponse([self::userSchema(), self::groupSchema()]);
    }

    /** @param array[] $resources */
    public static function listResponse(array $resources, ?int $total = null, int $startIndex = 1): array
    {
        return [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults' => $total ?? count($resources),
            'itemsPerPage' => count($resources),
            'startIndex' => $startIndex,
            'Resources' => $resources,
        ];
    }

    private static function userSchema(): array
    {
        return [
            'id' => 'urn:ietf:params:scim:schemas:core:2.0:User',
            'name' => 'User',
            'description' => 'SCIM core User, reduced to what an OPNsense account holds',
            'attributes' => [
                self::attr('userName', 'string', true, 'server'),
                self::attr('externalId', 'string', false, 'none'),
                self::attr('displayName', 'string', false, 'none'),
                self::attr('active', 'boolean', false, 'none'),
                [
                    'name' => 'emails',
                    'type' => 'complex',
                    'multiValued' => true,
                    'required' => false,
                    'mutability' => 'readWrite',
                    'returned' => 'default',
                    'uniqueness' => 'none',
                    'subAttributes' => [
                        self::attr('value', 'string', false, 'none'),
                        self::attr('primary', 'boolean', false, 'none'),
                    ],
                ],
            ],
            'meta' => ['resourceType' => 'Schema'],
        ];
    }

    private static function groupSchema(): array
    {
        return [
            'id' => 'urn:ietf:params:scim:schemas:core:2.0:Group',
            'name' => 'Group',
            'description' => 'SCIM core Group; os-sso maps members onto OPNsense group membership',
            'attributes' => [
                self::attr('displayName', 'string', true, 'server'),
                [
                    'name' => 'members',
                    'type' => 'complex',
                    'multiValued' => true,
                    'required' => false,
                    'mutability' => 'readWrite',
                    'returned' => 'default',
                    'uniqueness' => 'none',
                    'subAttributes' => [
                        self::attr('value', 'string', false, 'none'),
                        self::attr('display', 'string', false, 'none'),
                    ],
                ],
            ],
            'meta' => ['resourceType' => 'Schema'],
        ];
    }

    private static function attr(string $name, string $type, bool $required, string $uniqueness): array
    {
        return [
            'name' => $name,
            'type' => $type,
            'multiValued' => false,
            'required' => $required,
            'caseExact' => false,
            'mutability' => 'readWrite',
            'returned' => 'default',
            'uniqueness' => $uniqueness,
        ];
    }
}
