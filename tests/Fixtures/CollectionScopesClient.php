<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\Server\ResourceClient;

final class CollectionScopesClient extends ResourceClient
{
    /** @var array<string, string> */
    protected $casts = [
        'grant_types' => 'array',
        'scopes' => 'array',
        'registered_scopes' => 'collection',
        'redirect_uris' => 'array',
        'personal_access_client' => 'bool',
        'password_client' => 'bool',
        'revoked' => 'bool',
    ];
}
