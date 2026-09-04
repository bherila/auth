<?php

namespace BWH\Auth\Tests\Fixtures;

use Laravel\Passport\Token;

final class CollectionScopesToken extends Token
{
    /** @var array<string, string> */
    protected $casts = [
        'scopes' => 'collection',
        'revoked' => 'bool',
        'expires_at' => 'datetime',
    ];
}
