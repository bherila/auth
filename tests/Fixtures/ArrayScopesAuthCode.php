<?php

namespace BWH\Auth\Tests\Fixtures;

use Laravel\Passport\AuthCode;

final class ArrayScopesAuthCode extends AuthCode
{
    /** @var array<string, string> */
    protected $casts = [
        'scopes' => 'array',
        'revoked' => 'bool',
        'expires_at' => 'datetime',
    ];
}
