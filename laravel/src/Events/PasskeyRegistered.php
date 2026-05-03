<?php

namespace BWH\Auth\Events;

use BWH\Auth\Models\PasskeyCredential;
use Illuminate\Contracts\Auth\Authenticatable;

class PasskeyRegistered
{
    public function __construct(
        public readonly Authenticatable $user,
        public readonly PasskeyCredential $credential,
    ) {}
}
