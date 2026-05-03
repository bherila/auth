<?php

namespace Bherila\AuthLaravel\Events;

use Bherila\AuthLaravel\Models\PasskeyCredential;
use Illuminate\Contracts\Auth\Authenticatable;

class PasskeyLoginSucceeded
{
    public function __construct(
        public readonly Authenticatable $user,
        public readonly PasskeyCredential $credential,
    ) {}
}
