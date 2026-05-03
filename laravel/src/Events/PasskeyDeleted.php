<?php

namespace Bherila\AuthLaravel\Events;

use Bherila\AuthLaravel\Models\PasskeyCredential;
use Illuminate\Contracts\Auth\Authenticatable;

class PasskeyDeleted
{
    public function __construct(
        public readonly Authenticatable $user,
        public readonly PasskeyCredential $credential,
    ) {}
}
