<?php

namespace Bherila\AuthLaravel\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface AuthAuditLogger
{
    public function passkeyRegistered(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyDeleted(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyLoginSucceeded(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyLoginFailed(Request $request, ?Authenticatable $user, ?string $credentialId, string $reason): void;
}
