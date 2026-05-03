<?php

namespace Bherila\AuthLaravel\Services;

use Bherila\AuthLaravel\Contracts\AuthAuditLogger;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class NullAuthAuditLogger implements AuthAuditLogger
{
    public function passkeyRegistered(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyDeleted(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyLoginSucceeded(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyLoginFailed(Request $request, ?Authenticatable $user, ?string $credentialId, string $reason): void {}
}
