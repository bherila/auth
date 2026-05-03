<?php

namespace Bherila\AuthLaravel\Events;

class PasskeyLoginFailed
{
    public function __construct(
        public readonly ?string $credentialId,
        public readonly string $reason,
    ) {}
}
