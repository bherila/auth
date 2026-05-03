<?php

namespace BWH\Auth\Events;

class PasskeyLoginFailed
{
    public function __construct(
        public readonly ?string $credentialId,
        public readonly string $reason,
    ) {}
}
