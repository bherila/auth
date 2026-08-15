<?php

namespace BWH\Auth\OAuth;

final readonly class OAuthIdentity
{
    public function __construct(
        public string $provider,
        public string $subject,
        public string $name,
        public string $email,
    ) {}
}
