<?php

namespace BWH\Auth\Support;

use Carbon\CarbonInterface;

class LoginThrottleState
{
    public function __construct(
        public readonly bool $enabled,
        public readonly bool $locked,
        public readonly int $attempts,
        public readonly int $maxAttempts,
        public readonly int $remaining,
        public readonly ?int $decayMinutes,
        public readonly ?CarbonInterface $retryAt,
        public readonly ?string $email,
        public readonly ?string $ipAddress,
        public readonly ?string $authMethod,
    ) {}

    public static function allowed(bool $enabled, int $attempts, int $maxAttempts, ?int $decayMinutes, ?string $email, ?string $ipAddress, ?string $authMethod): self
    {
        return new self(
            enabled: $enabled,
            locked: false,
            attempts: $attempts,
            maxAttempts: $maxAttempts,
            remaining: max(0, $maxAttempts - $attempts),
            decayMinutes: $decayMinutes,
            retryAt: null,
            email: $email,
            ipAddress: $ipAddress,
            authMethod: $authMethod,
        );
    }

    public static function locked(int $attempts, int $maxAttempts, int $decayMinutes, CarbonInterface $retryAt, ?string $email, ?string $ipAddress, ?string $authMethod): self
    {
        return new self(
            enabled: true,
            locked: true,
            attempts: $attempts,
            maxAttempts: $maxAttempts,
            remaining: 0,
            decayMinutes: $decayMinutes,
            retryAt: $retryAt,
            email: $email,
            ipAddress: $ipAddress,
            authMethod: $authMethod,
        );
    }

    public function allowsLogin(): bool
    {
        return ! $this->locked;
    }

    public function availableInSeconds(): int
    {
        if (! $this->retryAt instanceof CarbonInterface) {
            return 0;
        }

        return max(0, $this->retryAt->getTimestamp() - now()->getTimestamp());
    }
}
