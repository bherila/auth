<?php

namespace BWH\Auth\OAuth\Introspection;

final readonly class IntrospectedToken
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences
     */
    public function __construct(
        public bool $active,
        public ?string $issuer = null,
        public ?string $subject = null,
        public ?string $clientId = null,
        public array $scopes = [],
        public array $audiences = [],
        public ?string $resource = null,
        public ?int $expiresAt = null,
        public ?int $issuedAt = null,
        public ?int $notBefore = null,
    ) {}

    public static function inactive(): self
    {
        return new self(false);
    }
}
