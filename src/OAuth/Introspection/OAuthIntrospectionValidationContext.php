<?php

namespace BWH\Auth\OAuth\Introspection;

use Closure;
use LogicException;

final class OAuthIntrospectionValidationContext
{
    private ?string $token = null;

    private ?string $resource = null;

    public function token(): ?string
    {
        return $this->token;
    }

    public function resource(): ?string
    {
        return $this->resource;
    }

    public function run(string $token, string $resource, Closure $callback): mixed
    {
        if ($this->token !== null || $this->resource !== null) {
            throw new LogicException('Nested OAuth introspection validation is not supported.');
        }

        $this->token = $token;
        $this->resource = $resource;

        try {
            return $callback();
        } finally {
            $this->token = null;
            $this->resource = null;
        }
    }
}
