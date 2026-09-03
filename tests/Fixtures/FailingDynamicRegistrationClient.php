<?php

namespace BWH\Auth\Tests\Fixtures;

use BWH\Auth\OAuth\Server\ResourceClient;
use RuntimeException;

final class FailingDynamicRegistrationClient extends ResourceClient
{
    public function setDynamicallyRegisteredAtAttribute(mixed $value): never
    {
        throw new RuntimeException('Synthetic dynamic client metadata failure.');
    }
}
