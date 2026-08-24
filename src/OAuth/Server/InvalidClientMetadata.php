<?php

namespace BWH\Auth\OAuth\Server;

use RuntimeException;

final class InvalidClientMetadata extends RuntimeException
{
    public function __construct(string $description = 'Client metadata is invalid.')
    {
        parent::__construct($description);
    }
}
