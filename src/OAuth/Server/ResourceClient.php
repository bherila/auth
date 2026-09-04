<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client as PassportClient;

/**
 * Makes package-created public clients third-party from Passport's perspective.
 *
 * Passport's default model treats an unowned client as first-party. That default
 * is useful for applications created through Passport's own UI, but it must not
 * make a public MCP client trusted merely because DCR created it.
 */
class ResourceClient extends PassportClient
{
    public function firstParty(): bool
    {
        return $this->isPackageDynamicClient() ? false : parent::firstParty();
    }

    /**
     * Keep the consent prompt for dynamically registered clients even if a future
     * Passport model derives its default from first-party status.
     *
     * @param  array<int, \Laravel\Passport\Scope>  $scopes
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return $this->isPackageDynamicClient() ? false : parent::skipsAuthorization($user, $scopes);
    }

    private function isPackageDynamicClient(): bool
    {
        $column = config(
            'bherila-auth.oauth_server.dynamic_clients.registered_at_column',
            'dynamically_registered_at',
        );
        if (! is_string($column) || $column === '') {
            return false;
        }

        return $this->getAttribute($column) !== null;
    }
}
