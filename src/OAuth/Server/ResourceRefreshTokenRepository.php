<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

/**
 * Keeps refresh-token exchanges on the resource selected for the original grant.
 */
final class ResourceRefreshTokenRepository extends PassportRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        if (parent::isRefreshTokenRevoked($tokenId)) {
            return true;
        }

        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($tokenId)->first();
        $accessTokenId = $refreshToken?->getAttribute('access_token_id');
        if (! is_string($accessTokenId) || $accessTokenId === '') {
            return true;
        }

        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();
        if ($accessToken === null) {
            return true;
        }

        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = Passport::token()->getConnection()->getSchemaBuilder()->hasColumn(
            $accessToken->getTable(),
            $resourceColumn,
        );
        $storedValue = $hasResourceColumn ? $accessToken->getAttribute($resourceColumn) : null;
        $storedResource = $storedValue === null ? null : OAuthResourceIndicator::canonicalize($storedValue);
        $scopes = OAuthResourceIndicator::scopeIdentifiers($accessToken->getAttribute('scopes'));
        $bound = $storedValue !== null || OAuthResourceIndicator::scopesRequireResource($scopes);
        $request = $this->request();
        $hasRequestedResource = $request?->exists('resource') ?? false;
        $requestedResource = $request === null ? null : OAuthResourceIndicator::requestResource($request);

        if (! $bound) {
            // A refresh request cannot add an audience that was absent from the
            // authorization-code grant.
            return $hasRequestedResource;
        }

        if ($storedResource === null
            || $storedResource !== OAuthResourceIndicator::configuredCanonical()
            || ! $hasRequestedResource
            || $requestedResource !== $storedResource) {
            // Do not consume the refresh token for a resource mismatch. A client
            // can retry the same token with the resource originally granted.
            return true;
        }

        $request?->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $storedResource);

        return false;
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }
}
