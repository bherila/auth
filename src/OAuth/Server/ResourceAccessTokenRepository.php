<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\Events\AccessTokenRevoked;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use RuntimeException;
use Throwable;

/**
 * Persists and validates Passport access-token resource bindings.
 *
 * Binding is stored in the database as well as in the JWT. The database state
 * lets a resource server reject revoked, legacy, or otherwise incomplete tokens;
 * the signed audience lets it reject a token whose credential was issued for a
 * different resource.
 */
final class ResourceAccessTokenRepository extends PassportAccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(Dispatcher $events)
    {
        parent::__construct($events);
    }

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        if (! $this->oauthServerEnabled()) {
            return parent::getNewToken($clientEntity, $scopes, $userIdentifier);
        }

        $token = new ResourceAccessToken($userIdentifier, $scopes, $clientEntity);
        $request = $this->request();
        $requestResource = $this->requestResource($request);
        $resource = $request === null
            ? null
            : (OAuthResourceIndicator::validatedFor($request) ?? $requestResource);

        if ($requestResource !== null && $resource !== $requestResource) {
            throw new RuntimeException('The access-token resource does not match the validated request resource.');
        }

        if ($resource !== null) {
            $token->setResource($resource);
        } elseif (OAuthResourceIndicator::scopesRequireResource($scopes)) {
            throw new RuntimeException('A protected resource is required for the requested scope.');
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (! $this->oauthServerEnabled()) {
            parent::persistNewAccessToken($accessTokenEntity);

            return;
        }

        $model = Passport::token();
        $resourceColumn = $this->resourceColumn();
        $hasResourceColumn = $this->hasColumn($model->getTable(), $resourceColumn);
        $request = $this->request();
        $requestResource = $this->requestResource($request);
        $resource = $accessTokenEntity instanceof ResourceAccessToken
            ? $accessTokenEntity->getResource()
            : ($request === null ? null : OAuthResourceIndicator::validatedFor($request));

        if ($resource !== null) {
            $resource = OAuthResourceIndicator::canonicalize($resource);
            if ($resource === null || $resource !== OAuthResourceIndicator::configuredCanonical()) {
                throw new RuntimeException('The access-token resource is not configured.');
            }
        }
        $validatedResource = $request === null ? null : OAuthResourceIndicator::validatedFor($request);
        if ($validatedResource !== null && ! OAuthResourceIndicator::isConfiguredResource($validatedResource)) {
            throw new RuntimeException('The validated access-token resource is invalid.');
        }
        $requestResource ??= $validatedResource;

        if ($resource !== $requestResource) {
            throw new RuntimeException('The access-token resource does not match the validated request resource.');
        }
        if (OAuthResourceIndicator::scopesRequireResource($accessTokenEntity->getScopes()) && $resource === null) {
            throw new RuntimeException('A protected resource is required for the requested scope.');
        }
        if ($resource !== null && ! $hasResourceColumn) {
            throw new RuntimeException("The {$model->getTable()}.{$resourceColumn} column is required.");
        }

        $attributes = [
            'id' => $id = $accessTokenEntity->getIdentifier(),
            'user_id' => $userId = $accessTokenEntity->getUserIdentifier(),
            'client_id' => $clientId = $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => $accessTokenEntity->getScopes(),
            'revoked' => false,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ];
        if ($hasResourceColumn) {
            $attributes[$resourceColumn] = $resource;
        }

        $model->forceFill($attributes)->save();
        $this->recordDynamicClientUse($clientId);

        $this->events->dispatch(new AccessTokenCreated($id, $userId, $clientId));
    }

    public function revokeAccessToken(string $tokenId): void
    {
        if (Passport::token()->newQuery()->whereKey($tokenId)->update(['revoked' => true])) {
            $this->events->dispatch(new AccessTokenRevoked($tokenId));
        }
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $model = Passport::token()->newQuery()->whereKey($tokenId)->first();
        if ($model === null || (bool) $model->getAttribute('revoked')) {
            return true;
        }

        $resourceColumn = $this->resourceColumn();
        // The token row is already loaded. Reading a missing attribute yields
        // null, which is the same fail-closed state as a missing binding, so the
        // bearer hot path does not need a schema-catalog query on every request.
        $storedValue = $model->getAttribute($resourceColumn);
        $storedResource = $storedValue === null ? null : OAuthResourceIndicator::canonicalize($storedValue);
        $scopes = OAuthResourceIndicator::scopeIdentifiers($model->getAttribute('scopes'));
        $bound = $storedValue !== null || OAuthResourceIndicator::scopesRequireResource($scopes);

        $request = $this->request();
        $serializedToken = $request?->bearerToken();
        $expectedResource = $request === null ? null : OAuthResourceIndicator::expectedFor($request);

        if (! $bound) {
            $claims = is_string($serializedToken)
                ? OAuthResourceIndicator::tokenClaims($serializedToken)
                : null;

            // A resource-bearing JWT without its database binding is incomplete;
            // never silently downgrade it to an unbound Passport token.
            if ($expectedResource !== null
                || OAuthResourceIndicator::tokenHasAnyResourceAudience($serializedToken)
                || is_string($claims['resource'] ?? null)) {
                return true;
            }

            // The row is already known to exist and be non-revoked. Preserve
            // Passport's normal unbound-token result without a second query.
            if (! $this->oauthServerEnabled()) {
                return false;
            }
        }

        try {
            $configuredResource = OAuthResourceIndicator::configuredCanonical();
            $issuer = OAuthResourceIndicator::issuer();
        } catch (Throwable) {
            return true;
        }
        if (! OAuthResourceIndicator::tokenHasIssuer($serializedToken, $issuer)) {
            return true;
        }

        if (! $bound) {
            return false;
        }

        // A resource-bound token is valid only where application policy has
        // explicitly marked the current route with its expected audience.
        if ($expectedResource === null
            || $storedResource === null
            || $storedResource !== $configuredResource
            || $storedResource !== $expectedResource) {
            return true;
        }

        if (! OAuthResourceIndicator::tokenHasAudience($serializedToken, $storedResource)
            || ! OAuthResourceIndicator::tokenResourceClaimMatches($serializedToken, $storedResource)) {
            return true;
        }

        $request?->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $storedResource);

        return false;
    }

    private function requestResource(?Request $request): ?string
    {
        if ($request === null || ! $request->exists('resource')) {
            return null;
        }

        $resource = OAuthResourceIndicator::requestResource($request);
        if ($resource === null || $resource !== OAuthResourceIndicator::configuredCanonical()) {
            throw new RuntimeException('The requested OAuth resource is invalid.');
        }

        return $resource;
    }

    private function resourceColumn(): string
    {
        $column = config('bherila-auth.oauth_server.resource_column', 'resource_uri');

        return is_string($column) && $column !== '' ? $column : 'resource_uri';
    }

    private function hasColumn(string $table, string $column): bool
    {
        return Passport::token()->getConnection()->getSchemaBuilder()->hasColumn($table, $column);
    }

    private function request(): ?Request
    {
        return app()->bound('request') ? app('request') : null;
    }

    private function oauthServerEnabled(): bool
    {
        return (bool) config('bherila-auth.oauth_server.enabled', false);
    }

    private function recordDynamicClientUse(string $clientId): void
    {
        $column = config('bherila-auth.oauth_server.dynamic_clients.last_used_at_column');
        if (! is_string($column) || $column === '') {
            return;
        }

        $client = Passport::client();
        if (! $this->hasColumn($client->getTable(), $column)) {
            return;
        }

        $client->newQuery()->whereKey($clientId)->update([$column => now()]);
    }
}
