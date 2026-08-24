<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Session\Session;

/**
 * Keeps a validated OAuth resource audience bound to Passport's opaque consent
 * token even when session middleware loses only the application's custom key.
 */
final readonly class OAuthAuthorizationStateStore
{
    public function __construct(
        private Session $session,
        private CacheRepository $cache,
    ) {}

    public function currentApprovalToken(): ?string
    {
        $authToken = $this->session->get('authToken');

        return is_string($authToken) ? $authToken : null;
    }

    public function rememberResource(string $authToken, string $resource): void
    {
        $this->session->put($this->key($authToken), $resource);
        $this->cache->put($this->key($authToken), $resource, $this->ttlSeconds());
    }

    public function resourceFor(string $authToken): ?string
    {
        $resource = $this->session->get($this->key($authToken));
        if (! is_string($resource)) {
            $resource = $this->cache->get($this->key($authToken));
        }

        return is_string($resource) ? $resource : null;
    }

    public function forgetResource(string $authToken): void
    {
        $this->session->forget($this->key($authToken));
        $this->cache->forget($this->key($authToken));
    }

    private function key(string $authToken): string
    {
        $prefix = config('bherila-auth.oauth_server.authorization_state.cache_prefix', 'oauth-resource:');

        return (is_string($prefix) ? $prefix : 'oauth-resource:').hash('sha256', $authToken);
    }

    private function ttlSeconds(): int
    {
        $configured = config('bherila-auth.oauth_server.authorization_state.ttl_seconds');
        if (is_int($configured) && $configured > 0) {
            return max(60, $configured);
        }

        return max(60, (int) config('session.lifetime', 120) * 60);
    }
}
