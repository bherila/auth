<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Introspection\OAuthIntrospectionClientRegistry;
use BWH\Auth\OAuth\Introspection\OAuthIntrospectionValidationContext;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use GuzzleHttp\Psr7\ServerRequest;
use InvalidArgumentException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OAuthTokenIntrospectionController
{
    public function __construct(
        private OAuthIntrospectionClientRegistry $clients,
        private OAuthIntrospectionValidationContext $context,
        private ResourceServer $resourceServer,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        abort_unless((bool) config('bherila-auth.oauth_server.introspection.enabled', false), 404);

        $resource = $this->clients->resourceFor($request);
        if ($resource === null) {
            return response()->json(['error' => 'invalid_client'], 401)->withHeaders([
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'WWW-Authenticate' => 'Basic realm="oauth-introspection"',
            ]);
        }

        $canonicalResource = OAuthResourceIndicator::canonicalize($resource);
        if ($canonicalResource === null || $canonicalResource !== OAuthResourceIndicator::configuredCanonical()) {
            return $this->inactive();
        }

        $token = $request->input('token');
        if (! is_string($token) || $token === '' || strlen($token) > 32_768) {
            return $this->inactive();
        }

        try {
            $validated = $this->context->run($token, $canonicalResource, function () use ($token): ServerRequestInterface {
                return $this->resourceServer->validateAuthenticatedRequest(
                    (new ServerRequest('POST', '/oauth/introspect'))
                        ->withHeader('Authorization', 'Bearer '.$token),
                );
            });
        } catch (OAuthServerException|InvalidArgumentException) {
            return $this->inactive();
        }

        $claims = OAuthResourceIndicator::tokenClaims($token);
        $subject = $validated->getAttribute('oauth_user_id');
        $clientId = $validated->getAttribute('oauth_client_id');
        $scopes = OAuthResourceIndicator::scopeIdentifiers($validated->getAttribute('oauth_scopes'));
        if ((! is_string($subject) && ! is_int($subject))
            || (string) $subject === ''
            || (! is_string($clientId) && ! is_int($clientId))
            || (string) $clientId === '') {
            return $this->inactive();
        }

        $response = [
            'active' => true,
            'iss' => $claims['iss'] ?? null,
            'sub' => (string) $subject,
            'client_id' => (string) $clientId,
            'scope' => implode(' ', $scopes),
            'exp' => $claims['exp'] ?? null,
            'aud' => $claims['aud'] ?? null,
            'resource' => $claims['resource'] ?? null,
        ];
        foreach (['iat', 'nbf'] as $claim) {
            if (isset($claims[$claim])) {
                $response[$claim] = $claims[$claim];
            }
        }

        return response()->json($response)->withHeaders($this->nonCacheableHeaders());
    }

    private function inactive(): JsonResponse
    {
        return response()->json(['active' => false])->withHeaders($this->nonCacheableHeaders());
    }

    /** @return array<string, string> */
    private function nonCacheableHeaders(): array
    {
        return [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ];
    }
}
