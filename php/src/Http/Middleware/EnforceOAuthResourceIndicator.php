<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\OAuthAuthorizationStateStore;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Symfony\Component\HttpFoundation\Response;

final class EnforceOAuthResourceIndicator
{
    public function __construct(
        private readonly OAuthAuthorizationStateStore $authorizationState,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethod('GET') && $request->routeIs('passport.authorizations.authorize')) {
            return $this->authorizationRequest($request, $next);
        }

        if ($request->routeIs('passport.authorizations.approve', 'passport.authorizations.deny')) {
            return $this->consentSubmission($request, $next);
        }

        if ($request->routeIs('passport.token') && $request->exists('resource')) {
            if (OAuthResourceIndicator::canonicalize($request->input('resource')) === null) {
                return $this->invalidResource();
            }
        }

        return $next($request);
    }

    private function authorizationRequest(Request $request, Closure $next): Response
    {
        $scopeInput = $request->query('scope', '');
        if (! is_string($scopeInput)) {
            return $this->invalidScope();
        }
        $scopes = DynamicClientRegistrationValidator::parseScopes($scopeInput);
        $knownScopes = $this->configuredScopes();
        if (array_diff($scopes, $knownScopes) !== []) {
            return $this->invalidScope();
        }
        if (! $this->clientAllows($request->query('client_id'), $scopes)) {
            return $this->invalidScope();
        }

        $resource = $request->query('resource');
        $requiredScope = config('bherila-auth.oauth_server.resource_required_scope');
        if (($resource !== null && ! OAuthResourceIndicator::isConfiguredResource($resource))
            || (is_string($requiredScope) && in_array($requiredScope, $scopes, true) && $resource === null)) {
            return $this->invalidResource();
        }
        if ($resource !== null) {
            $request->attributes->set(
                OAuthResourceIndicator::REQUEST_ATTRIBUTE,
                OAuthResourceIndicator::resource(),
            );
        }

        $previousAuthToken = $this->authorizationState->currentApprovalToken();
        $response = $next($request);
        $authToken = $this->authorizationState->currentApprovalToken();
        if (is_string($authToken)
            && ($previousAuthToken === null || ! hash_equals($previousAuthToken, $authToken))
            && $resource !== null) {
            $this->authorizationState->rememberResource(
                $authToken,
                OAuthResourceIndicator::resource(),
            );
        }
        if ($previousAuthToken !== null
            && ($authToken === null || ! hash_equals($previousAuthToken, $authToken))) {
            $this->authorizationState->forgetResource($previousAuthToken);
        }

        return $response;
    }

    private function consentSubmission(Request $request, Closure $next): Response
    {
        $authToken = $request->input('auth_token');
        $resource = is_string($authToken) ? $this->authorizationState->resourceFor($authToken) : null;
        if (is_string($resource)) {
            $request->attributes->set(OAuthResourceIndicator::REQUEST_ATTRIBUTE, $resource);
        }

        try {
            return $next($request);
        } finally {
            if (is_string($authToken)
                && $this->authorizationState->currentApprovalToken() !== $authToken) {
                $this->authorizationState->forgetResource($authToken);
            }
        }
    }

    /** @param list<string> $scopes */
    private function clientAllows(mixed $clientId, array $scopes): bool
    {
        if (! config('bherila-auth.oauth_server.dynamic_clients.enforce_registered_scopes', false)
            || ! is_string($clientId)) {
            return true;
        }

        $client = Passport::client()->newQuery()->find($clientId);
        if ($client === null) {
            return true;
        }
        $registeredAtColumn = config('bherila-auth.oauth_server.dynamic_clients.registered_at_column');
        if (! is_string($registeredAtColumn) || $client->getAttribute($registeredAtColumn) === null) {
            return true;
        }

        return array_filter($scopes, static fn (string $scope): bool => ! $client->hasScope($scope)) === [];
    }

    /** @return list<string> */
    private function configuredScopes(): array
    {
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        return array_is_list($scopes) ? array_values($scopes) : array_keys($scopes);
    }

    private function invalidResource(): JsonResponse
    {
        return new JsonResponse([
            'error' => 'invalid_target',
            'error_description' => 'The requested resource is invalid.',
        ], 400, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function invalidScope(): JsonResponse
    {
        return new JsonResponse([
            'error' => 'invalid_scope',
            'error_description' => 'The requested scope is invalid for this client.',
        ], 400, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
