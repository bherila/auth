<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Server\DynamicClientRegistration;
use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\InvalidClientMetadata;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\ClientRepository;

final class OAuthDynamicClientRegistrationController
{
    public function __invoke(
        Request $request,
        ClientRepository $clients,
        DynamicClientRegistrationValidator $validator,
    ): JsonResponse {
        $columns = $this->dynamicClientConfig('required_columns', ['dynamically_registered_at']);
        if (! is_array($columns) || ! Schema::hasColumns('oauth_clients', $columns)) {
            return $this->noStore(['error' => 'temporarily_unavailable'], 503);
        }

        try {
            $registration = $validator->validate($request, $this->scopes());
        } catch (InvalidClientMetadata $exception) {
            return $this->noStore([
                'error' => 'invalid_client_metadata',
                'error_description' => $exception->getMessage(),
            ], 400);
        }

        $client = $clients->createAuthorizationCodeGrantClient(
            $registration->clientName,
            $registration->redirectUris,
            confidential: false,
        );
        $client->forceFill($this->clientAttributes($registration))->save();

        return $this->noStore($registration->responseMetadata(
            (string) $client->id,
            $client->created_at?->getTimestamp(),
        ), 201, true);
    }

    /** @return array<string, mixed> */
    private function clientAttributes(DynamicClientRegistration $registration): array
    {
        $attributes = [];
        $registeredAt = $this->dynamicClientConfig('registered_at_column');
        if (is_string($registeredAt) && $registeredAt !== '') {
            $attributes[$registeredAt] = now();
        }
        $lastUsedAt = $this->dynamicClientConfig('last_used_at_column');
        if (is_string($lastUsedAt) && $lastUsedAt !== '') {
            $attributes[$lastUsedAt] = null;
        }
        $scopes = $this->dynamicClientConfig('scopes_column');
        if (is_string($scopes) && $scopes !== '') {
            $attributes[$scopes] = $registration->scopes;
        }

        return $attributes;
    }

    /** @return list<string> */
    private function scopes(): array
    {
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        return array_is_list($scopes) ? array_values($scopes) : array_keys($scopes);
    }

    private function dynamicClientConfig(string $key, mixed $default = null): mixed
    {
        return config("bherila-auth.oauth_server.dynamic_clients.{$key}", $default);
    }

    /** @param array<string, mixed> $payload */
    private function noStore(array $payload, int $status, bool $noSniff = false): JsonResponse
    {
        $headers = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];
        if ($noSniff) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }

        return response()->json($payload, $status, $headers);
    }
}
