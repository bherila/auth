<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\OAuth\Server\DynamicClientRegistration;
use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\InvalidClientMetadata;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

final class OAuthDynamicClientRegistrationController
{
    public function __invoke(
        Request $request,
        ClientRepository $clients,
        DynamicClientRegistrationValidator $validator,
    ): JsonResponse {
        if (! config('bherila-auth.oauth_server.enabled', false)) {
            return $this->noStore(['error' => 'invalid_request'], 404);
        }
        if (! config('bherila-auth.oauth_server.dynamic_clients.enabled', true)) {
            return $this->noStore(['error' => 'invalid_request'], 404);
        }
        if (! $this->supportsPublicClients()) {
            return $this->noStore(['error' => 'temporarily_unavailable'], 503);
        }

        $registeredAt = $this->dynamicClientConfig('registered_at_column', 'dynamically_registered_at');
        if (! is_string($registeredAt) || $registeredAt === '') {
            return $this->noStore(['error' => 'temporarily_unavailable'], 503);
        }

        $columns = $this->dynamicClientConfig('required_columns', ['dynamically_registered_at', 'scopes']);
        if (is_array($columns)) {
            foreach (['registered_at_column', 'last_used_at_column', 'scopes_column'] as $columnKey) {
                $column = $this->dynamicClientConfig($columnKey);
                if (is_string($column) && $column !== '') {
                    $columns[] = $column;
                }
            }
            $columns = array_values(array_unique(array_filter(
                $columns,
                static fn (mixed $column): bool => is_string($column) && $column !== '',
            )));
        }
        $clientModel = Passport::client();
        if (! is_array($columns)
            || ! $clientModel->getConnection()->getSchemaBuilder()->hasColumns(
                $clientModel->getTable(),
                $columns,
            )) {
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

        $client = $clientModel->getConnection()->transaction(function () use ($clients, $registration) {
            $client = $clients->createAuthorizationCodeGrantClient(
                $registration->clientName,
                $registration->redirectUris,
                confidential: false,
            );
            $client->forceFill($this->clientAttributes($registration))->save();

            return $client;
        });

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

        return OAuthResourceIndicator::scopeIdentifiers(
            array_is_list($scopes) ? $scopes : array_keys($scopes),
        );
    }

    private function dynamicClientConfig(string $key, mixed $default = null): mixed
    {
        return config("bherila-auth.oauth_server.dynamic_clients.{$key}", $default);
    }

    private function supportsPublicClients(): bool
    {
        $methods = config('bherila-auth.oauth_server.token_endpoint_auth_methods', ['none']);

        return is_array($methods) && in_array('none', $methods, true);
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
