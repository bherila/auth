<?php

namespace BWH\Auth\OAuth\Server;

final readonly class DynamicClientRegistration
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>|null  $scopes
     */
    public function __construct(
        public string $clientName,
        public array $redirectUris,
        public ?array $scopes,
        public ?string $applicationType,
    ) {}

    /** @return array<string, int|string|list<string>> */
    public function responseMetadata(string $clientId, ?int $issuedAt): array
    {
        $metadata = [
            'client_id' => $clientId,
            'client_id_issued_at' => $issuedAt ?? time(),
            'client_name' => $this->clientName,
            'redirect_uris' => $this->redirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];

        if ($this->scopes !== null) {
            $metadata['scope'] = implode(' ', $this->scopes);
        }
        if ($this->applicationType !== null) {
            $metadata['application_type'] = $this->applicationType;
        }

        return $metadata;
    }
}
