<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\OAuth\Server\DynamicClientRegistrationValidator;
use BWH\Auth\OAuth\Server\InvalidClientMetadata;
use BWH\Auth\OAuth\Server\OAuthAuthorizationStateStore;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;

class OAuthServerHelpersTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.name' => 'Synthetic App',
            'bherila-auth.oauth_server' => [
                'issuer' => 'https://auth.example.test',
                'resource' => 'https://auth.example.test/api/v1',
                'authorization_endpoint' => 'https://auth.example.test/oauth/authorize',
                'token_endpoint' => 'https://auth.example.test/oauth/token',
                'registration_endpoint' => 'https://auth.example.test/oauth/register',
                'scopes' => [
                    'identity:read' => 'Read identity',
                    'mcp:use' => 'Connect through MCP',
                ],
                'token_endpoint_auth_methods' => ['none'],
                'resource_required_scope' => 'mcp:use',
                'dynamic_clients' => [
                    'enforce_registered_scopes' => false,
                ],
                'authorization_state' => [
                    'cache_prefix' => 'test-oauth-resource:',
                    'ttl_seconds' => 300,
                ],
                'consent' => [
                    'app_name' => 'Synthetic App',
                    'heading' => 'Connect :client to :app?',
                    'intro' => 'Request access to :app.',
                    'identity' => true,
                    'trust_warning' => 'Trust this client only if you recognize it.',
                    'dynamic_client_warning' => 'This client registered automatically. Return to:',
                    'policy_notice' => 'Existing permissions continue to apply.',
                    'approve_label' => 'Authorize',
                    'deny_label' => 'Cancel',
                ],
            ],
        ]);

        Route::post('/oauth/approve-test', fn () => 'approved')
            ->name('passport.authorizations.approve');
        Route::delete('/oauth/deny-test', fn () => 'denied')
            ->name('passport.authorizations.deny');
        Route::get('/metadata/authorization-test', [OAuthMetadataController::class, 'authorizationServer']);
        Route::get('/metadata/resource-test', [OAuthMetadataController::class, 'protectedResource']);
    }

    public function test_metadata_is_built_from_the_application_scope_catalog(): void
    {
        $this->getJson('/metadata/authorization-test')
            ->assertOk()
            ->assertExactJson([
                'issuer' => 'https://auth.example.test',
                'authorization_endpoint' => 'https://auth.example.test/oauth/authorize',
                'token_endpoint' => 'https://auth.example.test/oauth/token',
                'registration_endpoint' => 'https://auth.example.test/oauth/register',
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'token_endpoint_auth_methods_supported' => ['none'],
                'scopes_supported' => ['identity:read', 'mcp:use'],
                'resource_indicators_supported' => true,
            ]);
        $this->assertStringContainsString('public', (string) $this->get('/metadata/authorization-test')->headers->get('Cache-Control'));

        $this->getJson('/metadata/resource-test')->assertOk()->assertExactJson([
            'resource' => 'https://auth.example.test/api/v1',
            'authorization_servers' => ['https://auth.example.test'],
            'scopes_supported' => ['identity:read', 'mcp:use'],
            'bearer_methods_supported' => ['header'],
        ]);

        config([
            'bherila-auth.oauth_server.issuer' => 'https://auth.example.test/tenant/',
            'bherila-auth.oauth_server.resource' => 'https://auth.example.test/api/v1/',
        ]);
        $this->getJson('/metadata/authorization-test')
            ->assertJsonPath('issuer', 'https://auth.example.test/tenant/');
        $this->getJson('/metadata/resource-test')
            ->assertJsonPath('resource', 'https://auth.example.test/api/v1/');
        $this->assertSame('https://auth.example.test/api/v1/', OAuthResourceIndicator::resource());
        $this->assertTrue(OAuthResourceIndicator::isConfiguredResource('https://auth.example.test/api/v1/'));

        config([
            'bherila-auth.oauth_server.issuer' => 'https://auth.example.test',
            'bherila-auth.oauth_server.resource' => 'https://auth.example.test/api/v1',
        ]);
    }

    public function test_dynamic_registration_accepts_codex_native_metadata_and_ignores_unknown_fields(): void
    {
        $request = $this->jsonRequest([
            'client_name' => 'Codex CLI',
            'redirect_uris' => ['http://127.0.0.1:1455/callback'],
            'grant_types' => ['refresh_token', 'authorization_code'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use identity:read',
            'application_type' => 'native',
            'software_id' => 'ignored-standard-metadata',
        ]);

        $registration = app(DynamicClientRegistrationValidator::class)->validate(
            $request,
            ['identity:read', 'mcp:use'],
        );

        $this->assertSame('Codex CLI', $registration->clientName);
        $this->assertSame(['http://127.0.0.1:1455/callback'], $registration->redirectUris);
        $this->assertSame(['mcp:use', 'identity:read'], $registration->scopes);
        $this->assertSame('native', $registration->applicationType);
        $this->assertSame('mcp:use identity:read', $registration->responseMetadata('client-id', 123)['scope']);
    }

    #[DataProvider('invalidRegistrationProvider')]
    public function test_dynamic_registration_rejects_unsafe_or_unsupported_metadata(array $metadata): void
    {
        $this->expectException(InvalidClientMetadata::class);

        app(DynamicClientRegistrationValidator::class)->validate(
            $this->jsonRequest($metadata),
            ['identity:read', 'mcp:use'],
        );
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function invalidRegistrationProvider(): iterable
    {
        $valid = [
            'client_name' => 'Synthetic Client',
            'redirect_uris' => ['https://client.example.test/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];

        yield 'non-loopback HTTP' => [[...$valid, 'redirect_uris' => ['http://client.example.test/callback']]];
        yield 'fragment' => [[...$valid, 'redirect_uris' => ['https://client.example.test/callback#fragment']]];
        yield 'unknown scope' => [[...$valid, 'scope' => 'mcp:use records:delete']];
        yield 'confidential client' => [[...$valid, 'token_endpoint_auth_method' => 'client_secret_post']];
        yield 'web application type' => [[...$valid, 'application_type' => 'web']];
        yield 'control character in name' => [[...$valid, 'client_name' => "Synthetic\nClient"]];
    }

    public function test_pkce_middleware_fails_locally_without_reflecting_caller_input(): void
    {
        $request = Request::create('/oauth/authorize', 'GET', [
            'code_challenge' => 'synthetic',
            'code_challenge_method' => 'plain',
            'redirect_uri' => 'https://untrusted.example.test/callback',
        ]);
        $request->setRouteResolver(static function (): RoutingRoute {
            return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                ->name('passport.authorizations.authorize');
        });

        $response = app(EnforceOAuthPkce::class)->handle($request, fn () => response('next'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringNotContainsString('untrusted.example.test', (string) $response->getContent());
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function test_resource_middleware_applies_default_scopes_and_rejects_unconfigured_token_targets(): void
    {
        Passport::defaultScopes(['mcp:use']);

        try {
            $authorization = Request::create('/oauth/authorize', 'GET');
            $authorization->setRouteResolver(static function (): RoutingRoute {
                return (new RoutingRoute('GET', '/oauth/authorize', fn () => 'next'))
                    ->name('passport.authorizations.authorize');
            });
            $authorizationResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($authorization, fn () => response('next'));
            $this->assertSame(400, $authorizationResponse->getStatusCode());
            $this->assertStringContainsString('invalid_target', (string) $authorizationResponse->getContent());

            $authorization->query->set('scope', '   ');
            $emptyScopeResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($authorization, fn () => response('next'));
            $this->assertSame(400, $emptyScopeResponse->getStatusCode());
            $this->assertStringContainsString('invalid_target', (string) $emptyScopeResponse->getContent());

            $token = Request::create('/oauth/token', 'POST', [
                'resource' => 'https://other.example.test/api/v1',
            ]);
            $token->setRouteResolver(static function (): RoutingRoute {
                return (new RoutingRoute('POST', '/oauth/token', fn () => 'next'))
                    ->name('passport.token');
            });
            $tokenResponse = app(EnforceOAuthResourceIndicator::class)
                ->handle($token, fn () => response('next'));
            $this->assertSame(400, $tokenResponse->getStatusCode());

            $token->request->set('resource', 'https://auth.example.test/api/v1/');
            $accepted = app(EnforceOAuthResourceIndicator::class)
                ->handle($token, fn (Request $request) => response(
                    OAuthResourceIndicator::validatedFor($request) ?? 'missing',
                ));
            $this->assertSame('https://auth.example.test/api/v1', $accepted->getContent());
        } finally {
            Passport::defaultScopes([]);
        }
    }

    public function test_resource_indicator_is_canonical_and_authorization_state_falls_back_to_cache(): void
    {
        $this->assertSame(
            'https://auth.example.test/api/v1',
            OAuthResourceIndicator::canonicalize('HTTPS://AUTH.EXAMPLE.TEST:443/api/v1/'),
        );
        $this->assertTrue(OAuthResourceIndicator::isConfiguredResource('https://auth.example.test/api/v1/'));
        $this->assertNull(OAuthResourceIndicator::canonicalize('https://user@auth.example.test/api/v1'));

        $state = app(OAuthAuthorizationStateStore::class);
        $state->rememberResource('synthetic-approval-token', OAuthResourceIndicator::resource());
        session()->forget('test-oauth-resource:'.hash('sha256', 'synthetic-approval-token'));

        $this->assertSame(OAuthResourceIndicator::resource(), $state->resourceFor('synthetic-approval-token'));
        $state->forgetResource('synthetic-approval-token');
        $this->assertNull($state->resourceFor('synthetic-approval-token'));
    }

    public function test_shared_consent_view_renders_identity_permissions_and_dynamic_redirect_warning(): void
    {
        $client = new class
        {
            public string $name = 'Synthetic Harness';

            public ?string $dynamically_registered_at = '2026-08-23 12:00:00';

            public ?string $registered_on = null;

            /** @var list<string> */
            public array $redirect_uris = ['http://127.0.0.1:1455/callback'];
        };
        $user = (object) ['name' => 'Synthetic User'];
        $scope = (object) ['description' => 'Connect through MCP'];
        $request = Request::create('/oauth/authorize', 'GET');

        $html = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => [$scope],
            'authToken' => 'synthetic-auth-token',
            'request' => $request,
        ])->render();

        $this->assertStringContainsString('Connect Synthetic Harness to Synthetic App?', $html);
        $this->assertStringContainsString('Signed in as Synthetic User.', $html);
        $this->assertStringContainsString('Connect through MCP', $html);
        $this->assertStringContainsString('http://127.0.0.1:1455/callback', $html);
        $this->assertStringContainsString('name="auth_token" value="synthetic-auth-token"', $html);

        config(['bherila-auth.oauth_server.dynamic_clients.registered_at_column' => 'registered_on']);
        $client->registered_on = '2026-08-23 12:00:00';
        $client->dynamically_registered_at = null;
        $configuredMarkerHtml = view('bherila-auth::oauth.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => [$scope],
            'authToken' => 'synthetic-auth-token',
            'request' => $request,
        ])->render();
        $this->assertStringContainsString('registered automatically', $configuredMarkerHtml);
    }

    /** @param array<string, mixed> $metadata */
    private function jsonRequest(array $metadata): Request
    {
        return Request::create(
            '/oauth/register',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($metadata, JSON_THROW_ON_ERROR),
        );
    }
}
