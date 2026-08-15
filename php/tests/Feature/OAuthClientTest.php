<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use BWH\Auth\Tests\TestCase;

class OAuthClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['bherila-auth.oauth_client' => [
            'provider' => 'test-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
        ]]);

        Route::middleware('web')->group(function (): void {
            Route::get('/oauth/start-test', fn (Request $request, OAuthClient $client) => $client->redirect($request));
            Route::get('/oauth/callback-test', function (Request $request, OAuthClient $client) {
                $identity = $client->identityFromCallback($request);

                return response()->json([
                    'provider' => $identity->provider,
                    'subject' => $identity->subject,
                    'name' => $identity->name,
                    'email' => $identity->email,
                ]);
            });
        });
    }

    public function test_redirect_creates_state_and_pkce_challenge(): void
    {
        $response = $this->get('/oauth/start-test');

        $response->assertRedirectContains('https://identity.example.test/oauth/authorize?');
        $response->assertSessionHas('oauth.login.state');
        $response->assertSessionHas('oauth.login.code_verifier');

        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('identity:read', $query['scope']);
        $this->assertSame(session('oauth.login.state'), $query['state']);
    }

    public function test_provider_metadata_is_exposed_from_the_validated_shared_config(): void
    {
        $client = app(OAuthClient::class);

        $this->assertSame('test-provider', $client->providerName());
        $this->assertSame('https://identity.example.test', $client->providerBaseUrl());
    }

    public function test_callback_exchanges_code_and_returns_validated_identity(): void
    {
        Http::fake([
            'https://identity.example.test/oauth/token' => Http::response(['access_token' => 'test-access-token']),
            'https://identity.example.test/api/oauth/user' => Http::response([
                'sub' => 'subject-123',
                'name' => ' Synthetic User ',
                'email' => 'SYNTHETIC@EXAMPLE.TEST',
            ]),
        ]);

        $response = $this->withSession([
            'oauth.login.state' => 'expected-state',
            'oauth.login.code_verifier' => 'expected-verifier',
        ])->get('/oauth/callback-test?state=expected-state&code=authorization-code');

        $response->assertOk()->assertExactJson([
            'provider' => 'test-provider',
            'subject' => 'subject-123',
            'name' => 'Synthetic User',
            'email' => 'synthetic@example.test',
        ]);

        Http::assertSentCount(2);
        Http::assertSent(fn ($request): bool => $request->url() === 'https://identity.example.test/oauth/token'
            && $request['code_verifier'] === 'expected-verifier');
    }

    public function test_callback_rejects_invalid_state_before_network_requests(): void
    {
        Http::fake();

        $this->withSession([
            'oauth.login.state' => 'expected-state',
            'oauth.login.code_verifier' => 'expected-verifier',
        ])->get('/oauth/callback-test?state=wrong-state&code=authorization-code')->assertForbidden();

        Http::assertNothingSent();
    }
}
