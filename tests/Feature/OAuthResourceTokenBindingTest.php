<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\OAuth\Server\ResourceAccessToken;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use BWH\Auth\Tests\Fixtures\User;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Client;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use BWH\Auth\Tests\TestCase;

final class OAuthResourceTokenBindingTest extends TestCase
{
    private const ISSUER = 'https://auth.example.test';

    private const RESOURCE = 'https://auth.example.test/mcp';

    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        [$privateKey, $publicKey] = $this->passportKeys();
        $app['config']->set('app.url', self::ISSUER);
        $app['config']->set('passport.private_key', $privateKey);
        $app['config']->set('passport.public_key', $publicKey);
        $app['config']->set('passport.middleware', ['web']);
        $app['config']->set('auth.guards.api', [
            'driver' => 'passport',
            'provider' => 'users',
        ]);
        $app['config']->set('bherila-auth.oauth_server.enabled', true);
        $app['config']->set('bherila-auth.oauth_server.issuer', self::ISSUER);
        $app['config']->set('bherila-auth.oauth_server.resource', self::RESOURCE);
        $app['config']->set('bherila-auth.oauth_server.scopes', [
            'mcp:use' => 'Connect through MCP',
            'identity:read' => 'Read identity',
        ]);
        $app['config']->set('bherila-auth.oauth_server.resource_required_scope', 'mcp:use');
        $app['config']->set('bherila-auth.oauth_server.resource_required_scopes', []);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.required_columns', [
            'dynamically_registered_at',
            'scopes',
        ]);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.scopes_column', 'scopes');
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.enforce_registered_scopes', true);
        $app['config']->set('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');

        Passport::$deviceCodeGrantEnabled = false;
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../../vendor/laravel/passport/database/migrations');
        parent::defineDatabaseMigrations();
    }

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan([
            'mcp:use' => 'Connect through MCP',
            'identity:read' => 'Read identity',
        ]);
        Passport::defaultScopes([]);
        Passport::authorizationView('bherila-auth::oauth.authorize');

        // This also documents the concrete Passport extension points used by the
        // package's opt-in provider.
        $this->assertInstanceOf(ResourceAccessTokenRepository::class, app(PassportAccessTokenRepository::class));
        $this->assertInstanceOf(ResourceAuthCodeRepository::class, app(PassportAuthCodeRepository::class));
        $this->assertInstanceOf(ResourceRefreshTokenRepository::class, app(PassportRefreshTokenRepository::class));

        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.authorizations.deny', 'passport.token'] as $name) {
            $route = Route::getRoutes()->getByName($name);
            if ($route !== null) {
                $route->middleware([
                    EnforceOAuthPkce::class,
                    EnforceOAuthResourceIndicator::class,
                ]);
            }
        }

        Route::get('/mcp', fn () => response()->json(['ok' => true]))->middleware('auth:api');
        Route::post('/oauth/register', OAuthDynamicClientRegistrationController::class);
    }

    protected function tearDown(): void
    {
        Passport::useAccessTokenEntity(AccessToken::class);
        Passport::useClientModel(Client::class);

        parent::tearDown();
    }

    public function test_resource_survives_authorization_code_token_and_refresh_lifecycle(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $verifier = str_repeat('v', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $authorization = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'state' => 'state-123',
        ]));
        $authorization->assertOk();

        $authToken = session('authToken');
        $this->assertIsString($authToken);
        $approval = $this->actingAs($user)->post('/oauth/authorize', [
            'auth_token' => $authToken,
        ]);
        $approval->assertRedirect();

        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);
        $this->assertArrayHasKey('code', $redirectQuery);

        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ]);
        $token->assertOk();
        $accessToken = (string) $token->json('access_token');
        $refreshToken = (string) $token->json('refresh_token');
        $claims = OAuthResourceIndicator::tokenClaims($accessToken);

        $this->assertContains(self::RESOURCE, $claims['aud'] ?? []);
        $this->assertSame(self::ISSUER, $claims['iss'] ?? null);
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $storedToken = Passport::token()->newQuery()->where('client_id', $client->getKey())->firstOrFail();
        $this->assertSame(self::RESOURCE, $storedToken->resource_uri);

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$accessToken])->assertOk();

        $refresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
        ]);
        $refresh->assertOk();
        $refreshedAccessToken = (string) $refresh->json('access_token');
        $refreshedClaims = OAuthResourceIndicator::tokenClaims($refreshedAccessToken);
        $this->assertContains(self::RESOURCE, $refreshedClaims['aud'] ?? []);
        $this->assertSame(self::RESOURCE, $refreshedClaims['resource'] ?? null);
        $this->assertSame(
            self::RESOURCE,
            Passport::token()->newQuery()->whereKey($claims['jti'])->value('resource_uri'),
        );
        $this->assertSame(
            self::RESOURCE,
            Passport::token()->newQuery()->whereKey($refreshedClaims['jti'])->value('resource_uri'),
        );
    }

    public function test_resource_is_required_and_cannot_be_changed_at_each_grant_boundary(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $verifier = str_repeat('x', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query = [
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'scope' => 'mcp:use',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query))
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_target');
        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query + ['resource' => 'https://other.example.test/mcp']))
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_target');

        $auth = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($query + ['resource' => self::RESOURCE]));
        $authToken = (string) session('authToken');
        $approval = $this->actingAs($user)->post('/oauth/authorize', ['auth_token' => $authToken]);
        $approval->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);

        $missingResource = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
        ]);
        $missingResource->assertStatus(400);

        // The failed attempt did not consume the code, so the client can retry
        // with the resource bound to its original authorization request.
        $validToken = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://127.0.0.1:1455/callback',
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ])->assertOk();
        $refreshToken = (string) $validToken->json('refresh_token');

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => 'https://other.example.test/mcp',
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
            'scope' => 'mcp:use identity:read',
        ])->assertStatus(400);

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $refreshToken,
            'resource' => self::RESOURCE,
        ])->assertOk();

        $this->assertNotNull($auth);
    }

    public function test_a_bound_token_is_rejected_for_a_different_resource_and_for_a_different_issuer(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertOk();

        config(['bherila-auth.oauth_server.resource' => 'https://other.example.test/mcp']);
        Auth::forgetGuards();
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();

        config(['bherila-auth.oauth_server.resource' => self::RESOURCE]);
        config(['bherila-auth.oauth_server.issuer' => 'https://wrong.example.test']);
        Auth::forgetGuards();
        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();
    }

    public function test_revocation_is_enforced_by_the_package_resource_repository(): void
    {
        [$user, $client] = $this->userAndPublicClient(['mcp:use']);
        $token = $this->issueToken($user, $client);
        $serialized = (string) $token->json('access_token');
        $tokenId = (string) (OAuthResourceIndicator::tokenClaims($serialized)['jti'] ?? '');

        Passport::token()->newQuery()->whereKey($tokenId)->update(['revoked' => true]);

        $this->getJson('/mcp', ['Authorization' => 'Bearer '.$serialized])->assertUnauthorized();
    }

    public function test_dcr_creates_a_public_client_without_a_secret_and_preserves_registered_scope_limits(): void
    {
        $redirectUri = 'http://127.0.0.1:39053/callback/BKj9umzr4ef_';
        $user = User::query()->create([
            'name' => 'DCR User',
            'email' => 'dcr@example.test',
            'password' => 'not-used',
        ]);
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'Codex CLI',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use',
            'software_id' => 'ignored',
        ]);
        $response->assertCreated()
            ->assertJsonPath('client_name', 'Codex CLI')
            ->assertJsonPath('token_endpoint_auth_method', 'none')
            ->assertJsonMissingPath('client_secret');

        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertNull($client->secret);
        $this->assertNotNull($client->dynamically_registered_at);
        $this->assertSame(['mcp:use'], $client->scopes);
        $this->assertFalse($client->firstParty());
        $this->assertFalse($client->skipsAuthorization($user, Passport::scopesFor(['mcp:use'])));

        $challenge = rtrim(strtr(base64_encode(hash('sha256', str_repeat('p', 43), true)), '+/', '-_'), '=');
        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => 'http://localhost:39053/callback/BKj9umzr4ef_',
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'identity:read',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertStatus(400)->assertJsonPath('error', 'invalid_scope');

        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => true]);
        $authorizationError = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'identity:read',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        $authorizationError->assertRedirect();
        $this->assertStringContainsString(
            'error=invalid_scope',
            (string) $authorizationError->headers->get('Location'),
        );
        $this->assertStringContainsString(
            'iss='.rawurlencode(self::ISSUER),
            (string) $authorizationError->headers->get('Location'),
        );
        config(['bherila-auth.oauth_server.authorization_response_issuer.enabled' => false]);

        $token = $this->issueToken($user, $client, $redirectUri);
        $token->assertJsonStructure(['access_token', 'refresh_token']);

        config(['bherila-auth.oauth_server.enabled' => false]);
        $this->postJson('/oauth/register', [
            'client_name' => 'Disabled Client',
            'redirect_uris' => ['https://client.example.test/callback'],
        ])->assertNotFound();
    }

    public function test_hosted_public_registration_completes_the_resource_bound_authorization_flow(): void
    {
        $redirectUri = 'https://chatgpt.com/connector_platform_oauth_redirect';
        $user = User::query()->create([
            'name' => 'Hosted Client User',
            'email' => 'hosted-client@example.test',
            'password' => 'not-used',
        ]);
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'ChatGPT',
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'application_type' => 'web',
            'scope' => 'mcp:use',
        ]);
        $response->assertCreated()
            ->assertJsonPath('client_name', 'ChatGPT')
            ->assertJsonPath('application_type', 'web')
            ->assertJsonPath('token_endpoint_auth_method', 'none')
            ->assertJsonMissingPath('client_secret');

        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertFalse($client->firstParty());

        $token = $this->issueToken($user, $client, $redirectUri)->assertOk();
        $claims = OAuthResourceIndicator::tokenClaims((string) $token->json('access_token'));
        $this->assertSame(self::ISSUER, $claims['iss'] ?? null);
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $this->assertContains(self::RESOURCE, $claims['aud'] ?? []);
    }

    /** @return array{User, Client} */
    private function userAndPublicClient(array $scopes): array
    {
        $user = User::query()->create([
            'name' => 'MCP User',
            'email' => 'mcp@example.test',
            'password' => 'not-used',
        ]);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Public MCP Client',
            ['http://127.0.0.1:1455/callback'],
            confidential: false,
        );
        $client->forceFill([
            'dynamically_registered_at' => now(),
            'scopes' => $scopes,
        ])->save();

        return [$user, $client->fresh()];
    }

    private function issueToken(
        User $user,
        Client $client,
        string $redirectUri = 'http://127.0.0.1:1455/callback',
    ): \Illuminate\Testing\TestResponse
    {
        $verifier = str_repeat('z', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $authorization = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'scope' => 'mcp:use',
            'resource' => self::RESOURCE,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
        $authorization->assertOk();
        $approval = $this->actingAs($user)->post('/oauth/authorize', [
            'auth_token' => (string) session('authToken'),
        ]);
        $approval->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectQuery);

        return $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'redirect_uri' => $redirectUri,
            'code' => $redirectQuery['code'],
            'code_verifier' => $verifier,
            'resource' => self::RESOURCE,
        ])->assertOk();
    }

    /** @return array{string, string} */
    private function passportKeys(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        if ($key === false || ! openssl_pkey_export($key, $privateKey)) {
            throw new \RuntimeException('Unable to create Passport test keys.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ! is_string($details['key'] ?? null)) {
            throw new \RuntimeException('Unable to read Passport test public key.');
        }

        return [$privateKey, $details['key']];
    }
}
