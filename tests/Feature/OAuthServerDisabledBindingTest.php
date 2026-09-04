<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\OAuth\Server\ResourceAccessToken;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use BWH\Auth\Tests\TestCase;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Bridge\Client as PassportBridgeClient;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;

final class OAuthServerDisabledBindingTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, PassportServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('bherila-auth.oauth_server.enabled', false);
    }

    protected function setUp(): void
    {
        Passport::useAccessTokenEntity(AccessToken::class);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        Passport::useAccessTokenEntity(AccessToken::class);

        parent::tearDown();
    }

    public function test_disabled_server_keeps_validation_binding_without_changing_unbound_issuance(): void
    {
        $repository = app(PassportAccessTokenRepository::class);

        self::assertInstanceOf(ResourceAccessTokenRepository::class, $repository);
        $token = $repository->getNewToken(new PassportBridgeClient('legacy-client'), []);
        self::assertInstanceOf(AccessToken::class, $token);
        self::assertNotInstanceOf(ResourceAccessToken::class, $token);
    }
}
