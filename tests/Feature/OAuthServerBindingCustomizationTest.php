<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Tests\TestCase;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;

final class OAuthServerBindingCustomizationTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [AuthServiceProvider::class, ApplicationOAuthRepositoryProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('bherila-auth.oauth_server.enabled', true);
    }

    public function test_application_repository_overrides_survive_the_package_boot_fallback(): void
    {
        self::assertInstanceOf(ApplicationRepositoryOverride::class, app(PassportAccessTokenRepository::class));
        self::assertInstanceOf(ApplicationRepositoryOverride::class, app(PassportAuthCodeRepository::class));
        self::assertInstanceOf(ApplicationRepositoryOverride::class, app(PassportRefreshTokenRepository::class));
    }
}

final class ApplicationOAuthRepositoryProvider extends ServiceProvider
{
    public function register(): void
    {
        foreach ([
            PassportAccessTokenRepository::class,
            PassportAuthCodeRepository::class,
            PassportRefreshTokenRepository::class,
        ] as $repository) {
            $this->app->bind($repository, static fn (): ApplicationRepositoryOverride => new ApplicationRepositoryOverride);
        }
    }
}

final class ApplicationRepositoryOverride
{
}
