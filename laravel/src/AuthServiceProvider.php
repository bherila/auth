<?php

namespace BWH\Auth;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Services\NullAuthAuditLogger;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/bherila-auth.php', 'bherila-auth');

        $this->app->bind(AuthUserPolicy::class, DefaultAuthUserPolicy::class);
        $this->app->bind(AuthAuditLogger::class, NullAuthAuditLogger::class);
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'bherila-auth');

        $this->publishes([
            __DIR__.'/../config/bherila-auth.php' => config_path('bherila-auth.php'),
        ], 'bherila-auth-config');

        $this->publishes([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'bherila-auth-migrations');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/bherila-auth'),
        ], 'bherila-auth-views');

        if (config('bherila-auth.routes.enabled', true) && config('bherila-auth.routes.passkeys', true)) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/passkeys.php');
        }

        if (config('bherila-auth.routes.enabled', true) && $this->shouldLoadAuthRoutes()) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/auth.php');
        }
    }

    private function shouldLoadAuthRoutes(): bool
    {
        return config('bherila-auth.routes.password_resets', true)
            || config('bherila-auth.routes.change_password', true)
            || config('bherila-auth.routes.two_factor', true);
    }
}
