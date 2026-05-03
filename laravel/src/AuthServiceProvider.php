<?php

namespace Bherila\AuthLaravel;

use Bherila\AuthLaravel\Contracts\AuthAuditLogger;
use Bherila\AuthLaravel\Contracts\AuthUserPolicy;
use Bherila\AuthLaravel\Services\DefaultAuthUserPolicy;
use Bherila\AuthLaravel\Services\NullAuthAuditLogger;
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

        if (config('bherila-auth.routes.enabled', true)) {
            Route::prefix(config('bherila-auth.routes.prefix', 'api'))
                ->middleware(config('bherila-auth.routes.middleware', ['web']))
                ->group(__DIR__.'/../routes/passkeys.php');
        }
    }
}
