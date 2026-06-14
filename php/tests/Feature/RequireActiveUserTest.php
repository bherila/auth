<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class RequireActiveUserTest extends TestCase
{
    // --- DefaultAuthUserPolicy::canLogin() ---

    public function test_default_policy_allows_user_with_no_special_columns(): void
    {
        $user = User::create(['name' => 'Test', 'email' => 'a@example.com', 'password' => bcrypt('x')]);
        $policy = new DefaultAuthUserPolicy;

        $this->assertTrue($policy->canLogin($user, Request::create('/')));
    }

    public function test_default_policy_delegates_to_can_login_method_when_present(): void
    {
        $user = new class extends User
        {
            public function canLogin(): bool
            {
                return false;
            }
        };
        $user->forceFill(['name' => 'Test', 'email' => 'b@example.com', 'password' => bcrypt('x')]);
        $user->exists = true;

        $policy = new DefaultAuthUserPolicy;
        $this->assertFalse($policy->canLogin($user, Request::create('/')));
    }

    public function test_default_policy_uses_is_disabled_fallback(): void
    {
        $user = new class extends User
        {
            public bool $is_disabled = true;
        };
        $user->forceFill(['name' => 'Test', 'email' => 'c@example.com', 'password' => bcrypt('x')]);
        $user->exists = true;

        $policy = new DefaultAuthUserPolicy;
        $this->assertFalse($policy->canLogin($user, Request::create('/')));
    }

    public function test_default_policy_can_passkey_login_delegates_to_can_login(): void
    {
        $user = new class extends User
        {
            public function canLogin(): bool
            {
                return false;
            }
        };
        $user->forceFill(['name' => 'Test', 'email' => 'd@example.com', 'password' => bcrypt('x')]);
        $user->exists = true;

        $policy = new DefaultAuthUserPolicy;
        $this->assertFalse($policy->canPasskeyLogin($user, Request::create('/')));
    }

    // --- RequireActiveUser middleware ---

    public function test_middleware_passes_through_when_user_can_login(): void
    {
        $user = User::create(['name' => 'Test', 'email' => 'e@example.com', 'password' => bcrypt('x')]);

        $request = Request::create('/');
        $request->setUserResolver(fn () => $user);

        $middleware = new RequireActiveUser(app(AuthUserPolicy::class));
        $response = $middleware->handle($request, fn ($r) => response('ok'));

        $this->assertSame('ok', $response->getContent());
    }

    public function test_middleware_aborts_403_when_user_cannot_login(): void
    {
        $policy = new class extends DefaultAuthUserPolicy
        {
            public function canLogin(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        };

        $user = User::create(['name' => 'Test', 'email' => 'f@example.com', 'password' => bcrypt('x')]);

        $request = Request::create('/');
        $request->setUserResolver(fn () => $user);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\HttpException::class);

        $middleware = new RequireActiveUser($policy);
        $middleware->handle($request, fn ($r) => response('ok'));
    }

    public function test_middleware_passes_through_when_no_authenticated_user(): void
    {
        $request = Request::create('/');
        $request->setUserResolver(fn () => null);

        $middleware = new RequireActiveUser(app(AuthUserPolicy::class));
        $response = $middleware->handle($request, fn ($r) => response('ok'));

        $this->assertSame('ok', $response->getContent());
    }
}
