<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Services\DefaultAuthUserPolicy;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;

class PasswordResetTest extends TestCase
{
    private function user(): User
    {
        return User::create([
            'name' => 'Test',
            'email' => 'user@example.com',
            'password' => bcrypt('old-password'),
        ]);
    }

    private function denyLogins(): void
    {
        $this->app->bind(AuthUserPolicy::class, fn () => new class extends DefaultAuthUserPolicy
        {
            public function canLogin(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        });
    }

    public function test_reset_link_is_mailed_and_the_framework_event_is_dispatched(): void
    {
        Mail::fake();
        Event::fake([PasswordResetLinkSent::class]);

        $this->user();

        $this->postJson('/api/auth/forgot-password', ['email' => 'user@example.com'])
            ->assertOk()
            ->assertJson(['success' => true]);

        Mail::assertSent(PasswordResetConfirmationMail::class);
        Event::assertDispatched(PasswordResetLinkSent::class);
    }

    public function test_a_second_request_is_throttled_by_the_broker(): void
    {
        Mail::fake();

        $this->user();

        $this->postJson('/api/auth/forgot-password', ['email' => 'user@example.com'])->assertOk();
        $this->postJson('/api/auth/forgot-password', ['email' => 'user@example.com'])
            ->assertOk()
            // Same generic body as the first request: the throttle must not become an
            // oracle for which addresses have an account.
            ->assertJson(['success' => true]);

        Mail::assertSentCount(1);
    }

    public function test_an_unknown_address_gets_the_same_response_and_no_mail(): void
    {
        Mail::fake();

        $this->postJson('/api/auth/forgot-password', ['email' => 'nobody@example.com'])
            ->assertOk()
            ->assertJson([
                'success' => true,
                'message' => 'If an account exists with this email, a password reset link has been sent.',
            ]);

        Mail::assertNothingSent();
    }

    public function test_reset_changes_the_password_and_logs_the_user_in(): void
    {
        Mail::fake();
        Event::fake([PasswordReset::class]);

        $user = $this->user();
        $token = Password::broker()->createToken($user);

        $this->postJson('/api/auth/reset-password', [
            'token' => $token,
            'email' => 'user@example.com',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertOk()->assertJson(['success' => true]);

        $this->assertTrue(Hash::check('new-password-1234', $user->fresh()->password));
        $this->assertAuthenticatedAs($user);
        Event::assertDispatched(PasswordReset::class);
    }

    public function test_reset_does_not_log_in_an_account_that_may_not_log_in(): void
    {
        Mail::fake();

        $user = $this->user();
        $token = Password::broker()->createToken($user);

        $this->denyLogins();

        $this->postJson('/api/auth/reset-password', [
            'token' => $token,
            'email' => 'user@example.com',
            'password' => 'new-password-1234',
            'password_confirmation' => 'new-password-1234',
        ])->assertOk()->assertJson(['success' => true]);

        // The reset still happens — a disabled account can take its password back —
        // but it does not hand out a session.
        $this->assertTrue(Hash::check('new-password-1234', $user->fresh()->password));
        $this->assertGuest();
    }
}
