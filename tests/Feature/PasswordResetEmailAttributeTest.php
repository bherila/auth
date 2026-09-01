<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Tests\Fixtures\CustomEmailUser;
use BWH\Auth\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;

class PasswordResetEmailAttributeTest extends TestCase
{
    /**
     * @param  \Illuminate\Foundation\Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', CustomEmailUser::class);
        $app['config']->set('bherila-auth.users.model', CustomEmailUser::class);
        $app['config']->set('bherila-auth.users.email_attribute', 'login_email');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::table('users', function (Blueprint $table): void {
            $table->string('login_email')->nullable();
        });
    }

    private function user(): CustomEmailUser
    {
        return CustomEmailUser::create([
            'name' => 'Test',
            'email' => 'not-the-login-address@example.com',
            'login_email' => 'user@example.com',
            'password' => bcrypt('old-password'),
        ]);
    }

    public function test_reset_link_is_sent_to_the_configured_email_column(): void
    {
        Mail::fake();

        $this->user();

        $this->postJson('/api/auth/forgot-password', ['email' => 'user@example.com'])
            ->assertOk()
            ->assertJson(['success' => true]);

        Mail::assertSent(PasswordResetConfirmationMail::class, function ($mail) {
            return $mail->hasTo('user@example.com');
        });
    }

    public function test_reset_completes_against_the_configured_email_column(): void
    {
        Mail::fake();

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
    }
}
