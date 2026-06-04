<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

class LoginThrottleTest extends TestCase
{
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    private function user(string $email = 'user@example.com'): User
    {
        return User::create([
            'name' => 'Test User',
            'email' => $email,
            'password' => bcrypt('secret'),
        ]);
    }

    private function request(string $ip = '198.51.100.10'): Request
    {
        return Request::create('/login', 'POST', server: [
            'REMOTE_ADDR' => $ip,
            'HTTP_USER_AGENT' => 'ThrottleTest/1.0',
        ]);
    }

    private function enableThrottle(int $maxAttempts = 3, int $decayMinutes = 10): void
    {
        config([
            'bherila-auth.throttle.enabled' => true,
            'bherila-auth.throttle.max_attempts' => $maxAttempts,
            'bherila-auth.throttle.decay_minutes' => $decayMinutes,
        ]);
    }

    public function test_disabled_by_default_allows_even_after_failed_logins(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');

        foreach (range(1, 5) as $_) {
            app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'USER@example.com', 'Invalid credentials');
        }

        $state = app(LoginThrottle::class)->inspect($this->request(), null, 'user@example.com');

        $this->assertFalse($state->enabled);
        $this->assertFalse($state->locked);
        $this->assertTrue($state->allowsLogin());
    }

    public function test_enabled_throttle_locks_after_configured_failures_for_same_email_and_ip(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 3, decayMinutes: 10);

        foreach (range(1, 3) as $_) {
            app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.10'), null, 'USER@example.com', 'Invalid credentials');
        }

        $state = app(LoginThrottle::class)->inspect($this->request('203.0.113.10'), null, 'user@example.com');

        $this->assertTrue($state->enabled);
        $this->assertTrue($state->locked);
        $this->assertFalse($state->allowsLogin());
        $this->assertSame(3, $state->attempts);
        $this->assertSame(0, $state->remaining);
        $this->assertSame(600, $state->availableInSeconds());
        $this->assertSame('2026-06-04 12:10:00', $state->retryAt?->format('Y-m-d H:i:s'));
    }

    public function test_successful_login_resets_failures_for_the_same_key(): void
    {
        $this->enableThrottle(maxAttempts: 3, decayMinutes: 10);
        $user = $this->user('user@example.com');

        Carbon::setTestNow('2026-06-04 12:00:00');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        Carbon::setTestNow('2026-06-04 12:01:00');
        app(AuthAuditLogger::class)->loginSucceeded($this->request(), $user);

        Carbon::setTestNow('2026-06-04 12:02:00');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        $state = app(LoginThrottle::class)->inspect($this->request(), null, 'USER@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(2, $state->attempts);
        $this->assertSame(1, $state->remaining);
    }

    public function test_failures_for_other_email_or_ip_do_not_count(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        app(AuthAuditLogger::class)->loginFailed($this->request('198.51.100.10'), null, 'target@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('198.51.100.99'), null, 'target@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('198.51.100.10'), null, 'other@example.com', 'Invalid credentials');

        $state = app(LoginThrottle::class)->inspect($this->request('198.51.100.10'), null, 'TARGET@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(1, $state->attempts);
        $this->assertSame(1, $state->remaining);
    }

    public function test_old_failures_outside_decay_window_do_not_count(): void
    {
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        Carbon::setTestNow('2026-06-04 11:30:00');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        Carbon::setTestNow('2026-06-04 12:00:00');
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        $state = app(LoginThrottle::class)->inspect($this->request(), null, 'user@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(1, $state->attempts);
    }

    public function test_record_blocked_writes_login_blocked_audit_row(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 1, decayMinutes: 10);

        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.50'), null, 'user@example.com', 'Invalid credentials');

        $throttle = app(LoginThrottle::class);
        $state = $throttle->inspect($this->request('203.0.113.50'), null, 'user@example.com');
        $throttle->recordBlocked($this->request('203.0.113.50'), null, 'user@example.com', 'password', $state);

        $blocked = AuthAuditLog::query()
            ->where('event', AuthAuditLog::EVENT_LOGIN_BLOCKED)
            ->firstOrFail();

        $this->assertSame('password', $blocked->auth_method);
        $this->assertFalse($blocked->succeeded);
        $this->assertTrue($blocked->is_suspicious);
        $this->assertSame('user@example.com', $blocked->email);
        $this->assertSame('203.0.113.50', $blocked->ip_address);
        $this->assertSame('Too many login attempts.', $blocked->reason);
        $this->assertSame(1, $blocked->metadata['attempts']);
        $this->assertSame(1, $throttle->inspect($this->request('203.0.113.50'), null, 'user@example.com')->attempts);
    }

    public function test_record_blocked_can_be_disabled(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 1, decayMinutes: 10);
        config(['bherila-auth.throttle.record_blocked' => false]);

        app(LoginThrottle::class)->recordBlocked($this->request(), null, 'user@example.com');

        $this->assertSame(0, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_LOGIN_BLOCKED)->count());
    }

    public function test_record_blocked_does_not_write_when_key_is_not_locked(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        app(LoginThrottle::class)->recordBlocked($this->request(), null, 'user@example.com');

        $this->assertSame(0, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_LOGIN_BLOCKED)->count());
    }
}
