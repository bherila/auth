<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Concerns\ThrottlesLoginAttempts;
use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\LoginThrottleState;
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

    public function test_record_blocked_is_noop_when_throttle_disabled(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        // Throttle left disabled (the default): even a state that looks locked must not write.
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        app(LoginThrottle::class)->recordBlocked($this->request(), null, 'user@example.com');

        $this->assertSame(0, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_LOGIN_BLOCKED)->count());
    }

    public function test_zero_max_attempts_is_a_fail_safe_that_never_locks(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 0, decayMinutes: 10);

        foreach (range(1, 4) as $_) {
            app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');
        }

        $state = app(LoginThrottle::class)->inspect($this->request(), null, 'user@example.com');

        $this->assertFalse($state->locked);
        $this->assertTrue($state->allowsLogin());
    }

    public function test_second_factor_failures_do_not_count_toward_login_lockout(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        // One genuine password failure for this key.
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'user@example.com', 'Invalid credentials');

        // A real second-factor failure (different event AND auth_method) must be ignored.
        app(AuthAuditLogger::class)->twoFactorLoginFailed($this->request(), $this->user('user@example.com'), null, 'Wrong code');

        // And even a two_factor_failed row crafted to share the same email + IP +
        // 'password' method must be excluded by the EVENT filter, not by the key.
        AuthAuditLog::create([
            'event' => AuthAuditLog::EVENT_TWO_FACTOR_FAILED,
            'auth_method' => 'password',
            'succeeded' => false,
            'email' => 'user@example.com',
            'ip_address' => '198.51.100.10',
            'reason' => 'Wrong code',
        ]);

        $state = app(LoginThrottle::class)->inspect($this->request(), null, 'user@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(1, $state->attempts);
    }

    public function test_email_key_strategy_counts_failures_across_source_ips(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);
        config(['bherila-auth.throttle.key' => 'email']);

        // Same account, two different source IPs.
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.1'), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.2'), null, 'user@example.com', 'Invalid credentials');
        // A different account from a shared IP must not contribute.
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.1'), null, 'other@example.com', 'Invalid credentials');

        // Inspecting from a third, never-seen IP still locks because the key is the email.
        $state = app(LoginThrottle::class)->inspect($this->request('203.0.113.9'), null, 'user@example.com');

        $this->assertTrue($state->locked);
        $this->assertSame(2, $state->attempts);
    }

    public function test_ip_key_strategy_counts_failures_across_accounts(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);
        config(['bherila-auth.throttle.key' => 'ip']);

        // Same source IP, two different accounts (credential-stuffing shape).
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.5'), null, 'a@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.5'), null, 'b@example.com', 'Invalid credentials');
        // Same accounts from a different IP must not contribute.
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.6'), null, 'a@example.com', 'Invalid credentials');

        // Inspecting with a third, never-seen account still locks because the key is the IP.
        $state = app(LoginThrottle::class)->inspect($this->request('203.0.113.5'), null, 'c@example.com');

        $this->assertTrue($state->locked);
        $this->assertSame(2, $state->attempts);
    }

    public function test_email_ip_strategy_does_not_lock_when_only_one_dimension_matches(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        // Default strategy is email_ip.
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        // Two failures for the same account but from two different IPs.
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.1'), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.2'), null, 'user@example.com', 'Invalid credentials');

        // email_ip needs both to match, so neither source pair has reached the limit.
        $state = app(LoginThrottle::class)->inspect($this->request('203.0.113.1'), null, 'user@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(1, $state->attempts);
    }

    public function test_unknown_key_strategy_falls_back_to_email_ip(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);
        config(['bherila-auth.throttle.key' => 'totally-bogus']);

        // Treated as email_ip: differing IPs for one account must not lock.
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.1'), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.2'), null, 'user@example.com', 'Invalid credentials');

        $state = app(LoginThrottle::class)->inspect($this->request('203.0.113.1'), null, 'user@example.com');

        $this->assertFalse($state->locked);
        $this->assertSame(1, $state->attempts);
    }

    public function test_email_strategy_without_an_email_is_allowed(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 1, decayMinutes: 10);
        config(['bherila-auth.throttle.key' => 'email']);

        // No email to key on, and the strategy ignores IP, so there is no usable key.
        $state = app(LoginThrottle::class)->inspect($this->request(), null, null);

        $this->assertFalse($state->enabled);
        $this->assertFalse($state->locked);
        $this->assertTrue($state->allowsLogin());
    }

    public function test_malformed_client_ip_is_treated_as_no_ip(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 1, decayMinutes: 10);
        config(['bherila-auth.throttle.key' => 'ip']);

        // Rows written from a request whose IP could not be parsed are stored with a
        // NULL ip_address. A later request whose IP is also unparseable must not adopt
        // that NULL as its key and inherit every other unknown-IP failure.
        app(AuthAuditLogger::class)->loginFailed($this->request('not-an-ip-address'), null, 'user@example.com', 'Invalid credentials');

        $this->assertNull(AuthAuditLog::query()->value('ip_address'));

        $state = app(LoginThrottle::class)->inspect($this->request('still-not-an-ip'), null, 'someone-else@example.com');

        $this->assertFalse($state->enabled);
        $this->assertFalse($state->locked);
        $this->assertTrue($state->allowsLogin());
        $this->assertNull($state->ipAddress);
    }

    public function test_malformed_client_ip_does_not_widen_an_email_ip_key(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 2, decayMinutes: 10);

        // Two failures for this account from a real address, then a request whose IP
        // will not parse: the email matches but the IP dimension does not, so the pair
        // this strategy keys on is not the locked one.
        app(AuthAuditLogger::class)->loginFailed($this->request('198.51.100.10'), null, 'user@example.com', 'Invalid credentials');
        app(AuthAuditLogger::class)->loginFailed($this->request('198.51.100.10'), null, 'user@example.com', 'Invalid credentials');

        $state = app(LoginThrottle::class)->inspect($this->request('not-an-ip-address'), null, 'user@example.com');

        $this->assertSame(0, $state->attempts);
        $this->assertFalse($state->locked);
    }

    public function test_throttles_login_attempts_trait_delegates_to_the_service(): void
    {
        Carbon::setTestNow('2026-06-04 12:00:00');
        $this->enableThrottle(maxAttempts: 1, decayMinutes: 10);

        app(AuthAuditLogger::class)->loginFailed($this->request('203.0.113.70'), null, 'user@example.com', 'Invalid credentials');

        $controller = new class
        {
            use ThrottlesLoginAttempts;

            public function state(Request $request, ?string $email): LoginThrottleState
            {
                return $this->inspectLoginThrottle($request, null, $email);
            }

            public function block(Request $request, ?string $email, LoginThrottleState $state): void
            {
                $this->auditLoginBlocked($request, null, $email, 'password', $state);
            }
        };

        $state = $controller->state($this->request('203.0.113.70'), 'user@example.com');
        $this->assertTrue($state->locked);

        $controller->block($this->request('203.0.113.70'), 'user@example.com', $state);

        $this->assertSame(1, AuthAuditLog::query()->where('event', AuthAuditLog::EVENT_LOGIN_BLOCKED)->count());
    }
}
