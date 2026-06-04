<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Services\DatabaseAuthAuditLogger;
use BWH\Auth\Services\NullAuthAuditLogger;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;

class DatabaseAuthAuditLoggerTest extends TestCase
{
    private function user(string $email = 'user@example.com'): User
    {
        return User::create([
            'name' => 'Test User',
            'email' => $email,
            'password' => bcrypt('secret'),
        ]);
    }

    private function request(array $headers = [], string $ip = '198.51.100.10'): Request
    {
        $request = Request::create('/login', 'POST', server: ['REMOTE_ADDR' => $ip]);

        foreach ($headers as $key => $value) {
            $request->headers->set($key, $value);
        }

        return $request;
    }

    public function test_binding_resolves_database_logger_when_driver_is_database(): void
    {
        $this->assertInstanceOf(DatabaseAuthAuditLogger::class, app(AuthAuditLogger::class));
    }

    public function test_binding_resolves_null_logger_when_driver_is_not_database(): void
    {
        config(['bherila-auth.audit.driver' => 'null']);

        $this->assertInstanceOf(NullAuthAuditLogger::class, app(AuthAuditLogger::class));
    }

    public function test_login_succeeded_writes_a_row(): void
    {
        $user = $this->user();
        $request = $this->request(['User-Agent' => 'TestAgent/1.0'], '203.0.113.7');

        app(AuthAuditLogger::class)->loginSucceeded($request, $user, 'password');

        $log = AuthAuditLog::firstOrFail();
        $this->assertSame(AuthAuditLog::EVENT_LOGIN_SUCCEEDED, $log->event);
        $this->assertSame('password', $log->auth_method);
        $this->assertTrue($log->succeeded);
        $this->assertSame($user->id, $log->user_id);
        $this->assertSame('user@example.com', $log->email);
        $this->assertSame('203.0.113.7', $log->ip_address);
        $this->assertSame('TestAgent/1.0', $log->user_agent);
    }

    public function test_login_failed_for_unknown_email_has_null_user_id(): void
    {
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'ghost@example.com', 'Invalid credentials', 'password');

        $log = AuthAuditLog::firstOrFail();
        $this->assertNull($log->user_id);
        $this->assertSame('ghost@example.com', $log->email);
        $this->assertFalse($log->succeeded);
        $this->assertSame('Invalid credentials', $log->reason);
        $this->assertSame(AuthAuditLog::EVENT_LOGIN_FAILED, $log->event);
    }

    public function test_logged_out_writes_a_row(): void
    {
        $user = $this->user();

        app(AuthAuditLogger::class)->loggedOut($this->request(), $user);

        $log = AuthAuditLog::firstOrFail();
        $this->assertSame(AuthAuditLog::EVENT_LOGGED_OUT, $log->event);
        $this->assertTrue($log->succeeded);
        $this->assertSame($user->id, $log->user_id);
    }

    public function test_ipv4_round_trips_through_binary_cast(): void
    {
        $user = $this->user();
        app(AuthAuditLogger::class)->loginSucceeded($this->request([], '192.0.2.55'), $user);

        $this->assertSame('192.0.2.55', AuthAuditLog::firstOrFail()->ip_address);
    }

    public function test_ipv6_round_trips_through_binary_cast(): void
    {
        $user = $this->user();
        app(AuthAuditLogger::class)->loginSucceeded($this->request([], '2001:db8::1'), $user);

        $this->assertSame('2001:db8::1', AuthAuditLog::firstOrFail()->ip_address);
    }

    public function test_forwarded_headers_are_ignored_without_trusted_proxies(): void
    {
        $user = $this->user();
        $request = $this->request([
            'CF-Connecting-IP' => '8.8.8.8',
            'X-Forwarded-For' => '1.2.3.4',
        ], '203.0.113.9');

        app(AuthAuditLogger::class)->loginSucceeded($request, $user);

        // Spoofed proxy headers must not override the connection IP.
        $this->assertSame('203.0.113.9', AuthAuditLog::firstOrFail()->ip_address);
    }

    public function test_long_failure_reason_is_truncated_to_column_width(): void
    {
        app(AuthAuditLogger::class)->loginFailed($this->request(), null, 'ghost@example.com', str_repeat('x', 300), 'password');

        $this->assertSame(255, mb_strlen((string) AuthAuditLog::firstOrFail()->reason));
    }

    public function test_passkey_login_failed_stores_credential_id_in_metadata(): void
    {
        app(AuthAuditLogger::class)->passkeyLoginFailed($this->request(), null, 'cred-abc-123', 'bad signature');

        $log = AuthAuditLog::firstOrFail();
        $this->assertSame(AuthAuditLog::EVENT_PASSKEY_LOGIN_FAILED, $log->event);
        $this->assertSame('passkey', $log->auth_method);
        $this->assertFalse($log->succeeded);
        $this->assertSame('cred-abc-123', $log->metadata['credential_id']);
    }

    public function test_two_factor_reported_suspicious_marks_row_suspicious(): void
    {
        $user = $this->user();
        $attempt = (object) ['id' => 42, 'is_suspicious' => true];

        app(AuthAuditLogger::class)->twoFactorReportedSuspicious($this->request(), $user, $attempt);

        $log = AuthAuditLog::firstOrFail();
        $this->assertSame(AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS, $log->event);
        $this->assertTrue($log->is_suspicious);
        $this->assertSame(42, $log->metadata['attempt_id']);
    }

    public function test_null_driver_persists_nothing(): void
    {
        config(['bherila-auth.audit.driver' => 'null']);
        $user = $this->user();

        app(AuthAuditLogger::class)->loginSucceeded($this->request(), $user);

        $this->assertSame(0, AuthAuditLog::count());
    }
}
