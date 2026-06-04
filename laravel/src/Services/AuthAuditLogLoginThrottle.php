<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use BWH\Auth\Support\LoginThrottleState;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

class AuthAuditLogLoginThrottle implements LoginThrottle
{
    public function inspect(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password'): LoginThrottleState
    {
        $maxAttempts = $this->maxAttempts();
        $decayMinutes = $this->decayMinutes();
        $normalizedEmail = $this->normalizeEmail($email ?? $this->userEmail($user));
        $ipAddress = ClientIp::resolve($request);

        if (! $this->enabled() || $maxAttempts < 1 || $decayMinutes < 1 || ($normalizedEmail === null && $ipAddress === null)) {
            return LoginThrottleState::allowed(false, 0, $maxAttempts, null, $normalizedEmail, $ipAddress, $method);
        }

        $windowStart = now()->subMinutes($decayMinutes);
        $since = $this->latestSuccessAt($normalizedEmail, $ipAddress, $method, $windowStart) ?? $windowStart;
        $failureTimes = $this->keyedQuery($normalizedEmail, $ipAddress, $method)
            ->where('event', AuthAuditLog::EVENT_LOGIN_FAILED)
            ->where('created_at', '>=', $since)
            ->oldest('created_at')
            ->limit($maxAttempts)
            ->pluck('created_at');

        $attempts = $failureTimes->count();

        if ($attempts < $maxAttempts) {
            return LoginThrottleState::allowed(true, $attempts, $maxAttempts, $decayMinutes, $normalizedEmail, $ipAddress, $method);
        }

        $firstFailureAt = $failureTimes->first();
        $retryAt = $firstFailureAt instanceof Carbon
            ? $firstFailureAt->copy()->addMinutes($decayMinutes)
            : Carbon::parse((string) $firstFailureAt)->addMinutes($decayMinutes);

        return LoginThrottleState::locked($attempts, $maxAttempts, $decayMinutes, $retryAt, $normalizedEmail, $ipAddress, $method);
    }

    public function recordBlocked(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password', ?LoginThrottleState $state = null): void
    {
        if (! $this->enabled() || ! config('bherila-auth.throttle.record_blocked', true)) {
            return;
        }

        $state ??= $this->inspect($request, $user, $email, $method);

        if (! $state->locked) {
            return;
        }

        AuthAuditLog::create([
            'event' => AuthAuditLog::EVENT_LOGIN_BLOCKED,
            'auth_method' => $method,
            'succeeded' => false,
            'user_id' => $this->userId($user),
            'email' => $this->clamp($email ?? $this->userEmail($user), 255),
            'reason' => 'Too many login attempts.',
            'ip_address' => ClientIp::resolve($request),
            'user_agent' => $request->userAgent(),
            'session_id' => $request->hasSession() ? $request->session()->getId() : null,
            'is_suspicious' => true,
            'metadata' => [
                'attempts' => $state->attempts,
                'max_attempts' => $state->maxAttempts,
                'decay_minutes' => $state->decayMinutes,
                'retry_at' => $state->retryAt?->toIso8601String(),
            ],
        ]);
    }

    protected function enabled(): bool
    {
        return (bool) config('bherila-auth.throttle.enabled', false);
    }

    protected function maxAttempts(): int
    {
        return max(0, (int) config('bherila-auth.throttle.max_attempts', 5));
    }

    protected function decayMinutes(): int
    {
        return max(0, (int) config('bherila-auth.throttle.decay_minutes', 15));
    }

    protected function latestSuccessAt(?string $email, ?string $ipAddress, ?string $method, Carbon $windowStart): ?Carbon
    {
        $createdAt = $this->keyedQuery($email, $ipAddress, $method)
            ->where('event', AuthAuditLog::EVENT_LOGIN_SUCCEEDED)
            ->where('created_at', '>=', $windowStart)
            ->latest('created_at')
            ->value('created_at');

        return $createdAt === null ? null : Carbon::parse((string) $createdAt);
    }

    /**
     * @return Builder<AuthAuditLog>
     */
    protected function keyedQuery(?string $email, ?string $ipAddress, ?string $method): Builder
    {
        return AuthAuditLog::query()
            ->when($method !== null, fn (Builder $query) => $query->where('auth_method', $method))
            ->when($email !== null, fn (Builder $query) => $query->whereRaw('LOWER(email) = ?', [$email]))
            ->when($email === null, fn (Builder $query) => $query->whereNull('email'))
            ->when($ipAddress !== null, fn (Builder $query) => $query->where('ip_address', $this->packedIp($ipAddress)))
            ->when($ipAddress === null, fn (Builder $query) => $query->whereNull('ip_address'));
    }

    protected function normalizeEmail(?string $email): ?string
    {
        $email = trim((string) $email);

        return $email === '' ? null : Str::lower($email);
    }

    protected function userId(?Authenticatable $user): int|string|null
    {
        return $user?->getAuthIdentifier();
    }

    protected function userEmail(?Authenticatable $user): ?string
    {
        if ($user === null) {
            return null;
        }

        $email = data_get($user, config('bherila-auth.users.email_attribute', 'email'));

        return is_string($email) ? $email : null;
    }

    protected function packedIp(string $ipAddress): ?string
    {
        $packed = inet_pton($ipAddress);

        return $packed === false ? null : $packed;
    }

    protected function clamp(?string $value, int $limit): ?string
    {
        return $value === null ? null : mb_substr($value, 0, $limit);
    }
}
