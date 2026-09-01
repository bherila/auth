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

        $key = $this->keyStrategy();
        $useEmail = $key !== 'ip';
        $useIp = $key !== 'email';

        // Every dimension the strategy names has to be present. Accepting a partial key
        // silently changes which strategy is in force: 'email_ip' with an IP that will
        // not resolve would fall back to counting an account's failures across every
        // request whose IP was unknown, which is both a wider key than was configured
        // and a way to lock an account out from behind an unresolvable address.
        $hasUsableKey = (! $useEmail || $normalizedEmail !== null)
            && (! $useIp || $ipAddress !== null);

        if (! $this->enabled() || $maxAttempts < 1 || $decayMinutes < 1 || ! $hasUsableKey) {
            return LoginThrottleState::allowed(false, 0, $maxAttempts, null, $normalizedEmail, $ipAddress, $method);
        }

        $windowStart = now()->subMinutes($decayMinutes);
        $since = $this->latestSuccessAt($useEmail, $useIp, $normalizedEmail, $ipAddress, $method, $windowStart) ?? $windowStart;
        $failureTimes = $this->keyedQuery($useEmail, $useIp, $normalizedEmail, $ipAddress, $method)
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

    /**
     * Resolve the configured lockout key strategy, defaulting to 'email_ip' for
     * any unrecognized value so a typo can never silently widen the key.
     *
     * @return 'email'|'ip'|'email_ip'
     */
    protected function keyStrategy(): string
    {
        $key = (string) config('bherila-auth.throttle.key', 'email_ip');

        return in_array($key, ['email', 'ip', 'email_ip'], true) ? $key : 'email_ip';
    }

    protected function latestSuccessAt(bool $useEmail, bool $useIp, ?string $email, ?string $ipAddress, ?string $method, Carbon $windowStart): ?Carbon
    {
        $createdAt = $this->keyedQuery($useEmail, $useIp, $email, $ipAddress, $method)
            ->where('event', AuthAuditLog::EVENT_LOGIN_SUCCEEDED)
            ->where('created_at', '>=', $windowStart)
            ->latest('created_at')
            ->value('created_at');

        return $createdAt === null ? null : Carbon::parse((string) $createdAt);
    }

    /**
     * Build the base query for the active key strategy. A dimension that is not part of
     * the strategy is omitted entirely.
     *
     * inspect() only reaches this once every dimension the strategy names has a value,
     * so the null clauses below are a floor for a caller arriving another way: matching
     * the rows whose column is null is narrower than dropping the constraint, which
     * would silently widen the key.
     *
     * @return Builder<AuthAuditLog>
     */
    protected function keyedQuery(bool $useEmail, bool $useIp, ?string $email, ?string $ipAddress, ?string $method): Builder
    {
        return AuthAuditLog::query()
            ->when($method !== null, fn (Builder $query) => $query->where('auth_method', $method))
            ->when($useEmail && $email !== null, fn (Builder $query) => $query->whereRaw('LOWER(email) = ?', [$email]))
            ->when($useEmail && $email === null, fn (Builder $query) => $query->whereNull('email'))
            ->when($useIp && $ipAddress !== null, fn (Builder $query) => $this->whereIpAddress($query, $ipAddress))
            ->when($useIp && $ipAddress === null, fn (Builder $query) => $query->whereNull('ip_address'));
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

    /**
     * Constrain the query to one client IP.
     *
     * ClientIp::resolve() already refuses an address that will not pack, so this is a
     * belt-and-braces guard for a value reaching the throttle by another route: matching
     * on a null packed value would be read as `ip_address IS NULL` and quietly count the
     * failures of every request whose IP was unknown. An address with no stored form
     * matches nothing instead.
     *
     * @param  Builder<AuthAuditLog>  $query
     * @return Builder<AuthAuditLog>
     */
    protected function whereIpAddress(Builder $query, string $ipAddress): Builder
    {
        $packed = $this->packedIp($ipAddress);

        return $packed === null
            ? $query->whereRaw('1 = 0')
            : $query->where('ip_address', $packed);
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
