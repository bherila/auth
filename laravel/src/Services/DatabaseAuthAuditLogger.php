<?php

namespace BWH\Auth\Services;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * Persists every auth event as a row in the {@see AuthAuditLog} table.
 *
 * Bound as the default {@see \BWH\Auth\Contracts\AuthAuditLogger} when
 * `bherila-auth.audit.driver` is 'database'. The loosely-typed credential /
 * attempt objects are read defensively so the logger is not coupled to the
 * package's Eloquent models.
 */
class DatabaseAuthAuditLogger extends AbstractAuthAuditLogger
{
    public function loginSucceeded(Request $request, Authenticatable $user, ?string $method = 'password'): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_LOGIN_SUCCEEDED,
            'auth_method' => $method,
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
        ]);
    }

    public function loginFailed(Request $request, ?Authenticatable $user, ?string $email, string $reason, ?string $method = 'password'): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_LOGIN_FAILED,
            'auth_method' => $method,
            'succeeded' => false,
            'user_id' => $this->userId($user),
            'email' => $email ?? $this->userEmail($user),
            'reason' => $reason,
        ]);
    }

    public function loggedOut(Request $request, ?Authenticatable $user): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_LOGGED_OUT,
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
        ]);
    }

    public function passkeyRegistered(Request $request, Authenticatable $user, object $credential): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSKEY_REGISTERED,
            'auth_method' => 'passkey',
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->credentialMeta($credential),
        ]);
    }

    public function passkeyDeleted(Request $request, Authenticatable $user, object $credential): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSKEY_DELETED,
            'auth_method' => 'passkey',
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->credentialMeta($credential),
        ]);
    }

    public function passkeyLoginSucceeded(Request $request, Authenticatable $user, object $credential): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSKEY_LOGIN_SUCCEEDED,
            'auth_method' => 'passkey',
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->credentialMeta($credential),
        ]);
    }

    public function passkeyLoginFailed(Request $request, ?Authenticatable $user, ?string $credentialId, string $reason): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSKEY_LOGIN_FAILED,
            'auth_method' => 'passkey',
            'succeeded' => false,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'reason' => $reason,
            'metadata' => $credentialId !== null ? ['credential_id' => $credentialId] : null,
        ]);
    }

    public function twoFactorChallengeCreated(Request $request, Authenticatable $user, object $attempt): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_TWO_FACTOR_CHALLENGE_CREATED,
            'auth_method' => 'two_factor',
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->attemptMeta($attempt),
        ]);
    }

    public function twoFactorLoginSucceeded(Request $request, Authenticatable $user, object $attempt): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_TWO_FACTOR_SUCCEEDED,
            'auth_method' => 'two_factor',
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->attemptMeta($attempt),
        ]);
    }

    public function twoFactorLoginFailed(Request $request, ?Authenticatable $user, ?object $attempt, string $reason): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_TWO_FACTOR_FAILED,
            'auth_method' => 'two_factor',
            'succeeded' => false,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'reason' => $reason,
            'metadata' => $attempt !== null ? $this->attemptMeta($attempt) : null,
        ]);
    }

    public function twoFactorReportedSuspicious(Request $request, Authenticatable $user, object $attempt): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS,
            'auth_method' => 'two_factor',
            'succeeded' => false,
            'is_suspicious' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
            'metadata' => $this->attemptMeta($attempt),
        ]);
    }

    public function passwordResetRequested(Request $request, Authenticatable $user): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSWORD_RESET_REQUESTED,
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
        ]);
    }

    public function passwordResetCompleted(Request $request, Authenticatable $user): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSWORD_RESET_COMPLETED,
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
        ]);
    }

    public function passwordChanged(Request $request, Authenticatable $user): void
    {
        $this->record($request, [
            'event' => AuthAuditLog::EVENT_PASSWORD_CHANGED,
            'succeeded' => true,
            'user_id' => $this->userId($user),
            'email' => $this->userEmail($user),
        ]);
    }

    /**
     * Persist one audit row. String fields backed by length-limited columns are
     * clamped so that auditing an event (e.g. a failed login whose reason is a
     * raw exception message) can never throw and escalate the request to a 500.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function record(Request $request, array $attributes): void
    {
        foreach (['reason' => 255, 'email' => 255] as $key => $limit) {
            if (isset($attributes[$key]) && is_string($attributes[$key])) {
                $attributes[$key] = mb_substr($attributes[$key], 0, $limit);
            }
        }

        AuthAuditLog::create(array_merge([
            'ip_address' => ClientIp::resolve($request),
            'user_agent' => $request->userAgent(),
            'session_id' => $request->hasSession() ? $request->session()->getId() : null,
        ], $attributes));
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
     * @return array<string, mixed>|null
     */
    protected function credentialMeta(object $credential): ?array
    {
        $meta = array_filter([
            'credential_pk' => data_get($credential, 'id'),
            'credential_id' => data_get($credential, 'credential_id'),
            'aaguid' => data_get($credential, 'aaguid'),
            'name' => data_get($credential, 'name'),
        ], static fn ($value): bool => $value !== null && $value !== '');

        return $meta === [] ? null : $meta;
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function attemptMeta(object $attempt): ?array
    {
        $meta = array_filter([
            'attempt_id' => data_get($attempt, 'id'),
            'attempt_suspicious' => data_get($attempt, 'is_suspicious'),
        ], static fn ($value): bool => $value !== null);

        return $meta === [] ? null : $meta;
    }
}
