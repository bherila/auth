<?php

namespace BWH\Auth\Models;

use BWH\Auth\Casts\BinaryIpAddressCast;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Append-only audit record for authentication events.
 *
 * Written by {@see \BWH\Auth\Services\DatabaseAuthAuditLogger}. The table name
 * is configurable via `bherila-auth.audit.table` so consuming apps can point it
 * at an existing table during migration.
 *
 * @property int $id
 * @property int|null $user_id
 * @property int|null $acting_user_id
 * @property string|null $email
 * @property string $event
 * @property string|null $auth_method
 * @property bool $succeeded
 * @property string|null $reason
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $session_id
 * @property bool $is_suspicious
 * @property array<string, mixed>|null $metadata
 */
class AuthAuditLog extends Model
{
    use Prunable;

    public const EVENT_LOGIN_SUCCEEDED = 'login_succeeded';

    public const EVENT_LOGIN_FAILED = 'login_failed';

    public const EVENT_LOGIN_BLOCKED = 'login_blocked';

    public const EVENT_LOGGED_OUT = 'logged_out';

    public const EVENT_TWO_FACTOR_CHALLENGE_CREATED = 'two_factor_challenge_created';

    public const EVENT_TWO_FACTOR_SUCCEEDED = 'two_factor_succeeded';

    public const EVENT_TWO_FACTOR_FAILED = 'two_factor_failed';

    public const EVENT_TWO_FACTOR_REPORTED_SUSPICIOUS = 'two_factor_reported_suspicious';

    public const EVENT_PASSKEY_REGISTERED = 'passkey_registered';

    public const EVENT_PASSKEY_DELETED = 'passkey_deleted';

    public const EVENT_PASSKEY_LOGIN_SUCCEEDED = 'passkey_login_succeeded';

    public const EVENT_PASSKEY_LOGIN_FAILED = 'passkey_login_failed';

    public const EVENT_PASSWORD_RESET_REQUESTED = 'password_reset_requested';

    public const EVENT_PASSWORD_RESET_COMPLETED = 'password_reset_completed';

    public const EVENT_PASSWORD_CHANGED = 'password_changed';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'acting_user_id',
        'email',
        'event',
        'auth_method',
        'succeeded',
        'reason',
        'ip_address',
        'user_agent',
        'session_id',
        'is_suspicious',
        'metadata',
    ];

    public function getTable(): string
    {
        return config('bherila-auth.audit.table', 'auth_audit_log');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'succeeded' => 'boolean',
            'is_suspicious' => 'boolean',
            'metadata' => 'array',
            'ip_address' => BinaryIpAddressCast::class,
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'user_id');
    }

    public function actingUser(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'acting_user_id');
    }

    /**
     * Rows eligible for pruning by `model:prune`.
     *
     * Returns a query matching nothing unless `bherila-auth.audit.retention_days`
     * is configured, so retention is OFF by default and never deletes audit data
     * for apps that rely on indefinite retention.
     */
    public function prunable(): Builder
    {
        $days = config('bherila-auth.audit.retention_days');

        if ($days === null) {
            return static::query()->whereRaw('1 = 0');
        }

        return static::query()->where('created_at', '<', now()->subDays((int) $days));
    }
}
