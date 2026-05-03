<?php

namespace BWH\Auth\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class TwoFactorAttempt extends Model
{
    protected $fillable = [
        'user_id',
        'token',
        'code',
        'is_used',
        'is_suspicious',
        'ip_address',
        'user_agent',
        'expires_at',
    ];

    protected $casts = [
        'is_used' => 'boolean',
        'is_suspicious' => 'boolean',
        'expires_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('bherila-auth.two_factor.table', 'auth_two_factor_attempts');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'user_id');
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isValid(): bool
    {
        return ! $this->is_used && ! $this->is_suspicious && ! $this->isExpired();
    }

    public static function createForUser(Authenticatable $user, ?string $ipAddress = null, ?string $userAgent = null): self
    {
        return self::create([
            'user_id' => $user->getAuthIdentifier(),
            'token' => Str::random(64),
            'code' => str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT),
            'is_used' => false,
            'is_suspicious' => false,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'expires_at' => now()->addMinutes((int) config('bherila-auth.two_factor.expires_minutes', 15)),
        ]);
    }
}
