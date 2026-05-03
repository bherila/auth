<?php

namespace BWH\Auth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasskeyCredential extends Model
{
    protected $fillable = [
        'user_id',
        'credential_id',
        'public_key',
        'counter',
        'aaguid',
        'name',
        'transports',
        'last_used_at',
    ];

    protected $casts = [
        'counter' => 'integer',
        'transports' => 'array',
        'last_used_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('bherila-auth.passkeys.table', 'auth_passkeys');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('bherila-auth.users.model'), 'user_id');
    }
}
