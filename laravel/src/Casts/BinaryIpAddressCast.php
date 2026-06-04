<?php

namespace BWH\Auth\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent cast for IP addresses stored as varbinary(16).
 *
 * Converts between human-readable IP strings and compact binary representation:
 * - IPv4 (e.g. '192.168.1.1') ↔ 4 bytes
 * - IPv6 (e.g. '2001:db8::1') ↔ 16 bytes
 *
 * Uses PHP's inet_pton() / inet_ntop() which are consistent with
 * MySQL's INET6_ATON() / INET6_NTOA().
 *
 * @implements CastsAttributes<string|null, string|null>
 */
class BinaryIpAddressCast implements CastsAttributes
{
    /**
     * Cast the stored binary value to a human-readable IP string.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        $result = inet_ntop($value);

        return $result !== false ? $result : null;
    }

    /**
     * Cast the IP string to its binary representation for storage.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        $binary = inet_pton((string) $value);

        return $binary !== false ? $binary : null;
    }
}
