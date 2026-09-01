<?php

namespace BWH\Auth\Support;

use Illuminate\Http\Request;

/**
 * Resolves the originating client IP for audit records.
 *
 * Uses the framework's {@see Request::ip()}, which only honours X-Forwarded-*
 * headers when the request originates from a configured trusted proxy
 * (Laravel's TrustProxies middleware). Apps behind Cloudflare or a load
 * balancer should configure trusted proxies so the real client IP is recorded;
 * otherwise forwarded headers are deliberately ignored so the audit log's IP
 * cannot be spoofed by a client sending arbitrary CF-Connecting-IP /
 * X-Forwarded-For headers.
 */
class ClientIp
{
    public static function resolve(?Request $request = null): ?string
    {
        $request ??= request();

        if (! $request instanceof Request) {
            return null;
        }

        return self::normalize($request->ip());
    }

    /**
     * The address, or null when it is not one this package can both store and query.
     *
     * Audit IPs are stored packed (varbinary(16), via {@see \BWH\Auth\Casts\BinaryIpAddressCast}),
     * so a value inet_pton() rejects has no stored form at all. Returning the raw value
     * would leave callers holding a non-null address that silently packs to null, and a
     * lookup keyed on it would then match the rows whose IP is genuinely unknown rather
     * than nothing. Null says what is true: there is no usable client IP here.
     *
     * The framework normally hands back a well-formed address, but not always — a
     * misconfigured trusted proxy can forward junk in an X-Forwarded-For header, and a
     * console or test request has no REMOTE_ADDR to speak of.
     */
    public static function normalize(?string $ipAddress): ?string
    {
        if ($ipAddress === null || $ipAddress === '') {
            return null;
        }

        return @inet_pton($ipAddress) === false ? null : $ipAddress;
    }
}
