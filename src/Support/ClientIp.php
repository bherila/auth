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

        return $request->ip();
    }
}
