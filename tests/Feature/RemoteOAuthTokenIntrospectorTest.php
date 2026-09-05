<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Introspection\OAuthIntrospectionException;
use BWH\Auth\OAuth\Introspection\RemoteOAuthTokenIntrospector;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;

final class RemoteOAuthTokenIntrospectorTest extends TestCase
{
    private const ENDPOINT = 'https://auth.example.test/oauth/introspect';

    private const RESOURCE = 'https://resource.example.test/mcp';

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'app.env' => 'testing',
            'bherila-auth.oauth_resource_server.introspection_endpoint' => self::ENDPOINT,
            'bherila-auth.oauth_resource_server.client_id' => 'resource-server',
            'bherila-auth.oauth_resource_server.client_secret' => 'test-secret',
            'bherila-auth.oauth_resource_server.issuer' => 'https://auth.example.test',
            'bherila-auth.oauth_resource_server.resource' => self::RESOURCE,
            'bherila-auth.oauth_resource_server.timeout_seconds' => 5,
        ]);
    }

    public function test_it_returns_a_defensively_validated_active_context(): void
    {
        Http::fake([
            self::ENDPOINT => Http::response([
                'active' => true,
                'iss' => 'https://auth.example.test',
                'sub' => '42',
                'client_id' => 'public-client',
                'scope' => 'mcp:use offers:read',
                'exp' => time() + 300,
                'iat' => time() - 10,
                'nbf' => time() - 10,
                'aud' => ['public-client', self::RESOURCE],
                'resource' => self::RESOURCE,
            ]),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('opaque-to-the-resource-server');

        self::assertTrue($result->active);
        self::assertSame('42', $result->subject);
        self::assertSame(['mcp:use', 'offers:read'], $result->scopes);
        Http::assertSent(function (Request $request): bool {
            return $request->url() === self::ENDPOINT
                && $request['token'] === 'opaque-to-the-resource-server'
                && $request['token_type_hint'] === 'access_token'
                && $request->hasHeader('Authorization', 'Basic '.base64_encode('resource-server:test-secret'));
        });
    }

    public function test_it_accepts_integral_float_timestamps_from_json(): void
    {
        $expiresAt = time() + 300;
        $issuedAt = time() - 10;
        $notBefore = time() - 10;
        Http::fake([
            self::ENDPOINT => Http::response($this->activeResponseJson(
                "{$expiresAt}.0",
                "{$issuedAt}.0",
                "{$notBefore}.0",
            ), 200, ['Content-Type' => 'application/json']),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('integral-float-timestamps');

        self::assertSame($expiresAt, $result->expiresAt);
        self::assertSame($issuedAt, $result->issuedAt);
        self::assertSame($notBefore, $result->notBefore);
    }

    #[DataProvider('invalidTimestampProvider')]
    public function test_it_rejects_non_integral_or_out_of_range_timestamps(string $timestamp): void
    {
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson($timestamp),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('invalid-timestamp');
    }

    /** @return array<string, array{string}> */
    public static function invalidTimestampProvider(): array
    {
        return [
            'fraction' => ['1770000000.5'],
            'string' => ['"1770000000"'],
            'nan' => ['NaN'],
            'infinity' => ['Infinity'],
            'overflow' => ['9223372036854775808'],
            'underflow' => ['-9223372036854775809'],
            // A double cannot represent these literals, so json_decode rounds
            // them onto the exact platform bounds. They must not be laundered
            // into PHP_INT_MAX by the range check.
            'float overflow' => ['9223372036854775809.0'],
            'float upper bound' => ['9223372036854775808.0'],
        ];
    }

    #[DataProvider('outOfRangeIssuedAtProvider')]
    public function test_it_rejects_out_of_range_issued_at_timestamps(string $issuedAt): void
    {
        $expiresAt = time() + 300;
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson((string) $expiresAt, $issuedAt),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('out-of-range-iat');
    }

    /**
     * `iat` carries no ordering constraint, so unlike `exp` it is rejected only
     * by the range check itself. The underflow literal is the important case:
     * json_decode rounds it onto exactly PHP_INT_MIN, where an inclusive lower
     * bound would silently accept it.
     *
     * @return array<string, array{string}>
     */
    public static function outOfRangeIssuedAtProvider(): array
    {
        return [
            'float underflow' => ['-9223372036854775809.0'],
            'float lower bound' => ['-9223372036854775808.0'],
            'float overflow' => ['9223372036854775809.0'],
            'float upper bound' => ['9223372036854775808.0'],
            'fraction' => ['1770000000.5'],
            'integer underflow' => ['-9223372036854775809'],
        ];
    }

    public function test_it_still_accepts_the_largest_representable_in_range_float(): void
    {
        // The greatest double strictly below 2 ** 63; the exclusive bounds must
        // not narrow the accepted range any further than the rounding demands.
        $expiresAt = 9223372036854774784;
        Http::fake([
            self::ENDPOINT => Http::response(
                $this->activeResponseJson($expiresAt.'.0'),
                200,
                ['Content-Type' => 'application/json'],
            ),
        ]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('largest-in-range-float');

        self::assertSame($expiresAt, $result->expiresAt);
    }

    public function test_inactive_tokens_remain_inactive_without_requiring_claims(): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('revoked')->active);
    }

    private function activeResponseJson(string $expiresAt, string $issuedAt = '1770000000', string $notBefore = '1770000000'): string
    {
        return '{"active":true,"iss":"https://auth.example.test","sub":"42",'
            .'"client_id":"public-client","scope":"mcp:use","exp":'.$expiresAt
            .',"iat":'.$issuedAt.',"nbf":'.$notBefore.',"aud":["public-client","'
            .self::RESOURCE.'"],"resource":"'.self::RESOURCE.'"}';
    }

    public function test_it_form_encodes_basic_credentials(): void
    {
        $clientId = 'resource: server+%';
        $clientSecret = 'secret: with+percent%';
        config([
            'bherila-auth.oauth_resource_server.client_id' => $clientId,
            'bherila-auth.oauth_resource_server.client_secret' => $clientSecret,
        ]);
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('revoked')->active);
        Http::assertSent(fn (Request $request): bool => $request->hasHeader(
            'Authorization',
            'Basic '.base64_encode(urlencode($clientId).':'.urlencode($clientSecret)),
        ));
    }

    public function test_an_active_response_for_the_wrong_resource_fails_closed(): void
    {
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true,
            'iss' => 'https://auth.example.test',
            'sub' => '42',
            'client_id' => 'public-client',
            'scope' => 'mcp:use',
            'exp' => time() + 300,
            'aud' => ['public-client', 'https://other.example.test/mcp'],
            'resource' => 'https://other.example.test/mcp',
        ])]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('wrong-resource');
    }

    public function test_it_canonicalizes_resource_identifiers_without_tls_restriction(): void
    {
        $configured = 'HTTPS://RESOURCE.EXAMPLE.TEST:443/mcp';
        config(['bherila-auth.oauth_resource_server.resource' => $configured]);
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true, 'iss' => 'https://auth.example.test', 'sub' => '42',
            'client_id' => 'public-client', 'scope' => 'mcp:use', 'exp' => time() + 300,
            'aud' => ['public-client', 'https://resource.example.test/mcp'],
            'resource' => 'HTTPS://RESOURCE.EXAMPLE.TEST:443/mcp',
        ])]);

        self::assertSame('https://resource.example.test/mcp', app(RemoteOAuthTokenIntrospector::class)->introspect('token')->resource);
    }

    public function test_it_preserves_opaque_subject_and_client_identifier_whitespace(): void
    {
        Http::fake([self::ENDPOINT => Http::response([
            'active' => true, 'iss' => 'https://auth.example.test', 'sub' => ' subject ',
            'client_id' => ' client ', 'scope' => 'mcp:use', 'exp' => time() + 300,
            'aud' => ['public-client', self::RESOURCE], 'resource' => self::RESOURCE,
        ])]);

        $result = app(RemoteOAuthTokenIntrospector::class)->introspect('token');
        self::assertSame(' subject ', $result->subject);
        self::assertSame(' client ', $result->clientId);
    }

    public function test_http_resource_is_allowed_when_introspection_endpoint_is_https(): void
    {
        config(['bherila-auth.oauth_resource_server.resource' => 'http://resource.example.test/mcp']);
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('token')->active);
    }

    public function test_http_and_schema_failures_are_reported_as_unavailable(): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => 'yes'], 200)]);

        $this->expectException(OAuthIntrospectionException::class);

        app(RemoteOAuthTokenIntrospector::class)->introspect('malformed-response');
    }

    public function test_it_refuses_insecure_endpoints_before_sending_the_token(): void
    {
        config(['bherila-auth.oauth_resource_server.introspection_endpoint' => 'http://auth.example.test/oauth/introspect']);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected insecure endpoint configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }

    public function test_it_refuses_loopback_http_outside_local_or_testing(): void
    {
        config([
            'app.env' => 'production',
            'bherila-auth.oauth_resource_server.introspection_endpoint' => 'http://127.0.0.1/oauth/introspect',
            'bherila-auth.oauth_resource_server.issuer' => 'http://127.0.0.1',
        ]);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected production loopback HTTP configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }

    public function test_it_allows_loopback_http_during_testing(): void
    {
        $endpoint = 'http://127.0.0.1/oauth/introspect';
        config([
            'bherila-auth.oauth_resource_server.introspection_endpoint' => $endpoint,
            'bherila-auth.oauth_resource_server.issuer' => 'http://127.0.0.1',
        ]);
        Http::fake([$endpoint => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('inactive')->active);
        Http::assertSentCount(1);
    }

    public function test_it_allows_bracketed_ipv6_loopback_http_during_testing(): void
    {
        $endpoint = 'http://[::1]/oauth/introspect';
        config([
            'bherila-auth.oauth_resource_server.introspection_endpoint' => $endpoint,
            'bherila-auth.oauth_resource_server.issuer' => 'http://[::1]',
        ]);
        Http::fake([$endpoint => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('inactive')->active);
        Http::assertSentCount(1);
    }

    public function test_it_refuses_a_cross_origin_introspection_endpoint_before_sending_the_token(): void
    {
        config(['bherila-auth.oauth_resource_server.introspection_endpoint' => 'https://other.example.test/oauth/introspect']);
        Http::fake();

        try {
            app(RemoteOAuthTokenIntrospector::class)->introspect('must-not-leave');
            self::fail('Expected cross-origin endpoint configuration to be rejected.');
        } catch (OAuthIntrospectionException) {
            Http::assertNothingSent();
        }
    }
}
