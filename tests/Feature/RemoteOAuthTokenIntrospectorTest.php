<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Introspection\OAuthIntrospectionException;
use BWH\Auth\OAuth\Introspection\RemoteOAuthTokenIntrospector;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

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

    public function test_inactive_tokens_remain_inactive_without_requiring_claims(): void
    {
        Http::fake([self::ENDPOINT => Http::response(['active' => false])]);

        self::assertFalse(app(RemoteOAuthTokenIntrospector::class)->introspect('revoked')->active);
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
