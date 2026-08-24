<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Services\WebAuthnService;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * A credential only ever works against the relying-party ID it was registered with, or a
 * host for which that ID is a registrable-domain suffix. Getting this wrong is silent:
 * registration succeeds and authentication simply never matches.
 */
class WebAuthnRelyingPartyIdTest extends TestCase
{
    private function rpIdFor(string $host): string
    {
        $request = Request::create("https://{$host}/passkeys/auth/options", 'POST');
        $request->setLaravelSession(app('session.store'));

        $options = app(WebAuthnService::class)->generateAuthenticationOptions(null, $request);

        return $options['rpId'];
    }

    public function test_the_request_host_is_used_when_no_relying_party_is_configured(): void
    {
        config(['bherila-auth.passkeys.rp_id' => null]);

        $this->assertSame('id.example.com', $this->rpIdFor('id.example.com'));
    }

    public function test_the_configured_registrable_domain_is_used_for_a_subdomain(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);

        $this->assertSame('example.com', $this->rpIdFor('id.example.com'));
        $this->assertSame('example.com', $this->rpIdFor('www.example.com'));
    }

    public function test_the_configured_registrable_domain_is_used_for_the_apex(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);

        $this->assertSame('example.com', $this->rpIdFor('example.com'));
    }

    public function test_a_configured_value_the_browser_would_reject_falls_back_to_the_host(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);
        Log::spy();

        // Local development against a production-shaped configuration must keep working.
        $this->assertSame('localhost', $this->rpIdFor('localhost'));

        Log::shouldHaveReceived('warning')->once();
    }

    public function test_a_sibling_domain_is_not_treated_as_a_suffix(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);

        // "notexample.com" ends with "example.com" as a *string*, but is a different
        // registrable domain; only a dot-delimited suffix is a valid relying party.
        $this->assertSame('notexample.com', $this->rpIdFor('notexample.com'));
    }
}
