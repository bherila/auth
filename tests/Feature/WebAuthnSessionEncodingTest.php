<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Services\WebAuthnService;
use BWH\Auth\Tests\TestCase;
use Illuminate\Http\Request;

/**
 * Sessions are stored as JSON. `json_encode()` returns false on invalid UTF-8 and does not
 * throw, so a binary value placed in the session does not fail where it is written — the
 * whole session is persisted as the encoding of `false`, silently discarding every other
 * key, including the CSRF token and the authenticated user.
 *
 * Ceremony options carry a raw random challenge, so their serialized form is binary. These
 * tests assert the session stays encodable, which is the property that actually matters;
 * asserting merely that the key is present passes even when the session is later destroyed.
 */
class WebAuthnSessionEncodingTest extends TestCase
{
    private function request(): Request
    {
        $request = Request::create('https://id.example.com/passkeys/auth/options', 'POST');
        $request->setLaravelSession(app('session.store'));

        return $request;
    }

    public function test_a_pending_authentication_challenge_leaves_the_session_encodable(): void
    {
        $request = $this->request();
        $request->session()->put('_token', 'a-csrf-token');

        app(WebAuthnService::class)->generateAuthenticationOptions(null, $request);

        $this->assertNotFalse(
            json_encode($request->session()->all()),
            'The session can no longer be encoded, so persisting it discards every key it holds.'
        );

        // The unrelated key must survive, which is the failure this actually causes.
        $this->assertSame('a-csrf-token', $request->session()->get('_token'));
    }

    public function test_a_stored_challenge_round_trips_through_json(): void
    {
        $request = $this->request();

        app(WebAuthnService::class)->generateAuthenticationOptions(null, $request);

        // Reproduce what the session layer does on the way out and back in.
        $encoded = json_encode($request->session()->all());
        $this->assertNotFalse($encoded);

        $restored = json_decode($encoded, true);
        $this->assertIsArray($restored);

        $key = 'bherila_auth_webauthn_login_options';
        $this->assertArrayHasKey($key, $restored);
        $this->assertSame($request->session()->get($key), $restored[$key]);
    }
}
