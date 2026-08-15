<?php

namespace BWH\Auth\OAuth;

use Illuminate\Http\Client\Response;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

final class OAuthClient
{
    private const string STATE_SESSION_KEY = 'oauth.login.state';

    private const string VERIFIER_SESSION_KEY = 'oauth.login.code_verifier';

    public function redirect(Request $request): RedirectResponse
    {
        $state = Str::random(40);
        $verifier = Str::random(96);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $request->session()->put([
            self::STATE_SESSION_KEY => $state,
            self::VERIFIER_SESSION_KEY => $verifier,
        ]);

        return redirect()->away($this->endpoint('authorize_path').'?'.http_build_query([
            'client_id' => $this->configuredValue('client_id'),
            'redirect_uri' => $this->configuredValue('redirect_uri'),
            'response_type' => 'code',
            'scope' => $this->configuredValue('scope'),
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));
    }

    public function identityFromCallback(Request $request): OAuthIdentity
    {
        $expectedState = $request->session()->pull(self::STATE_SESSION_KEY);
        $verifier = $request->session()->pull(self::VERIFIER_SESSION_KEY);
        $state = $request->query('state');
        $code = $request->query('code');

        abort_unless(
            is_string($expectedState)
            && is_string($state)
            && hash_equals($expectedState, $state)
            && is_string($verifier)
            && $verifier !== ''
            && is_string($code)
            && $code !== '',
            403,
            'The OAuth response could not be verified.',
        );

        $tokenResponse = Http::asForm()->acceptJson()->post($this->endpoint('token_path'), [
            'grant_type' => 'authorization_code',
            'client_id' => $this->configuredValue('client_id'),
            'client_secret' => $this->configuredValue('client_secret'),
            'redirect_uri' => $this->configuredValue('redirect_uri'),
            'code' => $code,
            'code_verifier' => $verifier,
        ]);
        abort_unless($tokenResponse->successful(), 502, 'The identity provider rejected the authorization code.');

        $accessToken = $tokenResponse->json('access_token');
        abort_unless(is_string($accessToken) && $accessToken !== '', 502, 'The identity provider returned an invalid token.');

        $identityResponse = Http::acceptJson()
            ->withToken($accessToken)
            ->get($this->endpoint('identity_path'));

        return $this->validatedIdentity($identityResponse);
    }

    public function providerName(): string
    {
        return $this->configuredValue('provider');
    }

    public function providerBaseUrl(): string
    {
        return $this->configuredValue('base_url');
    }

    private function validatedIdentity(Response $response): OAuthIdentity
    {
        abort_unless($response->successful(), 502, 'The identity provider did not return an account.');

        $identity = $response->json();
        abort_unless(
            is_array($identity)
            && is_string($identity['sub'] ?? null)
            && $identity['sub'] !== ''
            && strlen($identity['sub']) <= 191
            && is_string($identity['name'] ?? null)
            && trim($identity['name']) !== ''
            && is_string($identity['email'] ?? null)
            && filter_var($identity['email'], FILTER_VALIDATE_EMAIL) !== false,
            502,
            'The identity provider returned an invalid account.',
        );

        return new OAuthIdentity(
            provider: $this->providerName(),
            subject: $identity['sub'],
            name: trim($identity['name']),
            email: Str::lower($identity['email']),
        );
    }

    private function endpoint(string $pathKey): string
    {
        return $this->configuredValue('base_url').'/'.ltrim($this->configuredValue($pathKey), '/');
    }

    private function configuredValue(string $key): string
    {
        $value = config("bherila-auth.oauth_client.{$key}");
        abort_unless(is_string($value) && $value !== '', 503, 'OAuth is not configured.');

        if ($key === 'base_url') {
            $value = rtrim($value, '/');
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'redirect_uri') {
            abort_unless(filter_var($value, FILTER_VALIDATE_URL) !== false, 503, 'OAuth is not configured.');
        }

        if ($key === 'provider') {
            abort_unless($value === trim($value) && Str::length($value) <= 64, 503, 'OAuth is not configured.');
        }

        return $value;
    }
}
