<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;

final class OAuthConsentPresenter
{
    public function redirectUri(Request $request, object $client): ?string
    {
        $requested = $request->query('redirect_uri');
        if (is_string($requested) && $requested !== '') {
            return $requested;
        }

        $redirectUris = method_exists($client, 'getAttribute')
            ? $client->getAttribute('redirect_uris')
            : ($client->redirect_uris ?? null);
        if (! is_array($redirectUris)) {
            return null;
        }

        $registered = array_values(array_filter(
            $redirectUris,
            static fn (mixed $uri): bool => is_string($uri) && $uri !== '',
        ));

        return count($registered) === 1 ? $registered[0] : null;
    }
}
