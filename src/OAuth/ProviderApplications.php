<?php

namespace BWH\Auth\OAuth;

use Illuminate\Http\Request;

/**
 * The sibling applications the provider says the signed-in person can move between.
 *
 * The list is cached in the session at the OAuth callback rather than fetched per request:
 * that is the only moment an access token for the provider is in hand, and it is the only
 * moment the answer can change. Keeping it server-side also keeps the set of applications
 * that exist out of any JavaScript bundle, so downloading the front end tells an anonymous
 * visitor nothing about what else is deployed.
 *
 * Every relying party stores it under the same key so the shape is one thing to reason
 * about rather than five near-identical copies that can drift apart.
 */
final class ProviderApplications
{
    public const SESSION_KEY = 'oauth.applications';

    /**
     * Record the list for the lifetime of the session.
     *
     * Call this from the OAuth callback once the application has decided to admit the
     * person — not from inside the token exchange. A sign-in the application refuses
     * should leave nothing behind in the visitor's session.
     *
     * @param  list<array{key: string, name: string, url: string}>  $applications
     */
    public static function remember(Request $request, array $applications): void
    {
        $request->session()->put(self::SESSION_KEY, $applications);
    }

    /**
     * The list to render, or none.
     *
     * Reads defensively because it is the boundary between session state and the page:
     * a session written by an older release, or by a provider that has since changed
     * shape, must degrade to an empty menu rather than a broken layout.
     *
     * @return list<array{key: string, name: string, url: string}>
     */
    public static function forRequest(Request $request): array
    {
        $applications = $request->session()->get(self::SESSION_KEY, []);

        if (! is_array($applications)) {
            return [];
        }

        return array_values(array_filter(
            $applications,
            static fn (mixed $application): bool => is_array($application)
                && is_string($application['key'] ?? null)
                && is_string($application['name'] ?? null)
                && is_string($application['url'] ?? null),
        ));
    }
}
