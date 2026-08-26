<?php

namespace BWH\Auth\Concerns;

use BWH\Auth\OAuth\OAuthClient;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * Sign out here, and then at the provider.
 *
 * Ending only the local session is not signing out. The provider still recognises the
 * person, so the very next protected page sends them back for authorization and is handed
 * an identity without a prompt — a sign-out button that visibly does nothing. Handing off
 * to the provider's end-session endpoint is what makes it mean what it says, and it ends
 * the sibling applications' sessions too, which is what someone clicking "sign out" on a
 * shared identity actually expects.
 *
 * The local teardown still has to happen first and in this order. Redirecting to the
 * provider without it would leave a live session behind if the person closed the tab
 * mid-hop, and the provider is under no obligation to send them back.
 */
trait SignsOutThroughProvider
{
    /**
     * @param  string|null  $returnTo  Absolute URL to come back to; defaults to this
     *                                 application's root. The provider validates it against
     *                                 the origins registered for this client and lands the
     *                                 person on itself if it does not recognise the value,
     *                                 so an unregistered address degrades rather than leaks.
     */
    protected function signOutThroughProvider(Request $request, OAuthClient $oauth, ?string $returnTo = null): RedirectResponse
    {
        // Captured before the guard forgets it, so the audit trail can still say who left.
        $user = Auth::user();

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $this->afterLocalSignOut($request, $user);

        // `url()` passes an already-absolute URL through untouched, so callers may hand
        // this a route. Relative values would fail the provider's origin check.
        $returnTo = url($returnTo ?? '/');

        if (! OAuthClient::isConfigured()) {
            return redirect($returnTo);
        }

        return redirect()->away($oauth->endSessionUrl($returnTo));
    }

    /**
     * Hook for applications that keep an audit trail; a no-op by default.
     *
     * Runs after the session is gone, so it must not depend on session state. `$user` is
     * null when an already-expired session posts to sign out, which is not an error — see
     * the relying parties that deliberately leave that route outside `auth` middleware.
     */
    protected function afterLocalSignOut(Request $request, ?Authenticatable $user): void
    {
        //
    }
}
