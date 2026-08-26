<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Concerns\SignsOutThroughProvider;
use BWH\Auth\OAuth\OAuthClient;
use BWH\Auth\OAuth\ProviderApplications;
use BWH\Auth\Tests\Fixtures\User;
use BWH\Auth\Tests\TestCase;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/**
 * The relying-party half of the shared identity: what an application keeps in the session
 * about the provider, and what happens to both sessions when somebody signs out.
 */
class RelyingPartySessionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['bherila-auth.oauth_client' => [
            'provider' => 'test-provider',
            'base_url' => 'https://identity.example.test',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'scope' => 'identity:read',
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'identity_path' => '/api/oauth/user',
            'end_session_path' => '/oauth/end-session',
        ]]);

        Route::middleware('web')->group(function (): void {
            Route::get('/apps-test', fn (Request $request) => response()->json(ProviderApplications::forRequest($request)));
            Route::post('/logout-test', [SignOutTestController::class, 'logout']);
            Route::post('/logout-home-test', [SignOutTestController::class, 'logoutToNamedPage']);
            Route::get('/somewhere-else', fn () => 'here')->name('somewhere-else');
        });
    }

    public function test_the_application_list_survives_the_session_regeneration_that_follows_sign_in(): void
    {
        $apps = [['key' => 'phr', 'name' => 'Health', 'url' => 'https://phr.example.test']];

        $response = $this->withSession([ProviderApplications::SESSION_KEY => $apps])->get('/apps-test');

        $response->assertOk()->assertExactJson($apps);
    }

    public function test_no_list_means_an_empty_menu_rather_than_an_error(): void
    {
        $this->get('/apps-test')->assertOk()->assertExactJson([]);
    }

    /**
     * A session written by an older release, or by a provider that has changed shape, must
     * not be able to break the page that renders the menu.
     */
    public function test_a_session_holding_the_wrong_shape_degrades_to_an_empty_menu(): void
    {
        $this->withSession([ProviderApplications::SESSION_KEY => 'not-a-list'])
            ->get('/apps-test')
            ->assertOk()
            ->assertExactJson([]);

        $this->flushSession();

        $this->withSession([ProviderApplications::SESSION_KEY => [
            ['key' => 'good', 'name' => 'Good', 'url' => 'https://good.example.test'],
            ['key' => 'no-url', 'name' => 'Broken'],
            'not-even-an-array',
            ['key' => 123, 'name' => 'Wrong type', 'url' => 'https://wrong.example.test'],
        ]])
            ->get('/apps-test')
            ->assertOk()
            ->assertExactJson([['key' => 'good', 'name' => 'Good', 'url' => 'https://good.example.test']]);
    }

    public function test_remember_stores_the_list_under_the_shared_key(): void
    {
        $request = Request::create('/');
        $request->setLaravelSession($this->app['session']->driver());

        $apps = [['key' => 'games', 'name' => 'Games', 'url' => 'https://games.example.test']];
        ProviderApplications::remember($request, $apps);

        $this->assertSame($apps, $request->session()->get(ProviderApplications::SESSION_KEY));
        $this->assertSame($apps, ProviderApplications::forRequest($request));
    }

    public function test_signing_out_ends_the_local_session_and_hands_off_to_the_provider(): void
    {
        $user = User::forceCreate(['name' => 'Test', 'email' => 'test@example.test', 'password' => 'x']);

        $response = $this->actingAs($user)
            ->withSession([ProviderApplications::SESSION_KEY => [['key' => 'a', 'name' => 'A', 'url' => 'https://a.example.test']]])
            ->post('/logout-test');

        $response->assertRedirect(
            'https://identity.example.test/oauth/end-session?client_id=test-client'
            .'&post_logout_redirect_uri='.urlencode(url('/'))
        );

        $this->assertGuest();
        // Invalidated, not merely regenerated: the application list must not outlive the session.
        $this->assertNull(session(ProviderApplications::SESSION_KEY));
    }

    public function test_the_audit_hook_sees_who_left(): void
    {
        $user = User::forceCreate(['name' => 'Test', 'email' => 'left@example.test', 'password' => 'x']);

        SignOutTestController::$sawUser = null;

        $this->actingAs($user)->post('/logout-test');

        $this->assertSame('left@example.test', SignOutTestController::$sawUser);
    }

    /**
     * Signing out of an already-expired session is not an error; the route is deliberately
     * reachable without `auth` in at least one relying party.
     */
    public function test_signing_out_without_a_session_still_reaches_the_provider(): void
    {
        SignOutTestController::$sawUser = null;

        $this->post('/logout-test')->assertRedirectContains('https://identity.example.test/oauth/end-session');

        $this->assertNull(SignOutTestController::$sawUser);
    }

    public function test_a_caller_may_choose_where_the_provider_sends_them_back_to(): void
    {
        $this->post('/logout-home-test')->assertRedirect(
            'https://identity.example.test/oauth/end-session?client_id=test-client'
            .'&post_logout_redirect_uri='.urlencode(route('somewhere-else'))
        );
    }

    /**
     * An application with no client issued for it must still be able to sign somebody out;
     * the provider hand-off is the part that does not apply, not the sign-out.
     */
    public function test_an_unconfigured_application_signs_out_locally_instead_of_erroring(): void
    {
        config(['bherila-auth.oauth_client.client_id' => null]);

        $user = User::forceCreate(['name' => 'Test', 'email' => 'local@example.test', 'password' => 'x']);

        $this->actingAs($user)->post('/logout-test')->assertRedirect(url('/'));

        $this->assertGuest();
    }

    public function test_is_configured_reports_on_the_client_rather_than_aborting(): void
    {
        $this->assertTrue(OAuthClient::isConfigured());

        config(['bherila-auth.oauth_client.client_id' => '']);
        $this->assertFalse(OAuthClient::isConfigured());

        config(['bherila-auth.oauth_client.client_id' => '   ']);
        $this->assertFalse(OAuthClient::isConfigured());

        config(['bherila-auth.oauth_client.client_id' => 'test-client']);
        config(['bherila-auth.oauth_client.base_url' => null]);
        $this->assertFalse(OAuthClient::isConfigured());
    }
}

class SignOutTestController
{
    use SignsOutThroughProvider;

    public static ?string $sawUser = null;

    public function logout(Request $request, OAuthClient $oauth): RedirectResponse
    {
        return $this->signOutThroughProvider($request, $oauth);
    }

    public function logoutToNamedPage(Request $request, OAuthClient $oauth): RedirectResponse
    {
        return $this->signOutThroughProvider($request, $oauth, route('somewhere-else'));
    }

    protected function afterLocalSignOut(Request $request, ?Authenticatable $user): void
    {
        self::$sawUser = $user?->getAttribute('email');
    }
}
