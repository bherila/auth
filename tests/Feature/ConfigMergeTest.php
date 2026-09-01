<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\AuthServiceProvider;
use BWH\Auth\Tests\TestCase;

class ConfigMergeTest extends TestCase
{
    /** @var array<string, mixed>|null */
    private ?array $originalConfig = null;

    protected function tearDown(): void
    {
        if ($this->originalConfig !== null) {
            // Restore the real config before Testbench rolls the migrations back: the
            // fake published config renames tables the down() migrations look for.
            config(['bherila-auth' => $this->originalConfig]);
        }

        parent::tearDown();
    }

    /**
     * Stand in for a consumer whose published config/bherila-auth.php predates several
     * releases: it carries the nested sections as they looked then, and nothing newer.
     * Re-registering the provider over it is what happens on that consumer's boot.
     *
     * @param  array<string, mixed>  $published
     */
    private function bootWithPublishedConfig(array $published): void
    {
        $this->originalConfig ??= config('bherila-auth');

        config(['bherila-auth' => $published]);

        (new AuthServiceProvider($this->app))->register();
    }

    private function bootWithLegacyConfig(): void
    {
        $this->bootWithPublishedConfig([
            'two_factor' => [
                'table' => 'legacy_two_factor_attempts',
                'expires_minutes' => 5,
            ],
            'passkeys' => [
                'table' => 'legacy_passkeys',
                'timeout' => 30000,
            ],
            'oauth_server' => [
                'issuer' => 'https://legacy.example.com',
                'token_endpoint_auth_methods' => [],
                'dynamic_clients' => [
                    'registered_at_column' => 'registered_at',
                ],
            ],
        ]);
    }

    public function test_published_values_win(): void
    {
        $this->bootWithLegacyConfig();

        $this->assertSame('legacy_two_factor_attempts', config('bherila-auth.two_factor.table'));
        $this->assertSame(5, config('bherila-auth.two_factor.expires_minutes'));
        $this->assertSame('legacy_passkeys', config('bherila-auth.passkeys.table'));
        $this->assertSame('https://legacy.example.com', config('bherila-auth.oauth_server.issuer'));
    }

    public function test_keys_added_after_the_config_was_published_keep_their_defaults(): void
    {
        $this->bootWithLegacyConfig();

        // A top-level array_merge would have dropped every one of these along with the
        // rest of the nested section it lives in, leaving each reading as null.
        $this->assertSame('999999', config('bherila-auth.two_factor.test_code'));
        $this->assertFalse(config('bherila-auth.two_factor.allow_test_code'));
        $this->assertSame(['local', 'testing'], config('bherila-auth.two_factor.test_code_environments'));
        $this->assertSame('bherila_auth_2fa_user_id', config('bherila-auth.two_factor.session_user_key'));
        $this->assertSame('preferred', config('bherila-auth.passkeys.user_verification'));
        $this->assertSame('mcp:use', config('bherila-auth.oauth_server.resource_required_scope'));
    }

    public function test_nested_sections_merge_key_by_key(): void
    {
        $this->bootWithLegacyConfig();

        $this->assertSame('registered_at', config('bherila-auth.oauth_server.dynamic_clients.registered_at_column'));
        $this->assertSame(['dynamically_registered_at'], config('bherila-auth.oauth_server.dynamic_clients.required_columns'));
    }

    public function test_a_configured_list_replaces_the_default_rather_than_merging_into_it(): void
    {
        $this->bootWithLegacyConfig();

        // Emptying a list means empty, not "keep whatever the package shipped".
        $this->assertSame([], config('bherila-auth.oauth_server.token_endpoint_auth_methods'));

        $this->bootWithPublishedConfig(['routes' => ['middleware' => ['api']]]);

        $this->assertSame(['api'], config('bherila-auth.routes.middleware'));
    }

    public function test_untouched_sections_are_intact(): void
    {
        $this->bootWithLegacyConfig();

        $this->assertSame('api', config('bherila-auth.routes.prefix'));
        $this->assertSame(['web'], config('bherila-auth.routes.middleware'));
        $this->assertSame('email_ip', config('bherila-auth.throttle.key'));
    }
}
