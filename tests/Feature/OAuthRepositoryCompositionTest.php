<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use Illuminate\Contracts\Events\Dispatcher;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class OAuthRepositoryCompositionTest extends TestCase
{
    public function test_applications_can_extend_resource_repositories_without_replacing_them(): void
    {
        self::assertTrue(is_subclass_of(ApplicationAccessTokenRepository::class, ResourceAccessTokenRepository::class));
        self::assertTrue(is_subclass_of(ApplicationAuthCodeRepository::class, ResourceAuthCodeRepository::class));
        self::assertTrue(is_subclass_of(ApplicationRefreshTokenRepository::class, ResourceRefreshTokenRepository::class));
    }

    public function test_protocol_methods_are_final_while_application_policy_hooks_are_protected(): void
    {
        foreach ([
            [ResourceAccessTokenRepository::class, 'persistNewAccessToken', 'persistResourceAccessToken'],
            [ResourceAccessTokenRepository::class, 'isAccessTokenRevoked', 'isApplicationAccessTokenRevoked'],
            [ResourceAuthCodeRepository::class, 'persistNewAuthCode', 'persistResourceAuthCode'],
            [ResourceAuthCodeRepository::class, 'isAuthCodeRevoked', 'isApplicationAuthCodeRevoked'],
            [ResourceRefreshTokenRepository::class, 'persistNewRefreshToken', 'persistResourceRefreshToken'],
            [ResourceRefreshTokenRepository::class, 'isRefreshTokenRevoked', 'isApplicationRefreshTokenRevoked'],
        ] as [$repository, $protocolMethod, $policyHook]) {
            self::assertTrue((new ReflectionMethod($repository, $protocolMethod))->isFinal());
            self::assertTrue((new ReflectionMethod($repository, $policyHook))->isProtected());
        }
    }
}

final class ApplicationAccessTokenRepository extends ResourceAccessTokenRepository
{
    public function __construct(Dispatcher $events)
    {
        parent::__construct($events);
    }

    protected function persistResourceAccessToken(
        AccessTokenEntityInterface $accessTokenEntity,
        ?string $resource,
        bool $hasResourceColumn,
    ): void
    {
        parent::persistResourceAccessToken($accessTokenEntity, $resource, $hasResourceColumn);
    }

    protected function isApplicationAccessTokenRevoked(string $tokenId): bool
    {
        return false;
    }
}

final class ApplicationAuthCodeRepository extends ResourceAuthCodeRepository
{
    protected function persistResourceAuthCode(
        AuthCodeEntityInterface $authCodeEntity,
        ?string $resource,
        bool $hasResourceColumn,
        array $scopeIdentifiers,
    ): void
    {
        parent::persistResourceAuthCode($authCodeEntity, $resource, $hasResourceColumn, $scopeIdentifiers);
    }

    protected function isApplicationAuthCodeRevoked(string $codeId): bool
    {
        return false;
    }
}

final class ApplicationRefreshTokenRepository extends ResourceRefreshTokenRepository
{
    protected function persistResourceRefreshToken(
        RefreshTokenEntityInterface $refreshTokenEntity,
        ?string $resource,
        bool $hasResourceColumn,
    ): void
    {
        parent::persistResourceRefreshToken($refreshTokenEntity, $resource, $hasResourceColumn);
    }

    protected function isApplicationRefreshTokenRevoked(string $tokenId): bool
    {
        return false;
    }
}
