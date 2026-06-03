<?php

namespace BWH\Auth\Services;

use BWH\Auth\Models\PasskeyCredential;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnService
{
    private const SESSION_REGISTER_OPTIONS = 'bherila_auth_webauthn_register_options';

    private const SESSION_LOGIN_OPTIONS = 'bherila_auth_webauthn_login_options';

    public function generateRegistrationOptions(Authenticatable $user, Request $request): array
    {
        $rpId = $this->getRpId($request);
        $rpEntity = PublicKeyCredentialRpEntity::create(
            config('bherila-auth.passkeys.rp_name', config('app.name', 'App')),
            $rpId,
        );
        $userEntity = PublicKeyCredentialUserEntity::create(
            $this->userAttribute($user, config('bherila-auth.users.email_attribute', 'email')),
            (string) $user->getAuthIdentifier(),
            $this->userAttribute($user, config('bherila-auth.users.name_attribute', 'name')),
        );

        $excludeCredentials = PasskeyCredential::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->get()
            ->map(fn (PasskeyCredential $credential) => PublicKeyCredentialDescriptor::create(
                'public-key',
                $this->decodeCredentialId($credential->credential_id),
            ))
            ->toArray();

        $options = PublicKeyCredentialCreationOptions::create(
            rp: $rpEntity,
            user: $userEntity,
            challenge: random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::create('public-key', ES256::ID),
                PublicKeyCredentialParameters::create('public-key', RS256::ID),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: $this->userVerificationRequirement(),
                residentKey: $this->residentKeyRequirement(),
            ),
            attestation: 'none',
            excludeCredentials: $excludeCredentials,
            timeout: (int) config('bherila-auth.passkeys.timeout', 60000),
        );

        $request->session()->put(self::SESSION_REGISTER_OPTIONS, serialize($options));

        return $this->creationOptionsToArray($options);
    }

    public function verifyRegistrationResponse(Authenticatable $user, Request $request, array $credentialData, string $name): PasskeyCredential
    {
        $serializedOptions = $request->session()->pull(self::SESSION_REGISTER_OPTIONS);
        if (! $serializedOptions) {
            throw new RuntimeException('No pending registration options found.');
        }

        $options = unserialize($serializedOptions);
        $credential = $this->deserializeCredential($credentialData);

        /** @var AuthenticatorAttestationResponse $response */
        $response = $credential->response;
        $source = $this->createAttestationValidator($request)->check(
            $response,
            $options,
            $this->getRpId($request),
        );

        return PasskeyCredential::query()->create([
            'user_id' => $user->getAuthIdentifier(),
            'credential_id' => $this->encodeCredentialId($source->publicKeyCredentialId),
            'public_key' => base64_encode($source->credentialPublicKey),
            'counter' => $source->counter,
            'aaguid' => $source->aaguid->toRfc4122(),
            'name' => $name ?: 'Passkey',
            'transports' => $source->transports,
        ]);
    }

    public function generateAuthenticationOptions(?Authenticatable $user, Request $request): array
    {
        $allowCredentials = [];
        if ($user) {
            $allowCredentials = PasskeyCredential::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->get()
                ->map(fn (PasskeyCredential $credential) => PublicKeyCredentialDescriptor::create(
                    'public-key',
                    $this->decodeCredentialId($credential->credential_id),
                ))
                ->toArray();
        }

        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->getRpId($request),
            allowCredentials: $allowCredentials,
            userVerification: $this->userVerificationRequirement(),
            timeout: (int) config('bherila-auth.passkeys.timeout', 60000),
        );

        $request->session()->put(self::SESSION_LOGIN_OPTIONS, serialize($options));

        return $this->requestOptionsToArray($options);
    }

    /**
     * @return array{0: Authenticatable, 1: PasskeyCredential}
     */
    public function verifyAuthenticationResponse(Request $request, array $credentialData): array
    {
        $serializedOptions = $request->session()->pull(self::SESSION_LOGIN_OPTIONS);
        if (! $serializedOptions) {
            throw new RuntimeException('No pending authentication options found.');
        }

        $options = unserialize($serializedOptions);
        $credential = $this->deserializeCredential($credentialData);
        $storedCredential = PasskeyCredential::query()
            ->where('credential_id', $this->encodeCredentialId($credential->rawId))
            ->first();

        if (! $storedCredential) {
            throw new RuntimeException('Credential not found.');
        }

        $user = $storedCredential->user;
        if (! $user instanceof Authenticatable) {
            throw new RuntimeException('Credential user not found.');
        }

        /** @var AuthenticatorAssertionResponse $response */
        $response = $credential->response;
        $updatedSource = $this->createAssertionValidator($request)->check(
            $this->credentialToSource($storedCredential, $user),
            $response,
            $options,
            $this->getRpId($request),
            (string) $user->getAuthIdentifier(),
        );

        $storedCredential->update([
            'counter' => $updatedSource->counter,
            'last_used_at' => now(),
        ]);

        return [$user, $storedCredential];
    }

    private function deserializeCredential(array $credentialData): PublicKeyCredential
    {
        return $this->createSerializer()->deserialize(
            json_encode($credentialData, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json',
        );
    }

    private function getRpId(Request $request): string
    {
        return $request->getHost();
    }

    private function createSerializer(): SerializerInterface
    {
        $attestationManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);

        return (new WebauthnSerializerFactory($attestationManager))->create();
    }

    private function createAttestationValidator(Request $request): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create($this->ceremonyFactory($request)->creationCeremony());
    }

    private function createAssertionValidator(Request $request): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory($request)->requestCeremony());
    }

    private function ceremonyFactory(Request $request): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $origins = array_values(array_unique(array_filter([
            $request->getSchemeAndHttpHost(),
            config('app.url'),
            ...config('bherila-auth.passkeys.allowed_origins', []),
        ])));

        $factory->setAllowedOrigins($origins);

        return $factory;
    }

    private function credentialToSource(PasskeyCredential $credential, Authenticatable $user): CredentialRecord
    {
        return CredentialRecord::create(
            publicKeyCredentialId: $this->decodeCredentialId($credential->credential_id),
            type: 'public-key',
            transports: $credential->transports ?? [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $credential->aaguid
                ? Uuid::fromString($credential->aaguid)
                : Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: base64_decode($credential->public_key),
            userHandle: (string) $user->getAuthIdentifier(),
            counter: $credential->counter,
        );
    }

    private function creationOptionsToArray(PublicKeyCredentialCreationOptions $options): array
    {
        return [
            'challenge' => $this->encodeCredentialId($options->challenge),
            'rp' => [
                'name' => $options->rp->name,
                'id' => $options->rp->id,
            ],
            'user' => [
                'id' => $this->encodeCredentialId($options->user->id),
                'name' => $options->user->name,
                'displayName' => $options->user->displayName,
            ],
            'pubKeyCredParams' => array_map(fn ($parameter) => [
                'type' => $parameter->type,
                'alg' => $parameter->alg,
            ], $options->pubKeyCredParams),
            'timeout' => $options->timeout,
            'excludeCredentials' => array_map(fn ($credential) => [
                'type' => $credential->type,
                'id' => $this->encodeCredentialId($credential->id),
            ], $options->excludeCredentials),
            'authenticatorSelection' => [
                'residentKey' => $this->residentKeyRequirement(),
                'requireResidentKey' => $this->residentKeyRequirement() === AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                'userVerification' => $this->userVerificationRequirement(),
            ],
            'attestation' => 'none',
        ];
    }

    private function requestOptionsToArray(PublicKeyCredentialRequestOptions $options): array
    {
        return [
            'challenge' => $this->encodeCredentialId($options->challenge),
            'rpId' => $options->rpId,
            'allowCredentials' => array_map(fn ($credential) => [
                'type' => $credential->type,
                'id' => $this->encodeCredentialId($credential->id),
            ], $options->allowCredentials),
            'userVerification' => $options->userVerification ?? 'preferred',
            'timeout' => $options->timeout,
        ];
    }

    private function encodeCredentialId(string $rawId): string
    {
        return rtrim(strtr(base64_encode($rawId), '+/', '-_'), '=');
    }

    private function decodeCredentialId(string $credentialId): string
    {
        return base64_decode(strtr($credentialId, '-_', '+/'));
    }

    private function userAttribute(Authenticatable $user, string $attribute): string
    {
        if ($user instanceof Model) {
            return (string) ($user->getAttribute($attribute) ?: $user->getAuthIdentifier());
        }

        return (string) ($user->{$attribute} ?? $user->getAuthIdentifier());
    }

    private function userVerificationRequirement(): string
    {
        $value = config('bherila-auth.passkeys.user_verification', AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);

        return in_array($value, AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENTS, true)
            ? $value
            : AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED;
    }

    private function residentKeyRequirement(): ?string
    {
        $value = config('bherila-auth.passkeys.resident_key', AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED);

        return in_array($value, AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENTS, true)
            ? $value
            : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED;
    }
}
