<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Events\PasskeyDeleted;
use BWH\Auth\Events\PasskeyLoginFailed;
use BWH\Auth\Events\PasskeyLoginSucceeded;
use BWH\Auth\Events\PasskeyRegistered;
use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Services\WebAuthnService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Throwable;

class PasskeyController extends Controller
{
    public function __construct(
        private readonly WebAuthnService $webAuthnService,
        private readonly AuthUserPolicy $userPolicy,
        private readonly AuthAuditLogger $auditLogger,
    ) {}

    public function index(): JsonResponse
    {
        $passkeys = PasskeyCredential::query()
            ->where('user_id', Auth::id())
            ->orderByDesc('created_at')
            ->get(['id', 'name', 'aaguid', 'created_at', 'updated_at', 'last_used_at']);

        return response()->json($passkeys);
    }

    public function registrationOptions(Request $request): JsonResponse
    {
        return response()->json($this->webAuthnService->generateRegistrationOptions($request->user(), $request));
    }

    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'credential' => ['required', 'array'],
            'name' => ['nullable', 'string', 'max:255'],
        ]);

        try {
            $credential = $this->webAuthnService->verifyRegistrationResponse(
                $request->user(),
                $request,
                $validated['credential'],
                $validated['name'] ?? 'Passkey',
            );

            $this->auditLogger->passkeyRegistered($request, $request->user(), $credential);
            event(new PasskeyRegistered($request->user(), $credential));

            return response()->json([
                'success' => true,
                'passkey' => [
                    'id' => $credential->id,
                    'name' => $credential->name,
                    'created_at' => $credential->created_at,
                ],
            ]);
        } catch (Throwable $throwable) {
            return response()->json(['error' => 'Registration failed: '.$throwable->getMessage()], 422);
        }
    }

    public function destroy(Request $request, int $id): JsonResponse
    {
        $credential = PasskeyCredential::query()
            ->where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $credentialSnapshot = clone $credential;
        $credential->delete();

        $this->auditLogger->passkeyDeleted($request, $request->user(), $credentialSnapshot);
        event(new PasskeyDeleted($request->user(), $credentialSnapshot));

        return response()->json(['success' => true]);
    }

    public function authOptions(Request $request): JsonResponse
    {
        return response()->json($this->webAuthnService->generateAuthenticationOptions(null, $request));
    }

    public function authenticate(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'credential' => ['required', 'array'],
        ]);
        $credentialId = $request->input('credential.id');

        try {
            [$user, $credential] = $this->webAuthnService->verifyAuthenticationResponse($request, $validated['credential']);

            if (! $this->userPolicy->canPasskeyLogin($user, $request)) {
                throw new \RuntimeException('User is not allowed to log in.');
            }

            Auth::login($user);
            $request->session()->regenerate();

            $this->auditLogger->passkeyLoginSucceeded($request, $user, $credential);
            event(new PasskeyLoginSucceeded($user, $credential));

            return response()->json([
                'success' => true,
                'redirect' => $this->userPolicy->redirectAfterLogin($user, $request),
            ]);
        } catch (Throwable $throwable) {
            $this->auditLogger->passkeyLoginFailed($request, null, is_string($credentialId) ? $credentialId : null, $throwable->getMessage());
            event(new PasskeyLoginFailed(is_string($credentialId) ? $credentialId : null, $throwable->getMessage()));

            return response()->json(['error' => 'Authentication failed: '.$throwable->getMessage()], 422);
        }
    }
}
