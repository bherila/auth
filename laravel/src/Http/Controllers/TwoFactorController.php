<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class TwoFactorController extends Controller
{
    public function __construct(
        private readonly AuthUserPolicy $userPolicy,
        private readonly AuthAuditLogger $auditLogger,
        private readonly TwoFactorService $twoFactorService,
    ) {}

    public function verify(Request $request): JsonResponse|RedirectResponse
    {
        $validated = $request->validate([
            'attempt_token' => ['required', 'string'],
            'code' => ['required', 'string', 'size:6'],
        ]);

        $attempt = TwoFactorAttempt::where('token', $validated['attempt_token'])->first();

        if (! $attempt || ! $attempt->isValid()) {
            return $this->failure($request, $attempt, 'Invalid or expired verification attempt.');
        }

        $isValidCode = hash_equals($attempt->code, $validated['code'])
            || ($this->allowTestCode($attempt) && hash_equals(config('bherila-auth.two_factor.test_code', '999999'), $validated['code']));

        if (! $isValidCode) {
            return $this->failure($request, $attempt, 'The verification code is incorrect. Please try again.');
        }

        return $this->completeLogin($request, $attempt);
    }

    public function resend(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'attempt_token' => ['required', 'string'],
        ]);

        $attempt = TwoFactorAttempt::where('token', $validated['attempt_token'])->first();
        $user = $attempt?->user;

        if (! $attempt || ! $user instanceof Authenticatable || $attempt->is_suspicious || $attempt->is_used) {
            return response()->json(['success' => false, 'message' => 'Invalid or expired verification attempt.'], 422);
        }

        $attempt->update(['is_used' => true]);
        $newAttempt = $this->twoFactorService->startChallenge($user, $request, (bool) $request->session()->get(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), false));

        return response()->json([
            'success' => true,
            'message' => 'A new verification code has been sent to your email address.',
            'attempt_token' => $newAttempt->token,
        ]);
    }

    public function confirm(Request $request, string $token): JsonResponse|RedirectResponse
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if (! $attempt || ! $attempt->isValid()) {
            return $this->failure($request, $attempt, 'Invalid or expired login link. Please log in again.');
        }

        return $this->completeLogin($request, $attempt);
    }

    public function report(Request $request, string $token): JsonResponse
    {
        $attempt = TwoFactorAttempt::where('token', $token)->first();

        if ($attempt && ! $attempt->is_used) {
            $attempt->update(['is_suspicious' => true, 'is_used' => true]);
            if ($attempt->user instanceof Authenticatable) {
                $this->auditLogger->twoFactorReportedSuspicious($request, $attempt->user, $attempt);
            }
        }

        return response()->json([
            'success' => true,
            'message' => 'This login attempt has been reported.',
        ]);
    }

    private function completeLogin(Request $request, TwoFactorAttempt $attempt): JsonResponse|RedirectResponse
    {
        $user = $attempt->user;

        if (! $user instanceof Authenticatable) {
            return $this->failure($request, $attempt, 'Authentication error. Please log in again.');
        }

        $attempt->update(['is_used' => true]);

        Auth::login($user, (bool) $request->session()->pull(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), false));
        $request->session()->forget(config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'));
        $request->session()->regenerate();

        $redirect = $this->userPolicy->redirectAfterLogin($user, $request);
        $this->auditLogger->twoFactorLoginSucceeded($request, $user, $attempt);

        if ($request->expectsJson()) {
            return response()->json([
                'success' => true,
                'message' => 'Login successful.',
                'redirect' => $redirect,
            ]);
        }

        return redirect()->to($redirect);
    }

    private function failure(Request $request, ?TwoFactorAttempt $attempt, string $message): JsonResponse|RedirectResponse
    {
        $user = $attempt?->user;
        $this->auditLogger->twoFactorLoginFailed($request, $user instanceof Authenticatable ? $user : null, $attempt, $message);

        if ($request->expectsJson()) {
            return response()->json(['success' => false, 'message' => $message], 422);
        }

        return redirect('/login')->withErrors(['code' => $message]);
    }

    private function allowTestCode(TwoFactorAttempt $attempt): bool
    {
        if ((bool) config('bherila-auth.two_factor.allow_test_code', false)) {
            return true;
        }

        return (bool) data_get($attempt->user, 'is_test', false);
    }
}
