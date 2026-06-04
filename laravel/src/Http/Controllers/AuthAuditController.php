<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

/**
 * Read endpoints over the shared {@see AuthAuditLog} table.
 *
 * Registered only when `bherila-auth.audit.routes_enabled` is true. The package
 * ships no UI; apps render their own and call these (or query the model).
 */
class AuthAuditController extends Controller
{
    /**
     * The authenticated user's own login history, newest first.
     */
    public function index(Request $request): JsonResponse
    {
        $perPage = min(max($request->integer('per_page', 20), 1), 100);

        $logs = AuthAuditLog::query()
            ->where('user_id', Auth::id())
            ->latest()
            ->paginate($perPage);

        return response()->json($logs);
    }

    /**
     * Flag/unflag one of the authenticated user's own entries as suspicious.
     */
    public function markSuspicious(Request $request, int $id): JsonResponse
    {
        $log = AuthAuditLog::query()
            ->where('user_id', Auth::id())
            ->where('id', $id)
            ->firstOrFail();

        $log->is_suspicious = $request->has('is_suspicious')
            ? $request->boolean('is_suspicious')
            : ! $log->is_suspicious;
        $log->save();

        return response()->json([
            'success' => true,
            'is_suspicious' => $log->is_suspicious,
        ]);
    }

    /**
     * Cross-user admin listing, gated by the configured ability.
     */
    public function all(Request $request): JsonResponse
    {
        $ability = config('bherila-auth.audit.admin_ability');
        abort_unless(is_string($ability) && $ability !== '' && Gate::allows($ability), 403);

        $perPage = min(max($request->integer('per_page', 50), 1), 200);

        $logs = AuthAuditLog::query()
            ->when($request->filled('user_id'), fn ($query) => $query->where('user_id', $request->integer('user_id')))
            ->when($request->filled('event'), fn ($query) => $query->where('event', $request->string('event')))
            ->when($request->filled('email'), fn ($query) => $query->where('email', $request->string('email')))
            ->latest()
            ->paginate($perPage);

        return response()->json($logs);
    }
}
