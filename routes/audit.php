<?php

use BWH\Auth\Http\Controllers\AuthAuditController;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use Illuminate\Support\Facades\Route;

// The RequireActiveUser middleware ensures a pending or disabled account cannot reach
// these endpoints even when the surrounding app gate only checks role without verifying
// account state (see bherila-auth.audit.admin_ability).
Route::middleware(['auth', RequireActiveUser::class])->group(function () {
    Route::get('/auth/audit-log', [AuthAuditController::class, 'index'])->name('bherila-auth.audit.index');
    Route::post('/auth/audit-log/{id}/suspicious', [AuthAuditController::class, 'markSuspicious'])->name('bherila-auth.audit.suspicious');
    Route::get('/auth/audit-log/all', [AuthAuditController::class, 'all'])->name('bherila-auth.audit.all');
});
