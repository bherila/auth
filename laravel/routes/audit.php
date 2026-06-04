<?php

use BWH\Auth\Http\Controllers\AuthAuditController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::get('/auth/audit-log', [AuthAuditController::class, 'index'])->name('bherila-auth.audit.index');
    Route::post('/auth/audit-log/{id}/suspicious', [AuthAuditController::class, 'markSuspicious'])->name('bherila-auth.audit.suspicious');
    Route::get('/auth/audit-log/all', [AuthAuditController::class, 'all'])->name('bherila-auth.audit.all');
});
