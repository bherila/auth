<?php

use BWH\Auth\Http\Controllers\AuthenticatedPasswordController;
use BWH\Auth\Http\Controllers\PasswordResetController;
use BWH\Auth\Http\Controllers\TwoFactorController;
use Illuminate\Support\Facades\Route;

Route::post('/auth/forgot-password', [PasswordResetController::class, 'sendResetLink']);
Route::post('/auth/reset-password', [PasswordResetController::class, 'reset']);

Route::middleware('auth')->post('/change-password', [AuthenticatedPasswordController::class, 'update']);

Route::post('/auth/two-factor/verify', [TwoFactorController::class, 'verify']);
Route::post('/auth/two-factor/resend', [TwoFactorController::class, 'resend']);
Route::get('/auth/two-factor/confirm/{token}', [TwoFactorController::class, 'confirm'])->name('bherila-auth.two-factor.confirm');
Route::match(['GET', 'POST'], '/auth/two-factor/report/{token}', [TwoFactorController::class, 'report'])->name('bherila-auth.two-factor.report');
