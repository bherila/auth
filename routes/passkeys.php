<?php

use BWH\Auth\Http\Controllers\PasskeyController;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use Illuminate\Support\Facades\Route;

// Credential management sits behind RequireActiveUser as well as `auth`: enrolling or
// removing a passkey decides future logins, so a pending or disabled account must not
// reach it even if it still holds a session from before its state changed.
Route::middleware(['auth', RequireActiveUser::class])->group(function () {
    Route::get('/passkeys', [PasskeyController::class, 'index']);
    Route::post('/passkeys/register/options', [PasskeyController::class, 'registrationOptions']);
    Route::post('/passkeys/register', [PasskeyController::class, 'register']);
    Route::delete('/passkeys/{id}', [PasskeyController::class, 'destroy']);
});

Route::post('/passkeys/auth/options', [PasskeyController::class, 'authOptions']);
Route::post('/passkeys/auth', [PasskeyController::class, 'authenticate']);
