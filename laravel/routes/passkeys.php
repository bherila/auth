<?php

use Bherila\AuthLaravel\Http\Controllers\PasskeyController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::get('/passkeys', [PasskeyController::class, 'index']);
    Route::post('/passkeys/register/options', [PasskeyController::class, 'registrationOptions']);
    Route::post('/passkeys/register', [PasskeyController::class, 'register']);
    Route::delete('/passkeys/{id}', [PasskeyController::class, 'destroy']);
});

Route::post('/passkeys/auth/options', [PasskeyController::class, 'authOptions']);
Route::post('/passkeys/auth', [PasskeyController::class, 'authenticate']);
