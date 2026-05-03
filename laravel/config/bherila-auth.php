<?php

return [
    'routes' => [
        'enabled' => true,
        'prefix' => 'api',
        'middleware' => ['web'],
    ],

    'passkeys' => [
        'table' => 'auth_passkeys',
        'rp_name' => env('WEBAUTHN_RP_NAME', env('APP_NAME', 'App')),
        'allowed_origins' => array_filter(array_map('trim', explode(',', env('WEBAUTHN_ALLOWED_ORIGINS', '')))),
        'timeout' => 60000,
    ],

    'users' => [
        'model' => config('auth.providers.users.model', App\Models\User::class),
        'name_attribute' => 'name',
        'email_attribute' => 'email',
    ],
];
