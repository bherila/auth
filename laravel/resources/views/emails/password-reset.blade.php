@component('mail::message')
# Reset your {{ $appName }} password

Use the button below to reset your password.

@component('mail::button', ['url' => $resetUrl])
Reset Password
@endcomponent

If you did not request a password reset, you can ignore this email.
@endcomponent
