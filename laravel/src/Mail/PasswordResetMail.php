<?php

namespace Bherila\AuthLaravel\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class PasswordResetMail extends Mailable
{
    use Queueable;
    use SerializesModels;

    public function __construct(
        public readonly string $resetUrl,
        public readonly string $appName,
    ) {}

    public function build(): self
    {
        return $this
            ->subject("Reset your {$this->appName} password")
            ->view('bherila-auth::emails.password-reset', [
                'resetUrl' => $this->resetUrl,
                'appName' => $this->appName,
            ]);
    }
}
