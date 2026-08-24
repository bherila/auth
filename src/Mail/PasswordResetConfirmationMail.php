<?php

namespace BWH\Auth\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class PasswordResetConfirmationMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public string $resetUrl,
        public string $appName,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: strtr(config('bherila-auth.password_resets.mail_subject', 'Reset your :app password'), [':app' => $this->appName]),
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'bherila-auth::emails.password-reset',
        );
    }
}
