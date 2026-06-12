<?php

namespace BWH\Auth\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class PasswordResetNoticeMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public string $appName,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: strtr(config('bherila-auth.password_resets.notice_subject', 'Your :app password was changed'), [':app' => $this->appName]),
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'bherila-auth::emails.password-reset-notice',
        );
    }
}
