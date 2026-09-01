<?php

namespace BWH\Auth\Tests\Fixtures;

/**
 * An application whose login address lives somewhere other than `email` — the case
 * `bherila-auth.users.email_attribute` exists for. `email` is still present on the
 * table and deliberately holds a different address, so a lookup that ignores the
 * configured attribute finds the wrong row (or none) rather than passing by accident.
 */
class CustomEmailUser extends User
{
    public function getEmailForPasswordReset(): string
    {
        return (string) $this->login_email;
    }
}
