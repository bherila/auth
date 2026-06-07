<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Tests\TestCase;

class PruneAuthAuditLogCommandTest extends TestCase
{
    private function makeLog(int $ageInDays): AuthAuditLog
    {
        $log = AuthAuditLog::create([
            'event' => AuthAuditLog::EVENT_LOGIN_SUCCEEDED,
            'succeeded' => true,
        ]);

        $timestamp = now()->subDays($ageInDays);
        AuthAuditLog::query()->whereKey($log->getKey())->update([
            'created_at' => $timestamp,
            'updated_at' => $timestamp,
        ]);

        return $log->refresh();
    }

    public function test_command_prunes_old_rows_when_retention_is_set(): void
    {
        config(['bherila-auth.audit.retention_days' => 30]);
        $old = $this->makeLog(60); // older than retention -> pruned
        $new = $this->makeLog(5);  // within retention -> kept

        $this->artisan('bherila-auth:prune-audit-log')->assertSuccessful();

        $this->assertFalse(AuthAuditLog::whereKey($old->getKey())->exists());
        $this->assertTrue(AuthAuditLog::whereKey($new->getKey())->exists());
        $this->assertSame(1, AuthAuditLog::count());
    }

    public function test_command_does_not_prune_when_retention_is_null(): void
    {
        config(['bherila-auth.audit.retention_days' => null]);
        $this->makeLog(3650);

        $this->artisan('bherila-auth:prune-audit-log')->assertSuccessful();

        $this->assertSame(1, AuthAuditLog::count());
    }
}
