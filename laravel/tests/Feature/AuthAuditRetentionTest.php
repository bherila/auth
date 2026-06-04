<?php

namespace BWH\Auth\Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Tests\TestCase;

class AuthAuditRetentionTest extends TestCase
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

    public function test_nothing_is_pruned_when_retention_is_null(): void
    {
        config(['bherila-auth.audit.retention_days' => null]);
        $this->makeLog(3650);

        $pruned = (new AuthAuditLog)->pruneAll();

        $this->assertSame(0, $pruned);
        $this->assertSame(1, AuthAuditLog::count());
    }

    public function test_old_rows_are_pruned_when_retention_is_set(): void
    {
        config(['bherila-auth.audit.retention_days' => 30]);
        $this->makeLog(60); // older than retention -> pruned
        $this->makeLog(5);  // within retention -> kept

        $pruned = (new AuthAuditLog)->pruneAll();

        $this->assertSame(1, $pruned);
        $this->assertSame(1, AuthAuditLog::count());
    }
}
