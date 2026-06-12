<?php

namespace BWH\Auth\Console;

use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Console\Command;

class PruneAuthAuditLogCommand extends Command
{
    protected $signature = 'bherila-auth:prune-audit-log';

    protected $description = 'Delete auth audit log rows older than the configured retention window (bherila-auth.audit.retention_days). No-op when retention_days is null.';

    public function handle(): int
    {
        $count = (new AuthAuditLog)->pruneAll();
        $this->info("Pruned {$count} auth audit log row(s).");

        return self::SUCCESS;
    }
}
