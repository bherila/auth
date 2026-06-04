<?php

namespace BWH\Auth\Services;

/**
 * Default logger that discards every auth event.
 *
 * Bound by {@see \BWH\Auth\AuthServiceProvider} when the audit driver is not
 * 'database', so that out of the box the package persists nothing.
 */
class NullAuthAuditLogger extends AbstractAuthAuditLogger {}
