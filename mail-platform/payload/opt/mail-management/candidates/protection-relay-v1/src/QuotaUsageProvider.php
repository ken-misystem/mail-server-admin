<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Implementations read trusted collector output, never HTTP parameters. No shell/SQL in the web process. */
interface QuotaUsageProvider
{
    public function lookup(string $id, string $email, int $configuredBytes, int $now): array;
}
