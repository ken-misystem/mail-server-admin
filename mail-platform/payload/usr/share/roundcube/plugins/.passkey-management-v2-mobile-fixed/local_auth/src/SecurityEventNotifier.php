<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface SecurityEventNotifier
{
    public const PASSKEY_ADDED = 'passkey-added';
    public const PASSKEY_DISABLED = 'passkey-disabled';
    public const RECOVERY_CODES_REPLACED = 'recovery-codes-replaced';
    public const RECOVERY_CODE_USED = 'recovery-code-used';

    public function notify(string $account, string $event): bool;
}
