<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryMailTransport
{
    public const TOKEN_SUBJECT = '[mx.mi-sys.jp] Passkey recovery token';
    public const COMPLETION_SUBJECT = '[mx.mi-sys.jp] Passkey recovery completed';

    /** Submit through the fixed local transport without logging message data. */
    public function submit(string $recipient, string $subject, string $body): bool;
}
