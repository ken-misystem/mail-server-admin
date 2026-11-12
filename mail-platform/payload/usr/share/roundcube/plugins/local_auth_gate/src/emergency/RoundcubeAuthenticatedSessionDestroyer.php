<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use rcmail;

final class RoundcubeAuthenticatedSessionDestroyer implements EmergencyRecoveryAuthenticatedSessionDestroyer
{
    public function __construct(private readonly rcmail $roundcube)
    {
    }

    public function destroy(): bool
    {
        $this->roundcube->kill_session();
        // Roundcube intentionally leaves only a temporary language session.
        // Authentication identity and the in-memory IMAP password must be gone.
        return ($_SESSION['temp'] ?? null) === true
            && !array_key_exists('user_id', $_SESSION)
            && !array_key_exists('username', $_SESSION)
            && !array_key_exists('password', $_SESSION);
    }
}
