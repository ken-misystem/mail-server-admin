<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryAuthenticatedSessionDestroyer
{
    /** Return false on a post-commit failure; do not expose raw errors. */
    public function destroy(): bool;
}
