<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final class RestrictedRecoveryRouteGuard
{
    public const TASK = 'mail';
    public const ACTION_GATE = 'plugin.local_auth_emergency';
    public const ACTION_OPTIONS = 'plugin.local_auth_emergency-options';
    public const ACTION_FINISH = 'plugin.local_auth_emergency-finish';

    public function allows(string $task, string $action): bool
    {
        if ($task === 'logout' && ($action === '' || $action === 'logout')) {
            return true;
        }
        return $task === self::TASK
            && in_array($action, [self::ACTION_GATE, self::ACTION_OPTIONS, self::ACTION_FINISH], true);
    }
}
