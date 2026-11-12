<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use RuntimeException;

final class EmergencyRecoveryException extends RuntimeException
{
    private const SAFE_CODES = [
        'authentication',
        'delivery',
        'input',
        'rate-limit',
        'setup',
        'state',
        'storage',
        'internal',
    ];

    public readonly string $diagnosticCode;

    public function __construct(string $message = '', string $diagnosticCode = 'internal')
    {
        parent::__construct($message);
        $this->diagnosticCode = in_array($diagnosticCode, self::SAFE_CODES, true)
            ? $diagnosticCode
            : 'internal';
    }
}
