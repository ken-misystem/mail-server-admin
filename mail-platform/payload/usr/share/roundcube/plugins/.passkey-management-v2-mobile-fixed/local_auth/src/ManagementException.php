<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use RuntimeException;

final class ManagementException extends RuntimeException
{
    private const SAFE_CODES = [
        'authentication',
        'input',
        'limit',
        'last-factor',
        'rate-limit',
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
