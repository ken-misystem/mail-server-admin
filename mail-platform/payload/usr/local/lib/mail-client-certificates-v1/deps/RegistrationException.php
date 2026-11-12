<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

use RuntimeException;
use Throwable;

final class RegistrationException extends RuntimeException
{
    private const SAFE_DIAGNOSTIC_CODES = [
        'request',
        'setup',
        'state',
        'input',
        'response-decode',
        'options-encode',
        'options-decode',
        'response-type',
        'ceremony-challenge',
        'ceremony-origin',
        'ceremony-rp',
        'ceremony-user-verification',
        'ceremony-user-presence',
        'ceremony-algorithm',
        'ceremony-attestation',
        'ceremony-signature',
        'ceremony-counter',
        'ceremony-other',
        'record-decode',
        'record-type',
        'record-encode',
        'credential',
        'storage',
        'internal',
    ];

    public readonly string $diagnosticCode;

    public function __construct(
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
        string $diagnosticCode = 'internal',
    ) {
        parent::__construct($message, $code, $previous);
        $this->diagnosticCode = in_array($diagnosticCode, self::SAFE_DIAGNOSTIC_CODES, true)
            ? $diagnosticCode
            : 'internal';
    }
}
