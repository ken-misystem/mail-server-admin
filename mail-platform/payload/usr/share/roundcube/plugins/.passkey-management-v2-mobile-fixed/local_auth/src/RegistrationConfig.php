<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

final class RegistrationConfig
{
    public const RP_ID = 'mx.mi-sys.jp';
    public const RP_NAME = 'MI-SYS Webmail';
    public const ORIGIN = 'https://mx.mi-sys.jp';
    public const CHALLENGE_TTL_SECONDS = 300;
    public const MAX_REQUEST_BYTES = 131072;
    public const MAX_RESPONSE_BYTES = 65536;
    public const MAX_RECORD_BYTES = 131072;
    public const MAX_CREDENTIAL_ID_BYTES = 1023;
    public const MAX_LABEL_CHARACTERS = 100;

    private function __construct()
    {
    }
}
