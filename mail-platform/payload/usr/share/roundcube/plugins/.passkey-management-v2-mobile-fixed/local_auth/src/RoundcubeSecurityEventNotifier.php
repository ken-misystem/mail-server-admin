<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use Mail_mime;
use rcmail;
use Throwable;

final class RoundcubeSecurityEventNotifier implements SecurityEventNotifier
{
    private const EVENTS = [
        self::PASSKEY_ADDED => 'A Passkey was added.',
        self::PASSKEY_DISABLED => 'A Passkey was disabled.',
        self::RECOVERY_CODES_REPLACED => 'Recovery Codes were replaced.',
        self::RECOVERY_CODE_USED => 'A Recovery Code was used to sign in.',
    ];

    public function __construct(
        private readonly rcmail $roundcube,
        private readonly RecoveryAddressRepository $recoveryAddresses,
    ) {
    }

    public function notify(string $account, string $event): bool
    {
        $account = strtolower(trim($account));
        if (!isset(self::EVENTS[$event]) || !$this->validAddress($account)) {
            return false;
        }

        try {
            $recipient = $this->recoveryAddresses->verifiedAddress($account);
            if (!$this->validAddress($recipient)) {
                return false;
            }

            $message = new Mail_mime("\r\n");
            $message->setTXTBody(
                "Security settings changed for {$account}.\r\n\r\n"
                . self::EVENTS[$event] . "\r\n"
                . 'Time: ' . gmdate('Y-m-d H:i:s') . " UTC\r\n\r\n"
                . "If this was not you, reset your account password and contact the administrator.\r\n"
                . "Webmail: https://mx.mi-sys.jp/\r\n"
            );
            $message->headers([
                'From' => $account,
                'To' => $recipient,
                'Subject' => '[mx.mi-sys.jp] Security setting changed',
                'Date' => gmdate('r'),
                'Message-ID' => $this->roundcube->gen_message_id($account),
                'Auto-Submitted' => 'auto-generated',
                'X-Auto-Response-Suppress' => 'All',
            ]);

            $error = null;
            $bodyFile = null;
            return $this->roundcube->deliver_message(
                $message,
                $account,
                [$recipient],
                $error,
                $bodyFile,
                null,
                true,
            ) === true;
        } catch (Throwable $e) {
            // Do not expose database, SMTP, address, or message details.
            return false;
        }
    }

    private function validAddress(string $value): bool
    {
        return strlen($value) >= 3
            && strlen($value) <= 320
            && strpbrk($value, "\r\n") === false
            && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
}
