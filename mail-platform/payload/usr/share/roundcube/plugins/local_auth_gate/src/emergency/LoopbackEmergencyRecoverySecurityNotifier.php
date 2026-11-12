<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use MailServer\RoundcubeAuthManagement\RecoveryAddressRepository;
use Throwable;

final class LoopbackEmergencyRecoverySecurityNotifier implements EmergencyRecoverySecurityNotifier
{
    public function __construct(
        private readonly RecoveryAddressRepository $recoveryAddresses,
        private readonly EmergencyRecoveryMailTransport $transport,
    ) {
    }

    public function notify(string $accountIdentifier): bool
    {
        $account = strtolower(trim($accountIdentifier));
        if (!\MailServer\RoundcubePasskeyGeneral\AccountIdentity::valid($account)) {
            return false;
        }

        try {
            $recipient = $this->recoveryAddresses->verifiedAddress($account);
            $body = "Emergency Passkey recovery completed for {$account}.\r\n\r\n"
                . "One replacement Passkey was registered.\r\n"
                . "Older Passkeys were disabled and unused Recovery Codes were revoked.\r\n"
                . "Existing webmail sessions were invalidated.\r\n"
                . "A fresh password and Passkey login is required.\r\n\r\n"
                . "If this was not you, reset the account password and contact the administrator.\r\n"
                . "Webmail: https://mx.mi-sys.jp/\r\n";

            return $this->transport->submit(
                $recipient,
                EmergencyRecoveryMailTransport::COMPLETION_SUBJECT,
                $body,
            );
        } catch (Throwable $e) {
            // Do not expose lookup, address, or delivery details.
            return false;
        }
    }
}
