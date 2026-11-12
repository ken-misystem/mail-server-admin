<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use MailServer\RoundcubeAuthManagement\RecoveryAddressRepository;
use Throwable;

final class LoopbackEmergencyRecoveryTokenDelivery implements EmergencyRecoveryTokenDelivery
{
    public function __construct(
        private readonly RecoveryAddressRepository $recoveryAddresses,
        private readonly EmergencyRecoveryMailTransport $transport,
        private readonly int $owner,
        private readonly string $account,
    ) {
    }

    public function deliver(int $roundcubeUserId, string $plaintextToken): bool
    {
        if ($roundcubeUserId <= 0 || $roundcubeUserId !== $this->owner
            || !\MailServer\RoundcubePasskeyGeneral\AccountIdentity::valid($this->account)
            || preg_match('/\Amisf_[0-9a-f]{32}_[0-9a-f]{32}\z/D', $plaintextToken) !== 1
        ) {
            return false;
        }

        try {
            $recipient = $this->recoveryAddresses->verifiedAddress(
                $this->account,
            );
            $body = "A Passkey recovery request was approved for "
                . $this->account . ".\r\n\r\n"
                . "Recovery token:\r\n{$plaintextToken}\r\n\r\n"
                . "This token expires in 15 minutes and can be used once.\r\n"
                . "It permits only registration of one replacement Passkey.\r\n"
                . "Webmail: https://mx.mi-sys.jp/\r\n\r\n"
                . "If you did not request recovery, do not use this token and contact the administrator.\r\n";

            return $this->transport->submit(
                $recipient,
                EmergencyRecoveryMailTransport::TOKEN_SUBJECT,
                $body,
            );
        } catch (Throwable $e) {
            // Do not expose lookup, address, token, or delivery details.
            return false;
        }
    }
}
