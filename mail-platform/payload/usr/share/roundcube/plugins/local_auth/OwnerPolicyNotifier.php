<?php
declare(strict_types=1);
namespace MailServer\RoundcubePasskeyGeneral;

use MailServer\RoundcubeAuthManagement\MailAuthRecoveryAddressRepository;

final class OwnerPolicyNotifier
{
    public function notify(\rcmail $rc, string $account, bool $required): bool
    {
        try {
            $account = AccountIdentity::canonical($account);
            $recipient = (new MailAuthRecoveryAddressRepository())->verifiedAddress($account);
            $message = new \Mail_mime("\r\n");
            $message->setTXTBody("Passkey login requirement changed for {$account}.\r\nRequired: "
                . ($required ? 'yes' : 'no') . "\r\nTime: " . gmdate('Y-m-d H:i:s') . " UTC\r\n"
                . "If this was not you, reset your password and contact the administrator.\r\n");
            $message->headers(['From'=>$account,'To'=>$recipient,'Subject'=>'[mx.mi-sys.jp] Passkey login policy changed',
                'Date'=>gmdate('r'),'Message-ID'=>$rc->gen_message_id($account),'Auto-Submitted'=>'auto-generated','X-Auto-Response-Suppress'=>'All']);
            $error = $bodyFile = null;
            return $rc->deliver_message($message,$account,[$recipient],$error,$bodyFile,null,true) === true;
        } catch (\Throwable $error) { return false; }
    }
}
