<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableLegacySmtpStore implements LegacySmtpStore
{
    public function overview(AdminUser $actor,?string $before=null):array { throw new \DomainException('legacy_smtp_not_ready'); }
    public function save(AdminUser $actor,LegacySmtpMutation $mutation):void { throw new \DomainException('legacy_smtp_not_ready'); }
}
