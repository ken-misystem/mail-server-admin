<?php
declare(strict_types=1);
namespace MailServer\Management;
interface LegacySmtpStore
{
    public function overview(AdminUser $actor,?string $before=null): array;
    public function save(AdminUser $actor,LegacySmtpMutation $mutation): void;
}
