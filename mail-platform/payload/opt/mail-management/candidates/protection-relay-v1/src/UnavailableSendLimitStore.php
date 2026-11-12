<?php
declare(strict_types=1);
namespace MailServer\Management;

final class UnavailableSendLimitStore implements SendLimitStore
{
    public function overview(AdminUser $actor): array { throw new \RuntimeException('send_limits_unavailable'); }
    public function save(AdminUser $actor, SendLimitChange $change): void { throw new \RuntimeException('send_limits_unavailable'); }
}
