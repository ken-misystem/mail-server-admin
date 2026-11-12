<?php
declare(strict_types=1);
namespace MailServer\Management;

interface SendLimitStore
{
    public function overview(AdminUser $actor): array;
    public function save(AdminUser $actor, SendLimitChange $change): void;
}
