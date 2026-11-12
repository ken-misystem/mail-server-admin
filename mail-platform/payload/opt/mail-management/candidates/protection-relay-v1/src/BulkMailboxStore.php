<?php
declare(strict_types=1);
namespace MailServer\Management;
interface BulkMailboxStore
{
    public function domains(AdminUser $actor):array;
    public function apply(AdminUser $actor,#[\SensitiveParameter] BulkMailboxPlan $plan,array $lines,string $requestId):array;
}
