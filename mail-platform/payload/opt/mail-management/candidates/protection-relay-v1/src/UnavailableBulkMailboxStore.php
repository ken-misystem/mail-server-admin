<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableBulkMailboxStore implements BulkMailboxStore
{
    public function domains(AdminUser $actor):array{throw new \DomainException('bulk_storage_unavailable');}
    public function apply(AdminUser $actor,BulkMailboxPlan $plan,array $lines,string $requestId):array{throw new \DomainException('bulk_storage_unavailable');}
}
