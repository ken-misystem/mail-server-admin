<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableAdminAuditStore implements AdminAuditStore
{
    public function search(AdminUser $actor,AdminAuditQuery $query,int $now): array {throw new \DomainException('audit_unavailable');}
}
