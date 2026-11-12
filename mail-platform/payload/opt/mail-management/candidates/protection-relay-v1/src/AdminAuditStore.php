<?php
declare(strict_types=1);
namespace MailServer\Management;
interface AdminAuditStore {public function search(AdminUser $actor,AdminAuditQuery $query,int $now): array;}
