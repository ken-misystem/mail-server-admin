<?php
declare(strict_types=1);
namespace MailServer\Management;

interface AdminInventoryStore
{
    public function browse(AdminUser $actor, AdminInventoryFilter $filter): array;
}
