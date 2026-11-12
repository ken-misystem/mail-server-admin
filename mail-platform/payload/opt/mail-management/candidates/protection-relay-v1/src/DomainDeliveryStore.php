<?php
declare(strict_types=1);
namespace MailServer\Management;

interface DomainDeliveryStore
{
    public function overview(AdminUser $actor): array;
    public function save(AdminUser $actor,string $id,bool $followMx,string $version,string $confirm): void;
}
