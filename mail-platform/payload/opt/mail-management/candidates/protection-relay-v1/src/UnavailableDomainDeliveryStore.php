<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableDomainDeliveryStore implements DomainDeliveryStore
{
    public function overview(AdminUser $actor): array { throw new \DomainException('routing_storage_unavailable'); }
    public function save(AdminUser $actor,string $id,bool $followMx,string $version,string $confirm): void
    { throw new \DomainException('routing_storage_unavailable'); }
}
