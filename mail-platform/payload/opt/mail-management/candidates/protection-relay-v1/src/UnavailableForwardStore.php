<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableForwardStore implements ForwardStore
{
    public function lookup(AdminUser $actor,string $userId):?array{throw new \RuntimeException('forward_store_unavailable');}
    public function save(AdminUser $actor,string $userId,int $revision,array $destinations,bool $enabled,string $confirmation,string $requestId):array{throw new \RuntimeException('forward_store_unavailable');}
}
