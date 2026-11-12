<?php
declare(strict_types=1);
namespace MailServer\Management;
interface QueueAdminStore
{
    public function browse(array $filters): array;
    public function apply(array $request): array;
}
