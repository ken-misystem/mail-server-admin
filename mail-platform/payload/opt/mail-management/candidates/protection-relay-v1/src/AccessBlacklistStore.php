<?php
declare(strict_types=1);
namespace MailServer\Management;

interface AccessBlacklistStore
{
    public function overview(): array;
    public function release(array $request): array;
}
