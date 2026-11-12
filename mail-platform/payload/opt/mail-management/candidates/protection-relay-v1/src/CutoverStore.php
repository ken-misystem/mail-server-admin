<?php
declare(strict_types=1);
namespace MailServer\Management;

interface CutoverStore
{
    public function overview(AdminUser $actor, string $section, string $after = '0', array $filters = []): array;
    public function save(AdminUser $actor, string $section, array $input): void;
}
