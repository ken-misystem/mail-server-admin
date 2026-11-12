<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableCutoverStore implements CutoverStore
{
    public function overview(AdminUser $actor, string $section, string $after = '0', array $filters = []): array
    { throw new \DomainException('schema_not_ready'); }
    public function save(AdminUser $actor, string $section, array $input): void
    { throw new \DomainException('schema_not_ready'); }
}
