<?php
declare(strict_types=1);
namespace MailServer\Management;
interface LogViewStore { public function search(LogViewQuery $query,int $now): array; }
