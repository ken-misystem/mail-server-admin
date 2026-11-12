<?php
declare(strict_types=1);
namespace MailServer\Management;

interface OperationsStatusStore
{
    public function read(int $now): OperationsSnapshot;
}
