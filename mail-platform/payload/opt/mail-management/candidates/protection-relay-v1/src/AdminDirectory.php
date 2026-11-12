<?php

declare(strict_types=1);

namespace MailServer\Management;

interface AdminDirectory
{
    public function byEmail(string $email): ?AdminUser;
    public function byId(string $id): ?AdminUser;
}
