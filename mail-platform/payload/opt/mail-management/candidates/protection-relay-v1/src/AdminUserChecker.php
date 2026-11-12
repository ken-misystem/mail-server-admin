<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class AdminUserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof AdminUser || !$user->active) { throw new DisabledException('admin_disabled'); }
    }
    public function checkPostAuth(UserInterface $user): void { $this->checkPreAuth($user); }
}
