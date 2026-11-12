<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class AdminUserProvider implements UserProviderInterface
{
    public function __construct(private readonly AdminDirectory $directory) {}

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        return $this->directory->byEmail($identifier) ?? throw new UserNotFoundException('admin_not_found');
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof AdminUser) { throw new UnsupportedUserException('unsupported_admin'); }
        return $this->directory->byId($user->id) ?? throw new UserNotFoundException('admin_not_found');
    }

    public function supportsClass(string $class): bool { return $class === AdminUser::class; }
}
