<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/** Independent administrator principal; never a Dovecot/Roundcube mailbox user. */
final class AdminUser implements UserInterface, PasswordAuthenticatedUserInterface, EquatableInterface
{
    private readonly string $fingerprint;

    public function __construct(
        public readonly string $id,
        private readonly string $email,
        #[\SensitiveParameter] private readonly ?string $passwordHash,
        public readonly bool $active,
        public readonly bool $systemAdmin,
        public readonly string $epoch,
    ) {
        if (!self::decimal($id) || !self::decimal($epoch)
            || AdminPolicy::identity($email) !== $email || !$passwordHash) {
            throw new \DomainException('invalid_admin_record');
        }
        $this->fingerprint = hash('sha256', $passwordHash);
    }

    public function getUserIdentifier(): string { return $this->email; }
    public function getPassword(): ?string { return $this->passwordHash; }
    public function getRoles(): array
    {
        if (!$this->active) { return []; }
        return $this->systemAdmin ? ['ROLE_MAIL_ADMIN', 'ROLE_MAIL_SYSTEM_ADMIN'] : ['ROLE_MAIL_ADMIN'];
    }
    public function eraseCredentials(): void {}

    public function isEqualTo(UserInterface $user): bool
    {
        return $user instanceof self && $user->active && $this->active
            && $this->id === $user->id && $this->email === $user->email
            && $this->epoch === $user->epoch && $this->systemAdmin === $user->systemAdmin
            && hash_equals($this->fingerprint, $user->fingerprint);
    }

    /** Standard session refresh needs a fingerprint, not the reusable password hash. */
    public function __serialize(): array
    {
        return ['id' => $this->id, 'email' => $this->email, 'active' => $this->active,
            'system_admin' => $this->systemAdmin, 'epoch' => $this->epoch,
            'fingerprint' => $this->fingerprint];
    }

    public function __unserialize(array $data): void
    {
        if (!is_string($data['id'] ?? null) || !self::decimal($data['id'])
            || !is_string($data['epoch'] ?? null) || !self::decimal($data['epoch'])
            || !is_string($data['email'] ?? null) || AdminPolicy::identity($data['email']) !== $data['email']
            || !is_bool($data['active'] ?? null) || !is_bool($data['system_admin'] ?? null)
            || !is_string($data['fingerprint'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/D', $data['fingerprint'])) {
            throw new \DomainException('invalid_admin_session');
        }
        $this->id = $data['id']; $this->email = $data['email'];
        $this->active = $data['active']; $this->systemAdmin = $data['system_admin'];
        $this->epoch = $data['epoch']; $this->fingerprint = $data['fingerprint'];
        $this->passwordHash = null;
    }

    private static function decimal(string $value): bool
    {
        return (bool) preg_match('/^[1-9][0-9]{0,19}$/D', $value)
            && (strlen($value) < 20 || strcmp($value, '18446744073709551615') <= 0);
    }
}
