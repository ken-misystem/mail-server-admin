<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

final class AdminPasswordEncoder
{
    public function encode(#[\SensitiveParameter] string $password, #[\SensitiveParameter] string $repeat, bool $mailbox): string
    {
        if (strlen($password) < 12 || strlen($password) > 1024 || preg_match('/[\x00-\x1f\x7f]/', $password)
            || !hash_equals($password, $repeat)) { throw new \DomainException('invalid_new_password'); }
        // Standard PHP/Dovecot PHC and Symfony hashing; no custom crypto.
        $hash = $mailbox ? password_hash($password, PASSWORD_ARGON2ID) : (new NativePasswordHasher())->hash($password);
        if (!is_string($hash) || strlen($hash) > 245) { throw new \DomainException('password_hash_unavailable'); }
        return $mailbox ? '{ARGON2ID}' . $hash : $hash;
    }
}
