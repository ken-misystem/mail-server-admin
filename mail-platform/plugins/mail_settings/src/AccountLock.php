<?php
declare(strict_types=1);
namespace MiSystem\MailSettings;

/** SPDX-License-Identifier: MIT */
final class AccountLock
{
    private mixed $handle;

    public function __construct(string $directory, string $owner)
    {
        $info = lstat($directory);
        $uid = posix_geteuid();
        if (!$info || is_link($directory) || !is_dir($directory) || $info['uid'] !== $uid
            || ($info['mode'] & 0777) !== 0700) throw new \DomainException('lock_unavailable');
        $path = $directory . '/' . hash('sha256', $owner) . '.lock';
        $mask = umask(0077);
        try { $this->handle = fopen($path, 'c+'); }
        finally { umask($mask); }
        if (!is_resource($this->handle)) throw new \DomainException('lock_unavailable');
        $opened = fstat($this->handle);
        $named = lstat($path);
        if (!$opened || !$named || is_link($path) || !is_file($path) || $opened['uid'] !== $uid
            || ($opened['mode'] & 0777) !== 0600 || $opened['nlink'] !== 1
            || $opened['ino'] !== $named['ino'] || $opened['dev'] !== $named['dev']) {
            throw new \DomainException('lock_unavailable');
        }
        if (!flock($this->handle, LOCK_EX | LOCK_NB)) throw new \DomainException('settings_busy');
    }

    public function __destruct()
    {
        if (isset($this->handle) && is_resource($this->handle)) fclose($this->handle);
    }
}
