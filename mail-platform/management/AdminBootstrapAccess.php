<?php
declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Security\Core\Exception\DisabledException;

/** Root-issued, expiring access to the isolated first-install UI. */
final class AdminBootstrapAccess
{
    public static function check(AdminUser $user): void
    {
        $path = '/etc/mail-platform/initial-access.json';
        if (!file_exists($path) && !is_link($path)) { return; }
        $stream = @fopen($path, 'rb');
        if ($stream === false) { throw new DisabledException('initial_access_unavailable'); }
        try {
            $metadata = fstat($stream);
            $named = lstat($path);
            if (!is_array($metadata) || !is_array($named)
                || ($metadata['mode'] & 0170000) !== 0100000 || $metadata['uid'] !== 0
                || $metadata['nlink'] !== 1 || ($metadata['mode'] & 0022) !== 0
                || $metadata['size'] > 4096 || $named['ino'] !== $metadata['ino']
                || $named['dev'] !== $metadata['dev'] || is_link($path)) {
                throw new DisabledException('initial_access_trust');
            }
            $value = json_decode(stream_get_contents($stream, 4097), true, 16, JSON_THROW_ON_ERROR);
            self::validate($user, $value, time());
        } catch (DisabledException $error) {
            throw $error;
        } catch (\Throwable) {
            throw new DisabledException('initial_access_invalid');
        } finally { fclose($stream); }
    }

    public static function validate(AdminUser $user, mixed $value, int $now): void
    {
        if (!is_array($value) || ($value['format'] ?? null) !== 1) {
            throw new DisabledException('initial_access_invalid');
        }
        if (($value['phase'] ?? null) === 'complete') { return; }
        $administrator = $value['administrator'] ?? null;
        if (($value['phase'] ?? null) !== 'setup' || !is_array($administrator)
            || ($administrator['id'] ?? null) !== $user->id
            || ($administrator['email'] ?? null) !== $user->getUserIdentifier()
            || ($administrator['epoch'] ?? null) !== $user->epoch
            || !is_string($administrator['password_fingerprint'] ?? null)
            || !hash_equals($administrator['password_fingerprint'], hash('sha256', $user->getPassword() ?? ''))
            || !is_int($value['issued_at'] ?? null) || !is_int($value['expires_at'] ?? null)
            || $value['issued_at'] > $now || $value['expires_at'] <= $now
            || $value['expires_at'] - $value['issued_at'] !== 1800) {
            throw new DisabledException('initial_access_expired_or_reissued');
        }
    }
}
