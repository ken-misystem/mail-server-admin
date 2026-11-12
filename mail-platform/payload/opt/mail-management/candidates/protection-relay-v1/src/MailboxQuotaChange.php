<?php
declare(strict_types=1);

namespace MailServer\Management\Preparation;

/** Inert request policy only. Does not establish Dovecot enforcement or usage freshness. */
final class MailboxQuotaChange
{
    public static function plan(array $input, int $currentBytes, int $usedBytes, bool $usageVerified): int
    {
        if (!$usageVerified || $currentBytes < 0 || $usedBytes < 0) { throw new \DomainException('usage_unverified'); }
        if (!is_string($input['expected_bytes'] ?? null) || $input['expected_bytes'] !== (string) $currentBytes) {
            throw new \DomainException('stale_form');
        }
        if (($input['mode'] ?? null) === 'unlimited') {
            if (($input['confirm_unlimited'] ?? null) !== '1') { throw new \DomainException('unlimited_confirmation_required'); }
            return 0;
        }
        if (($input['mode'] ?? null) !== 'limited' || !is_string($input['limit_kib'] ?? null)
            || !preg_match('/^[1-9][0-9]{0,9}$/D', $input['limit_kib'])) {
            throw new \DomainException('invalid_quota');
        }
        // New UI explicitly uses KiB, not ambiguous legacy KB. No automatic import conversion.
        $bytes = (int) $input['limit_kib'] * 1024;
        if (!is_int($bytes) || $bytes <= 0 || $bytes < $usedBytes) {
            throw new \DomainException('quota_below_usage_or_overflow');
        }
        return $bytes;
    }
}
