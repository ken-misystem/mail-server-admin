<?php

declare(strict_types=1);

/** Decode only the fixed opt-in bit from Roundcube's serialized preferences. */
final class PilotPreferenceDecoder
{
    private const PREF_KEY = 'junk_digest_daily_opt_in_v1';
    private const MAX_BYTES = 65536;

    public static function enabled(mixed $raw): bool
    {
        if (!is_string($raw) || $raw === '' || strlen($raw) > self::MAX_BYTES) {
            return false;
        }

        try {
            // The stored format is PHP serialization. Never instantiate classes.
            $decoded = @unserialize($raw, [
                'allowed_classes' => false,
                'max_depth' => 16,
            ]);
        } catch (Throwable) {
            return false;
        }

        return is_array($decoded) && ($decoded[self::PREF_KEY] ?? null) === true;
    }
}
