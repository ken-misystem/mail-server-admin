<?php

declare(strict_types=1);
namespace MailServer\AliasUi;

/** Existing authenticated Roundcube principal only; never accept identity or limits from POST. */
final class RequestPolicy
{
    public static function actor(bool $enabled, array $pilots, mixed $id, mixed $sessionName, mixed $mailbox): string
    {
        $validId = (is_int($id) && $id > 0) || (is_string($id) && preg_match('/\A[1-9][0-9]{0,19}\z/D', $id));
        if (!$enabled || !$validId || !is_string($mailbox) || !is_string($sessionName)
            || strlen($mailbox) > 320 || preg_match('/[\s\x00-\x1f\x7f]/', $mailbox)
            || substr_count($mailbox, '@') !== 1 || !hash_equals(strtolower($sessionName), strtolower($mailbox))
            || ($pilots !== ['*'] && !in_array(strtolower($mailbox), $pilots, true))) {
            throw new \DomainException('not_authorized');
        }
        return $mailbox;
    }

    public static function command(array $input): array
    {
        if (array_intersect(['user_id', 'mailbox', 'domain', 'destination', 'limit'], array_keys($input))) {
            throw new \DomainException('invalid_request');
        }
        $kind = $input['kind'] ?? null;
        if ($kind === 'list' && array_keys($input) === ['kind']) { return ['kind' => $kind]; }
        if ($kind === 'preferences' && count($input) === 3
            && is_bool($input['ignore_dots'] ?? null) && is_bool($input['allow_plus'] ?? null)) {
            return ['kind' => $kind, 'ignore_dots' => $input['ignore_dots'], 'allow_plus' => $input['allow_plus']];
        }
        if ($kind === 'create' && is_string($input['local_part'] ?? null) && strlen($input['local_part']) <= 64
            && count($input) === 2) { return ['kind' => $kind, 'local_part' => $input['local_part']]; }
        $id = $input['id'] ?? null;
        if (!is_string($id) || !preg_match('/\A[1-9][0-9]{0,19}\z/D', $id)
            || (strlen($id) === 20 && strcmp($id, '18446744073709551615') > 0)) {
            throw new \DomainException('invalid_request');
        }
        if ($kind === 'state' && is_bool($input['enabled'] ?? null) && count($input) === 3) {
            return ['kind' => $kind, 'id' => $id, 'enabled' => $input['enabled']];
        }
        if ($kind === 'remove' && ($input['confirm'] ?? null) === 'remove' && count($input) === 3) {
            return ['kind' => $kind, 'id' => $id];
        }
        throw new \DomainException('invalid_request');
    }
}
