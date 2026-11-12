<?php
declare(strict_types=1);
namespace MailServer\Management;

final readonly class SendLimitChange
{
    public const LABELS = ['mailbox'=>'通常メールボックス', 'legacy'=>'旧SMTP認証ID'];
    public const FIELDS = ['minute_messages','minute_recipients','hour_messages','hour_recipients'];

    private function __construct(public string $profile, public int $revision, public array $limits, public string $reason) {}

    public static function limits(array $row): array
    {
        $values = [];
        foreach (self::FIELDS as $name) {
            $value = $row[$name] ?? null;
            if ((!is_string($value) && !is_int($value)) || !preg_match('/^[1-9][0-9]{0,6}$/D', (string)$value)
                || (int)$value > 1000000) { throw new \DomainException('invalid_limits'); }
            $values[$name] = (int)$value;
        }
        if ($values['minute_messages'] > $values['hour_messages']
            || $values['minute_recipients'] > $values['hour_recipients']
            || $values['minute_messages'] > $values['minute_recipients']
            || $values['hour_messages'] > $values['hour_recipients']) {
            throw new \DomainException('invalid_limits');
        }
        return $values;
    }

    public static function revision(mixed $value): int
    {
        if ((!is_string($value) && !is_int($value)) || !preg_match('/^[1-9][0-9]{0,14}$/D', (string)$value)) {
            throw new \DomainException('invalid_revision');
        }
        return (int)$value;
    }

    public static function fromForm(array $input): self
    {
        if (array_diff(array_keys($input), [...self::FIELDS,'profile','revision','confirm_profile','reason','_csrf_token'])) {
            throw new \DomainException('invalid_input');
        }
        $profile = $input['profile'] ?? null;
        if (!is_string($profile) || !isset(self::LABELS[$profile])) { throw new \DomainException('invalid_profile'); }
        if (($input['confirm_profile'] ?? null) !== self::LABELS[$profile]) { throw new \DomainException('confirmation_required'); }
        $reason = $input['reason'] ?? null;
        if (!is_string($reason) || !preg_match('//u', $reason) || preg_match('/[\x00-\x1f\x7f]/', $reason)
            || trim($reason) === '' || strlen($reason) > 200) { throw new \DomainException('invalid_reason'); }
        return new self($profile, self::revision($input['revision'] ?? null), self::limits($input), trim($reason));
    }
}
