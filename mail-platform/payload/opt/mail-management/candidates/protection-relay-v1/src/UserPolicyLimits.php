<?php

declare(strict_types=1);

namespace MailServer\Management;

final readonly class UserPolicyLimits
{
    public function __construct(public int $aliasLimit, public int $popLimit, public int $pollSeconds)
    {
        if ($aliasLimit < 0 || $aliasLimit > 1000 || $popLimit < 0 || $popLimit > 100
            || $pollSeconds < 60 || $pollSeconds > 86400) { throw new \DomainException('invalid_policy_limits'); }
    }

    public static function fromForm(array $input): self
    {
        $values = [];
        if(array_key_exists('pop_poll_seconds',$input)){throw new \DomainException('invalid_policy_limits');}
        foreach (['alias_limit', 'pop_account_limit'] as $name) {
            $value = $input[$name] ?? null;
            if (!is_string($value) || !preg_match('/^(0|[1-9][0-9]{0,5})$/D', $value)) {
                throw new \DomainException('invalid_policy_limits');
            }
            $values[] = (int) $value;
        }
        return new self($values[0],$values[1],300); // Poll timing is not an administrator form control.
    }

    public static function userId(string $id): string
    {
        if (!preg_match('/^[1-9][0-9]{0,19}$/D', $id)
            || (strlen($id) === 20 && strcmp($id, '18446744073709551615') > 0)) {
            throw new \DomainException('invalid_user_id');
        }
        return $id;
    }
}
