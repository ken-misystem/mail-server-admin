<?php

declare(strict_types=1);

namespace MailServer\Management;

/** Request DTO contains hashes, never raw passwords; do not serialize/log its values. */
final readonly class AdminMutation
{
    public const ACTIONS = ['domain_create', 'domain_state', 'mailbox_create', 'mailbox_state', 'mailbox_password',
        'alias_create', 'alias_state', 'alias_destination', 'alias_remove', 'admin_create', 'admin_state', 'admin_password', 'admin_identity'];

    private function __construct(public string $action, #[\SensitiveParameter] private array $values) {}
    public function value(string $key): mixed { return $this->values[$key]; }
    public function __debugInfo(): array { return ['action' => $this->action, 'values' => '[omitted]']; }
    public function __serialize(): array { throw new \LogicException('mutation_not_serializable'); }

    public static function fromForm(string $action, #[\SensitiveParameter] array $input): self
    {
        if (!in_array($action, self::ACTIONS, true)) { throw new \DomainException('unknown_operation'); }
        $text = static function (string $key) use ($input): string {
            if (!is_string($input[$key] ?? null) || strlen($input[$key]) > 1024) { throw new \DomainException('invalid_input'); }
            return $input[$key];
        };
        $id = static fn (string $key): string => UserPolicyLimits::userId($text($key));
        $state = static function (string $key) use ($text): bool {
            $value = $text($key); if (!in_array($value, ['0', '1'], true)) { throw new \DomainException('invalid_input'); }
            return $value === '1';
        };
        $hash = static fn (bool $mailbox): string => (new AdminPasswordEncoder())->encode($text('new_password'), $text('repeat_password'), $mailbox);
        $values = match ($action) {
            'domain_create' => ['name' => AdminMailPolicy::domain($text('name'))],
            'domain_state', 'mailbox_state', 'alias_state' => ['id' => $id('id'), 'enabled' => $state('enabled'), 'confirm' => $text('confirm_target')],
            'mailbox_create' => ['domain_id' => $id('domain_id'), 'local' => AliasPolicy::registrationLocal(AdminMailPolicy::localPart($text('local_part'))), 'hash' => $hash(true)],
            'mailbox_password' => ['id' => $id('id'), 'confirm' => $text('confirm_target'), 'hash' => $hash(true)],
            'alias_create' => ['domain_id' => $id('domain_id'), 'local' => AliasPolicy::registrationLocal(AdminMailPolicy::localPart($text('local_part'))), 'destination_id' => $id('destination_id')],
            'alias_destination' => ['id' => $id('id'), 'confirm' => $text('confirm_target'), 'destination_id' => $id('destination_id')],
            'alias_remove' => ['id' => $id('id'), 'confirm' => $text('confirm_target')],
            'admin_create' => ['email' => AdminPolicy::identity(trim($text('email'))), 'hash' => $hash(false)],
            'admin_state' => ['id' => $id('id'), 'confirm' => $text('confirm_target'), 'enabled' => $state('enabled'), 'system_admin' => $state('system_admin')],
            'admin_password' => ['id' => $id('id'), 'confirm' => $text('confirm_target'), 'hash' => $hash(false)],
            'admin_identity' => ['id' => $id('id'), 'confirm' => $text('confirm_target'), 'email' => AdminPolicy::identity(trim($text('email')))],
        };
        return new self($action, $values);
    }
}
