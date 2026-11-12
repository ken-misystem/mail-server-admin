<?php
declare(strict_types=1);

namespace MailServer\Management\Preparation;

use MailServer\Management\AdminMailPolicy;
use MailServer\Management\UserPolicyLimits;

/** Inert candidate: no DB, DNS, filesystem, authentication or routing writes.
 * A future authenticated adapter must obtain the snapshot under alias_namespace
 * + admin_roles locks, revalidate the actor/epoch, audit and commit atomically.
 * This policy is not an authorization boundary or a deployed endpoint.
 */
final class DomainAliasChange
{
    /** @return array{operation:string,alias_domain:string,target_domain_id:string,active:bool} */
    public static function plan(array $input, array $snapshot): array
    {
        $text = static function (string $key) use ($input): string {
            if (!is_string($input[$key] ?? null) || strlen($input[$key]) > 253) {
                throw new \DomainException('invalid_input');
            }
            return $input[$key];
        };
        $operation = $text('operation');
        if (!in_array($operation, ['create', 'set_state', 'repoint'], true)) {
            throw new \DomainException('unknown_operation');
        }
        $alias = AdminMailPolicy::domain($text('alias_domain'));
        if ($text('confirm_alias') !== $alias) { throw new \DomainException('confirmation_required'); }
        $targetId = UserPolicyLimits::userId($text('target_domain_id'));
        $state = $text('enabled');
        if (!in_array($state, ['0', '1'], true)) { throw new \DomainException('invalid_state'); }
        if ($operation === 'create' && $state !== '0') { throw new \DomainException('create_disabled_only'); }

        if (!is_array($snapshot['domains'] ?? null) || !is_array($snapshot['aliases'] ?? null)
            || ($snapshot['complete'] ?? null) !== true) {
            throw new \DomainException('snapshot_incomplete');
        }
        $domains = []; $names = []; $aliases = [];
        foreach ($snapshot['domains'] as $row) {
            self::rowShape($row, ['id', 'name', 'active']);
            $id = UserPolicyLimits::userId($row['id']);
            $name = AdminMailPolicy::domain($row['name']);
            if (isset($domains[$id]) || isset($names[$name])) { throw new \DomainException('snapshot_conflict'); }
            $domains[$id] = ['name' => $name, 'active' => self::state($row['active'])];
            $names[$name] = true;
        }
        foreach ($snapshot['aliases'] as $row) {
            self::rowShape($row, ['alias_domain', 'target_domain_id', 'active']);
            $name = AdminMailPolicy::domain($row['alias_domain']);
            $id = UserPolicyLimits::userId($row['target_domain_id']);
            if (isset($aliases[$name]) || isset($names[$name]) || !isset($domains[$id])) {
                throw new \DomainException('snapshot_conflict');
            }
            $aliases[$name] = ['target_domain_id' => $id, 'active' => self::state($row['active'])];
        }
        if (!isset($domains[$targetId])) { throw new \DomainException('primary_domain_required'); }
        if (isset($names[$alias])) { throw new \DomainException('namespace_unavailable'); }
        $current = $aliases[$alias] ?? null;
        if ($operation === 'create') {
            if ($current !== null) { throw new \DomainException('namespace_unavailable'); }
        } else {
            if ($current === null) { throw new \DomainException('alias_missing'); }
            $expectedId = UserPolicyLimits::userId($text('expected_target_domain_id'));
            $expectedState = $text('expected_enabled');
            if (!in_array($expectedState, ['0', '1'], true) || $current['target_domain_id'] !== $expectedId
                || $current['active'] !== ($expectedState === '1')) { throw new \DomainException('stale_form'); }
            if ($operation === 'set_state' && $targetId !== $expectedId) { throw new \DomainException('unexpected_repoint'); }
            if ($operation === 'repoint' && ($current['active'] || $state !== '0')) {
                throw new \DomainException('disable_before_repoint');
            }
        }
        if ($state === '1' && !$domains[$targetId]['active']) { throw new \DomainException('inactive_destination'); }
        return ['operation' => $operation, 'alias_domain' => $alias,
            'target_domain_id' => $targetId, 'active' => $state === '1'];
    }

    private static function rowShape(mixed $row, array $keys): void
    {
        if (!is_array($row)) { throw new \DomainException('snapshot_shape'); }
        foreach ($keys as $key) {
            if (!is_string($row[$key] ?? null)) { throw new \DomainException('snapshot_shape'); }
        }
    }

    private static function state(string $value): bool
    {
        if (!in_array($value, ['0', '1'], true)) { throw new \DomainException('snapshot_shape'); }
        return $value === '1';
    }
}
