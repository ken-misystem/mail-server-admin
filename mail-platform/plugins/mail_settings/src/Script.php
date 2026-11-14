<?php
declare(strict_types=1);
namespace MiSystem\MailSettings;

/** Original MI-SYSTEM implementation. SPDX-License-Identifier: MIT */
final class Script
{
    public const MARKER = '# MI-SYSTEM mail settings v1';
    public const MAX_BYTES = 65536;

    public static function defaults(): array
    {
        return ['format' => 1, 'base' => null, 'rules' => [],
            'forward' => ['enabled' => false, 'targets' => [], 'keep' => true],
            'vacation' => ['enabled' => false, 'days' => 7, 'subject' => '', 'body' => '']];
    }

    private static function keys(array $value, array $expected): void
    {
        $keys = array_keys($value);
        sort($keys);
        sort($expected);
        if ($keys !== $expected) throw new \DomainException('invalid_settings');
    }

    public static function text(mixed $value, int $maximum, bool $multiline = false): string
    {
        if (!is_string($value) || strlen($value) > $maximum || preg_match('//u', $value) !== 1
            || preg_match($multiline ? '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/' : '/[\x00-\x1f\x7f]/', $value)) {
            throw new \DomainException('invalid_settings');
        }
        return $value;
    }

    public static function address(mixed $value): string
    {
        $value = self::text($value, 254);
        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) throw new \DomainException('invalid_address');
        return $value;
    }

    public static function validate(array $value): array
    {
        self::keys($value, ['format', 'base', 'rules', 'forward', 'vacation']);
        if ($value['format'] !== 1 || ($value['base'] !== null
            && (!is_string($value['base']) || !preg_match('/\Ams-base-[a-f0-9]{64}\z/D', $value['base'])))) {
            throw new \DomainException('invalid_settings');
        }
        if (!is_array($value['rules']) || !array_is_list($value['rules']) || count($value['rules']) > 32) {
            throw new \DomainException('invalid_settings');
        }
        foreach ($value['rules'] as $rule) {
            if (!is_array($rule)) throw new \DomainException('invalid_settings');
            self::keys($rule, ['field', 'match', 'value', 'action', 'target', 'stop']);
            if (!in_array($rule['field'], ['subject', 'from', 'to'], true)
                || !in_array($rule['match'], ['contains', 'is'], true)
                || !in_array($rule['action'], ['fileinto', 'keep', 'discard'], true)
                || !is_bool($rule['stop']) || self::text($rule['value'], 512) === '') {
                throw new \DomainException('invalid_settings');
            }
            $target = self::text($rule['target'], 255);
            if (($rule['action'] === 'fileinto' && ($target === '' || str_starts_with($target, '/')))
                || ($rule['action'] !== 'fileinto' && $target !== '')) {
                throw new \DomainException('invalid_settings');
            }
        }
        if (!is_array($value['forward']) || !is_array($value['vacation'])) throw new \DomainException('invalid_settings');
        $forward = $value['forward'];
        self::keys($forward, ['enabled', 'targets', 'keep']);
        if (!is_bool($forward['enabled']) || !is_bool($forward['keep']) || !is_array($forward['targets'])
            || !array_is_list($forward['targets']) || count($forward['targets']) > 10
            || ($forward['enabled'] && !$forward['targets'])) throw new \DomainException('invalid_settings');
        foreach ($forward['targets'] as $target) self::address($target);
        if (count(array_unique($forward['targets'])) !== count($forward['targets'])) throw new \DomainException('invalid_settings');
        $vacation = $value['vacation'];
        self::keys($vacation, ['enabled', 'days', 'subject', 'body']);
        if (!is_bool($vacation['enabled']) || !is_int($vacation['days']) || $vacation['days'] < 1 || $vacation['days'] > 30
            || ($vacation['enabled'] && $vacation['body'] === '')) throw new \DomainException('invalid_settings');
        self::text($vacation['subject'], 200);
        self::text($vacation['body'], 8192, true);
        return $value;
    }

    private static function quote(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    public static function compile(array $value): string
    {
        $value = self::validate($value);
        $encoded = base64_encode(json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $lines = [self::MARKER, '# state=' . $encoded, 'require ["include", "fileinto", "copy", "vacation"];'];
        if ($value['base'] !== null) $lines[] = 'include :once :personal ' . self::quote($value['base']) . ';';
        foreach ($value['rules'] as $rule) {
            $lines[] = 'if header :' . $rule['match'] . ' ' . self::quote($rule['field']) . ' ' . self::quote($rule['value']) . ' {';
            $lines[] = '  ' . $rule['action'] . ($rule['action'] === 'fileinto' ? ' ' . self::quote($rule['target']) : '') . ';';
            if ($rule['stop']) $lines[] = '  stop;';
            $lines[] = '}';
        }
        if ($value['forward']['enabled']) {
            foreach ($value['forward']['targets'] as $target) {
                $lines[] = 'redirect' . ($value['forward']['keep'] ? ' :copy' : '') . ' ' . self::quote($target) . ';';
            }
        }
        if ($value['vacation']['enabled']) {
            $lines[] = 'vacation :days ' . $value['vacation']['days'] . ' :subject ' . self::quote($value['vacation']['subject']) . ' text:';
            $body = str_replace(["\r\n", "\r"], "\n", $value['vacation']['body']);
            foreach (explode("\n", $body) as $line) $lines[] = str_starts_with($line, '.') ? '.' . $line : $line;
            $lines[] = '.';
            $lines[] = ';';
        }
        $script = implode("\r\n", $lines) . "\r\n";
        if (strlen($script) > self::MAX_BYTES) throw new \DomainException('script_too_large');
        return $script;
    }

    public static function decode(string $source): ?array
    {
        if (!str_starts_with($source, self::MARKER)) return null;
        $lines = explode("\r\n", $source, 3);
        if (count($lines) !== 3 || !str_starts_with($lines[1], '# state=')) throw new \DomainException('managed_script_changed');
        try {
            $raw = base64_decode(substr($lines[1], 8), true);
            if ($raw === false || strlen($raw) > self::MAX_BYTES) throw new \DomainException('managed_script_changed');
            $model = json_decode($raw, true, 12, JSON_THROW_ON_ERROR);
            if (!is_array($model) || self::compile($model) !== $source) throw new \DomainException('managed_script_changed');
            return $model;
        } catch (\Throwable) { throw new \DomainException('managed_script_changed'); }
    }
}
