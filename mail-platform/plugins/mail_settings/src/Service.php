<?php
declare(strict_types=1);
namespace MiSystem\MailSettings;
require_once __DIR__ . '/Document.php';

/** SPDX-License-Identifier: MIT */
interface SieveConnection
{
    public function scripts(): array;
    public function read(string $name): string;
    public function put(string $name, string $source): void;
    public function activate(string $name): void;
}

interface ScriptSetConnection extends SieveConnection
{
    public function delete(string $name): void;
    public function rename(string $oldName, string $newName): void;
}

final class Service
{
    public function __construct(private readonly SieveConnection $sieve) {}

    public function snapshot(): array
    {
        $list = $this->sieve->scripts();
        $active = $list['active'];
        $source = $active === null ? '' : $this->sieve->read($active);
        if (strlen($source) > Script::MAX_BYTES) throw new \DomainException('script_too_large');
        $model = Script::decode($source);
        $base = $model === null ? $source : ($model['base'] === null ? '' : $this->sieve->read($model['base']));
        if (strlen($base) > Script::MAX_BYTES) throw new \DomainException('script_too_large');
        if ($model !== null && $model['base'] !== null && $model['base'] !== 'ms-base-' . hash('sha256', $base)) {
            throw new \DomainException('base_script_changed');
        }
        return ['active' => $active, 'source' => $source, 'base_source' => $base, 'script_names' => $list['names'],
            'extensions' => $list['extensions'] ?? null,
            'document' => Document::parse($source), 'base_document' => Document::parse($base),
            'managed' => $model !== null,
            'model' => $model ?? Script::defaults(),
            'revision' => hash('sha256', json_encode([$active, $source, $base], JSON_THROW_ON_ERROR))];
    }

    private function scriptName(string $name, bool $new = false): void
    {
        if ($name === '' || strlen($name) > 512 || preg_match('//u', $name) !== 1 || preg_match('/[\x00-\x1f\x7f]/', $name)
            || ($new && str_starts_with($name, 'ms-'))) throw new \DomainException('invalid_script');
    }

    public function inspectSet(string $name): array
    {
        $this->scriptName($name);
        if (!in_array($name, $this->sieve->scripts()['names'], true)) throw new \DomainException('settings_conflict');
        $source = $this->sieve->read($name);
        return ['name' => $name, 'sha256' => hash('sha256', $source), 'source' => $source, 'document' => Document::parse($source)];
    }

    private function checkedSet(string $revision, string $name, string $expected): array
    {
        if (!hash_equals($revision, $this->snapshot()['revision'])) throw new \DomainException('settings_conflict');
        $set = $this->inspectSet($name);
        if (!hash_equals($set['sha256'], $expected)) throw new \DomainException('settings_conflict');
        return $set;
    }

    public function copySet(string $revision, string $name, array $document): array
    {
        $this->scriptName($name, true);
        if (!hash_equals($revision, $this->snapshot()['revision']) || in_array($name, $this->sieve->scripts()['names'], true)) {
            throw new \DomainException('settings_conflict');
        }
        if (count($this->sieve->scripts()['names']) >= 64) throw new \DomainException('script_limit');
        if (!$this->sieve instanceof ScriptSetConnection) throw new \DomainException('invalid_script');
        $source = Document::render($document);
        // RENAMESCRIPT rejects an existing destination atomically (RFC 5804).
        $temporary = 'ms-draft-' . bin2hex(random_bytes(16));
        $this->sieve->put($temporary, $source);
        if ($this->sieve->read($temporary) !== $source) throw new \DomainException('result_unverified');
        $this->sieve->rename($temporary, $name);
        if ($this->sieve->read($name) !== $source) throw new \DomainException('result_unverified');
        return $this->snapshot();
    }

    public function activateSet(string $revision, string $name, string $expected): array
    {
        $set = $this->checkedSet($revision, $name, $expected);
        $current = $this->snapshot();
        if ($current['source'] !== '') $this->immutable('ms-settings-' . hash('sha256', $current['source']), $current['source']);
        // Validate the exact selected bytes with PUTSCRIPT without replacing an active name.
        $this->immutable('ms-settings-' . $set['sha256'], $set['source']);
        $this->checkedSet($revision, $name, $expected);
        $this->sieve->activate($name);
        $after = $this->snapshot();
        if ($after['active'] !== $name || $after['source'] !== $set['source']) throw new \DomainException('result_unverified');
        return $after;
    }

    private function unreferenced(string $name): void
    {
        // Dynamic include names cannot be proven independent. Refuse deletion in that case.
        foreach ($this->sieve->scripts()['names'] as $other) {
            if ($other === $name) continue;
            $source = $this->sieve->read($other);
            if (preg_match('/\binclude\b/i', $source) && (str_contains($source, $name) || str_contains($source, '${'))) {
                throw new \DomainException('script_referenced');
            }
        }
    }

    public function deleteSet(string $revision, string $name, string $expected): array
    {
        $set = $this->checkedSet($revision, $name, $expected);
        $this->scriptName($name, true);
        if (!$this->sieve instanceof ScriptSetConnection || $this->snapshot()['active'] === $name) throw new \DomainException('script_referenced');
        $this->unreferenced($name);
        $this->immutable('ms-settings-' . $set['sha256'], $set['source']);
        $this->checkedSet($revision, $name, $expected);
        $this->sieve->delete($name);
        if (in_array($name, $this->sieve->scripts()['names'], true)) throw new \DomainException('result_unverified');
        return $this->snapshot();
    }

    public function renameSet(string $revision, string $name, string $expected, string $newName): array
    {
        $set = $this->checkedSet($revision, $name, $expected);
        $this->scriptName($name, true);
        if (!$this->sieve instanceof ScriptSetConnection) throw new \DomainException('invalid_script');
        $this->unreferenced($name);
        $current = $this->copySet($revision, $newName, $set['document']);
        if ($current['active'] === $name) $current = $this->activateSet($revision, $newName, $expected);
        return $this->deleteSet($current['revision'], $name, $expected);
    }

    /** Preserve included-script scope, including return/stop semantics. */
    public function saveBaseDocument(string $revision, array $document): array
    {
        $current = $this->snapshot();
        return $this->save($revision, $current['model'], Document::render($document));
    }

    public function saveDocument(string $revision, array $document, bool $restoring = false): array
    {
        $current = $this->snapshot();
        if (!hash_equals($current['revision'], $revision)) throw new \DomainException('settings_conflict');
        $source = Document::render($document);
        if ($source === $current['source']) return $current;
        // An edited v1 document no longer represents its old encoded form model.
        if (!$restoring && !str_starts_with($source, Document::MARKER)) $source = Document::MARKER . "\r\n" . $source;
        Document::parse($source);
        if ($current['source'] !== '') $this->immutable('ms-settings-' . hash('sha256', $current['source']), $current['source']);
        $name = 'ms-settings-' . hash('sha256', $source);
        $this->immutable($name, $source);
        if (!hash_equals($revision, $this->snapshot()['revision'])) throw new \DomainException('settings_conflict');
        $this->sieve->activate($name);
        $after = $this->snapshot();
        if ($after['active'] !== $name || $after['source'] !== $source) throw new \DomainException('result_unverified');
        return $after;
    }

    private function immutable(string $name, string $source): void
    {
        $list = $this->sieve->scripts();
        if (in_array($name, $list['names'], true)) {
            if ($this->sieve->read($name) !== $source) throw new \DomainException('snapshot_collision');
            return;
        }
        if (count($list['names']) >= 64) throw new \DomainException('script_limit');
        $this->sieve->put($name, $source);
        if ($this->sieve->read($name) !== $source) throw new \DomainException('result_unverified');
    }

    /** Caller holds the same account lock from snapshot validation through readback. */
    public function save(string $revision, array $model, ?string $newBase = null): array
    {
        $current = $this->snapshot();
        if (!hash_equals($current['revision'], $revision)) throw new \DomainException('settings_conflict');
        $base = $newBase ?? $current['base_source'];
        if (strlen($base) > Script::MAX_BYTES || preg_match('//u', $base) !== 1 || str_contains($base, "\0")) {
            throw new \DomainException('invalid_script');
        }
        $model['base'] = $base === '' ? null : 'ms-base-' . hash('sha256', $base);
        $source = Script::compile($model);
        $name = 'ms-settings-' . hash('sha256', $source);
        if ($current['active'] === $name && $current['source'] === $source) return $current;
        if ($base !== '') $this->immutable($model['base'], $base);
        // PUTSCRIPT validates syntax while keeping the old active script in service.
        $this->immutable($name, $source);
        if (!hash_equals($revision, $this->snapshot()['revision'])) throw new \DomainException('settings_conflict');
        $this->sieve->activate($name);
        $after = $this->snapshot();
        if ($after['active'] !== $name || $after['source'] !== $source) throw new \DomainException('result_unverified');
        return $after;
    }

    public function versions(): array
    {
        $list = $this->sieve->scripts();
        return array_values(array_filter($list['names'], static fn($name) => preg_match('/\Ams-settings-[a-f0-9]{64}\z/D', $name) === 1));
    }

    public function restore(string $revision, string $name): array
    {
        if (!in_array($name, $this->versions(), true)) throw new \DomainException('invalid_version');
        $source = $this->sieve->read($name);
        $model = Script::decode($source);
        if ($name !== 'ms-settings-' . hash('sha256', $source)) throw new \DomainException('invalid_version');
        if ($model === null) return $this->saveDocument($revision, Document::parse($source), true);
        $base = $model['base'] === null ? '' : $this->sieve->read($model['base']);
        if ($model['base'] !== null && $model['base'] !== 'ms-base-' . hash('sha256', $base)) throw new \DomainException('base_script_changed');
        return $this->save($revision, $model, $base);
    }
}
