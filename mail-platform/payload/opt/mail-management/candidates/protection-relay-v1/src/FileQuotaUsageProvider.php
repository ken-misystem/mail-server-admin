<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Linux deployment only. Root-owned, non-writable parents and file; bounded read once per request. */
final class FileQuotaUsageProvider implements QuotaUsageProvider
{
    private ?array $snapshot = null;
    public function __construct(private readonly string $file, private readonly string $deploymentHash)
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $deploymentHash) || !str_starts_with($file, '/')
            || str_contains($file, '//') || in_array('..', explode('/', $file), true)
            || in_array('.', explode('/', $file), true) || str_contains($file, "\0")) {
            throw new \DomainException('quota_snapshot_invalid');
        }
    }

    public function lookup(string $id, string $email, int $configuredBytes, int $now): array
    {
        if ($this->snapshot === null) { $this->snapshot = $this->read(); }
        return self::validate($this->snapshot, $this->deploymentHash, $id, $email, $configuredBytes, $now);
    }

    public static function validate(array $doc, string $deploymentHash, string $id, string $email, int $configuredBytes, int $now): array
    {
        if (($doc['version'] ?? null) !== 1 || ($doc['deployment_hash'] ?? null) !== $deploymentHash
            || ($doc['enforcement_verified'] ?? null) !== true || !is_array($doc['records'] ?? null)
            || count($doc['records']) > 10000) { throw new \DomainException('quota_backend_unverified'); }
        $r = $doc['records'][$id] ?? null;
        if (!is_array($r) || ($r['id'] ?? null) !== $id || ($r['email'] ?? null) !== $email
            || ($r['configured_bytes'] ?? null) !== $configuredBytes || ($r['effective_bytes'] ?? null) !== $configuredBytes) {
            throw new \DomainException('quota_binding_changed');
        }
        if (!is_int($r['observed_at'] ?? null) || $r['observed_at'] > $now || $r['observed_at'] <= $now - 120) {
            throw new \DomainException('quota_usage_stale');
        }
        if (!is_int($r['used_bytes_upper_bound'] ?? null) || $r['used_bytes_upper_bound'] < 0) {
            throw new \DomainException('quota_snapshot_invalid');
        }
        return ['used_bytes_upper_bound'=>$r['used_bytes_upper_bound'], 'observed_at'=>$r['observed_at'], 'enforcement_verified'=>true];
    }

    private function read(): array
    {
        if (PHP_OS_FAMILY !== 'Linux') { throw new \DomainException('quota_backend_unverified'); }
        $path = '';
        foreach (explode('/', trim(dirname($this->file), '/')) as $part) {
            $path .= '/'.$part; clearstatcache(true, $path); $s = @lstat($path);
            if (!$s || ($s['mode'] & 0170000) !== 0040000 || $s['uid'] !== 0 || ($s['mode'] & 0022) !== 0) {
                throw new \DomainException('quota_snapshot_invalid');
            }
        }
        clearstatcache(true, $this->file); $a = @lstat($this->file);
        if (!$a || ($a['mode'] & 0170000) !== 0100000 || $a['uid'] !== 0 || $a['nlink'] !== 1
            || ($a['mode'] & 0027) !== 0 || $a['size'] > 2097152) { throw new \DomainException('quota_snapshot_invalid'); }
        $f = @fopen($this->file, 'rb'); if (!$f) { throw new \DomainException('quota_snapshot_invalid'); }
        try {
            $b = fstat($f); $raw = stream_get_contents($f, 2097153); $c = fstat($f);
            clearstatcache(true, $this->file); $d = @lstat($this->file);
            foreach (['dev','ino','uid','gid','mode','nlink','size','mtime','ctime'] as $key) {
                if (!$b || !$c || !$d || $a[$key] !== $b[$key] || $b[$key] !== $c[$key] || $c[$key] !== $d[$key]) {
                    throw new \DomainException('quota_snapshot_invalid');
                }
            }
            if (!is_string($raw) || strlen($raw) !== $a['size']) { throw new \DomainException('quota_snapshot_invalid'); }
            try { $doc = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); }
            catch (\JsonException) { throw new \DomainException('quota_snapshot_invalid'); }
            if (!is_array($doc)) { throw new \DomainException('quota_snapshot_invalid'); }
            return $doc;
        } finally { fclose($f); }
    }
}
