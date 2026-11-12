<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Protected root-published aggregate only; never runs shell, SQL, HTTP or a collector. */
final class FileOperationsStatusStore implements OperationsStatusStore
{
    public const PATH = '/var/lib/mail-management-operations-v1/snapshot.json';
    public function __construct(private readonly string $path=self::PATH) {}

    public function read(int $now): OperationsSnapshot
    {
        $parents=[];
        for ($parent=dirname($this->path);; $parent=dirname($parent)) {
            $s=$this->metadata($parent);
            if (($s['mode']&0170000)!==0040000 || $s['uid']!==0 || ($s['mode']&0022)!==0) { throw new \DomainException('unsafe_snapshot'); }
            $parents[$parent]=$s;
            if ($parent==='/') { break; }
            if ($parent==='.' || dirname($parent)===$parent) { throw new \DomainException('unsafe_snapshot'); }
        }
        $before=$this->metadata($this->path); $this->fileGuard($before);
        $handle=@fopen($this->path,'rb');
        if ($handle===false) { throw new \DomainException('unreadable_snapshot'); }
        try {
            $held=fstat($handle);
            if (!is_array($held) || !$this->same($held,$before)) { throw new \DomainException('changed_snapshot'); }
            $raw=stream_get_contents($handle,65537);
            if (!is_string($raw) || strlen($raw)>65536) { throw new \DomainException('invalid_snapshot'); }
            $after=$this->metadata($this->path); $this->fileGuard($after);
            if (!$this->same($before,$after) || !$this->same($held,fstat($handle))) { throw new \DomainException('changed_snapshot'); }
            foreach ($parents as $path=>$s) { if (!$this->same($s,$this->metadata($path))) { throw new \DomainException('changed_snapshot'); } }
            return OperationsSnapshot::fromJson($raw,$now);
        } finally { fclose($handle); }
    }
    private function metadata(string $path): array
    {
        clearstatcache(true,$path); $s=@lstat($path);
        if ($s===false) { throw new \DomainException('missing_snapshot'); } return $s;
    }
    private function fileGuard(array $s): void
    {
        if (($s['mode']&0170000)!==0100000 || $s['uid']!==0 || ($s['mode']&0777)!==0640
            || $s['nlink']!==1 || $s['size']<=0 || $s['size']>65536) { throw new \DomainException('unsafe_snapshot'); }
    }
    private function same(array $a,mixed $b): bool
    {
        if (!is_array($b)) { return false; }
        foreach (['dev','ino','uid','gid','mode','nlink','size','mtime','ctime'] as $key) { if ($a[$key]!==$b[$key]) { return false; } }
        return true;
    }
}
