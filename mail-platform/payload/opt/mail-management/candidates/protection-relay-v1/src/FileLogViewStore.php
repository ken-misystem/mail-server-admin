<?php
declare(strict_types=1);
namespace MailServer\Management;
/** Only bounded published JSON. No command, socket, SQL or source-log access. */
final class FileLogViewStore implements LogViewStore
{
    public const DIRECTORY='/var/lib/mail-management-log-viewer-v1/published';
    public function __construct(private readonly string $directory=self::DIRECTORY,private readonly bool $enforceOwner=true) {}
    private function read(string $path,int $limit): string
    {
        clearstatcache(true,$path);$s=@lstat($path);
        if(!is_array($s)||($s['mode']&0170000)!==0100000||$s['nlink']!==1||$s['size']<1||$s['size']>$limit
            || is_link($path)||($this->enforceOwner&&($s['uid']!==0||($s['mode']&0777)!==0640))) throw new \DomainException('log_cache_unavailable');
        $fd=@fopen($path,'rb');if(!$fd)throw new \DomainException('log_cache_unavailable');
        try {
            $held=fstat($fd);if($held['ino']!==$s['ino']||$held['dev']!==$s['dev'])throw new \DomainException('log_cache_changed');
            $raw=stream_get_contents($fd,$limit+1);$end=fstat($fd);
            foreach(['ino','dev','mode','uid','gid','nlink','size','mtime','ctime']as$k)if($held[$k]!==$end[$k])throw new \DomainException('log_cache_changed');
            if(!is_string($raw)||strlen($raw)!==$held['size']||strlen($raw)>$limit)throw new \DomainException('log_cache_changed');return $raw;
        } finally {fclose($fd);}
    }
    private function decode(string $raw): array
    {
        try {$v=json_decode($raw,true,32,JSON_THROW_ON_ERROR);}catch(\Throwable){throw new \DomainException('invalid_log_cache');}
        if(!is_array($v))throw new \DomainException('invalid_log_cache');return $v;
    }
    public function search(LogViewQuery $q,int $now): array
    {
        foreach([$this->directory,$this->directory.'/pages']as$dir){
            clearstatcache(true,$dir);$s=@lstat($dir);
            if(!is_array($s)||($s['mode']&0170000)!==0040000||is_link($dir)||($this->enforceOwner&&($s['uid']!==0||($s['mode']&0022)!==0)))throw new \DomainException('unsafe_log_cache');
        }
        if($this->enforceOwner)for($p=$this->directory;;$p=dirname($p)){
            clearstatcache(true,$p);$s=@lstat($p);
            if(!is_array($s)||($s['mode']&0170000)!==0040000||$s['uid']!==0||($s['mode']&0022)!==0||is_link($p))throw new \DomainException('unsafe_log_cache');
            if($p==='/')break;
        }
        $catalog=$this->decode($this->read($this->directory.'/index.json',262144));
        if(($catalog['schema']??null)!==1 || !is_int($catalog['generated']??null)||$catalog['generated']>$now+5
            || !is_array($catalog['pages']??null)||count($catalog['pages'])>801||!is_array($catalog['collector']??null)
            ||!in_array($catalog['collector']['status']??null,['ok','failed'],true))throw new \DomainException('invalid_log_cache');
        $start=hrtime(true);$rows=[];$scanned=0;$bytes=0;$next=null;$limited=false;$lastMax=PHP_INT_MAX;
        foreach($catalog['pages']as$page){
            if(!is_array($page)||!preg_match('/^[a-f0-9]{64}$/D',$page['hash']??'')||!is_int($page['min']??null)||!is_int($page['max']??null)
                ||$page['min']<1||$page['max']<$page['min']||$page['max']>=$lastMax||!is_int($page['start']??null)||!is_int($page['end']??null)
                ||!is_array($page['categories']??null)||!is_array($page['levels']??null))throw new \DomainException('invalid_log_cache');
            $lastMax=$page['min'];
            if($page['min']>=$q->before || $page['end']<($now-$q->hours*3600)*1000000)continue;
            if(($q->category!==''&&!in_array($q->category,$page['categories'],true))||($q->level!==''&&!in_array($q->level,$page['levels'],true)))continue;
            if($scanned>=32||$bytes>=2097152||hrtime(true)-$start>1_000_000_000){$limited=true;break;}
            $raw=$this->read($this->directory.'/pages/'.$page['hash'].'.json',65536);$bytes+=strlen($raw);++$scanned;
            if(hash('sha256',$raw)!==$page['hash'])throw new \DomainException('invalid_log_cache');
            $items=$this->decode($raw);if(count($items)>25)throw new \DomainException('invalid_log_cache');
            foreach(array_reverse($items)as$row){
                if(!is_array($row)||!is_int($row['id']??null)||$row['id']<$page['min']||$row['id']>$page['max']||!is_int($row['ts']??null)
                    ||!isset(LogViewQuery::CATEGORIES[$row['category']??''])||!isset(LogViewQuery::LEVELS[$row['level']??'']))throw new \DomainException('invalid_log_cache');
                foreach(['text','source','outcome','sender','recipient','account','ip','queue']as$k)if(!is_string($row[$k]??null)||strlen($row[$k])>1024)throw new \DomainException('invalid_log_cache');
                if($row['id']>=$q->before)continue;
                if(count($rows)===100){$limited=true;break 2;}
                $next=$row['id'];
                if($row['ts']<($now-$q->hours*3600)*1000000||($q->category!==''&&$row['category']!==$q->category)||($q->level!==''&&$row['level']!==$q->level))continue;
                $hay=implode(' ',array_map(static fn($k)=>$row[$k],['text','source','outcome','sender','recipient','account','ip','queue']));
                if($q->word!==''&&stripos($hay,$q->word)===false)continue;
                $rows[]=$row;
            }
        }
        return ['rows'=>$rows,'generated'=>$catalog['generated'],'stale'=>$now-$catalog['generated']>180,'collector'=>$catalog['collector'],
            'coverage'=>$catalog['coverage']??[],'retained'=>$catalog['retained']??0,'hidden_total'=>$catalog['hidden_total']??0,
            'next_before'=>$limited?$next:null,'scan_limited'=>$limited,'pages_read'=>$scanned,'bytes_read'=>$bytes];
    }
}
