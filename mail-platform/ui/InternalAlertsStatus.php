<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Finite, aggregate-only status. Never reads a webhook or starts a process. */
final class InternalAlertsStatus
{
    private const LABELS = ['email'=>'メール','discord'=>'Discord'];

    public static function read(int $now): string
    {
        $config='/etc/mail-management-alerts-v1/public-reader.json';
        if (!file_exists($config)) {
            return '<fieldset><legend>内部障害通知</legend><p>内部障害通知はまだ配置されていません。</p></fieldset>';
        }
        try {
            $raw=self::file($config,0,113,0640,2048);
            $v=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
            self::keys($v,['version','worker_uid','public_gid']);
            self::need($v['version']===1 && is_int($v['worker_uid']) && $v['worker_uid']>0 && $v['public_gid']===113);
            $updated = null;
            $runtime=json_decode(self::file('/etc/mail-management-alerts-v1/runtime.json',0,$v['public_gid'],0640,16384,$updated),true,8,JSON_THROW_ON_ERROR);
            self::keys($runtime,['version','enabled','channels','smtp','public_group']);
            self::need($runtime['version']===1 && is_bool($runtime['enabled']) && $runtime['public_group']===$v['public_gid']);
            self::validChannels($runtime['channels']);
            self::need($runtime['enabled'] || !in_array(true,$runtime['channels'],true));
        } catch (\Throwable) {
            return self::panel('<p role="alert">現在の通知設定を確認できません。</p>');
        }
        if (!in_array(true,$runtime['channels'],true)) {
            return self::fromJson(null,$now,$runtime['channels']);
        }
        try {
            $data=self::file('/var/lib/mail-management-alerts-public-v1/status.json',$v['worker_uid'],113,0640,16384);
            return self::fromJson($data,$now,$runtime['channels'],$updated);
        } catch (\Throwable) {
            return self::fromJson(null,$now,$runtime['channels']);
        }
    }

    /** Render using the current operator setting, never the history's enabled flags alone. */
    public static function fromJson(?string $raw,int $now,array $configured,?int $updated = null): string
    {
        self::validChannels($configured);
        $enabled = array_intersect_key(self::LABELS,array_filter($configured));
        if ($enabled===[]) {
            return self::panel('<p role="status">通知停止中（メール・Discordとも無効）</p>');
        }
        $channels = implode('・',$enabled);
        if ($raw===null) {
            return self::panel('<p role="alert">通知設定は有効（'.$channels.'）。現在の通知処理を確認できません。</p>');
        }
        self::need(strlen($raw)<=16384);
        $v=json_decode($raw,true,24,JSON_THROW_ON_ERROR);
        self::need(json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)===rtrim($raw,"\r\n"));
        self::keys($v,['version','observed_at','issues','channels','archived_events','mailbox_delivery_verified','external_liveness_monitoring','worker']);
        self::need($v['version']===1 && is_int($v['observed_at']) && $v['observed_at']>=0 &&
            $v['mailbox_delivery_verified']===false && $v['external_liveness_monitoring']===false);
        if ($updated!==null && $v['observed_at']<$updated && $updated<=$now && $now-$updated<=180) {
            return self::panel('<p role="status">通知を再開しました（'.$channels.'）。次の定期処理を待っています。</p>');
        }
        if ($v['observed_at']>$now || $now-$v['observed_at']>180) {
            return self::panel('<p role="alert">通知設定は有効（'.$channels.'）。新しい通知処理記録を確認できません。</p>');
        }
        self::keys($v['issues'],['warning','critical']);
        foreach($v['issues'] as $count) { self::integer($count,512); }
        self::integer($v['archived_events'],4096);
        self::keys($v['channels'],['email','discord']);
        self::keys($v['worker'],['status','faults']);
        self::need(in_array($v['worker']['status'],['ok','warning'],true) && is_array($v['worker']['faults']) && array_is_list($v['worker']['faults']) && count($v['worker']['faults'])<=2);
        self::need(($v['worker']['status']==='ok')===($v['worker']['faults']===[]));
        foreach($v['worker']['faults'] as $fault) {
            self::keys($fault,['channel','stage','error_class','errno']);
            self::need(in_array($fault['channel'],['email','discord'],true) && $fault['stage']==='adapter_or_result_validation' &&
                in_array($fault['error_class'],['OSError','TimeoutError','ValueError','TypeError','KeyError','ConnectionError','PermissionError','FileNotFoundError','JSONDecodeError','other'],true) &&
                ($fault['errno']===null || is_int($fault['errno']) && $fault['errno']>=0 && $fault['errno']<=65535));
        }
        $totals=[];
        $configurationMatches = true;
        $attention = [];
        foreach(self::LABELS as $name=>$label) {
            $c=$v['channels'][$name];
            self::keys($c,['enabled','counts','last_cycle']);
            self::need(is_bool($c['enabled']) && in_array($c['last_cycle'],['disabled','accepted','retry','blocked','unknown','no_submission'],true));
            self::need(($c['last_cycle']==='disabled')===(!$c['enabled']));
            self::keys($c['counts'],['pending','inflight','accepted','unknown','blocked']);
            foreach($c['counts'] as $n) { self::integer($n,128); }
            self::need(array_sum($c['counts'])<=128);
            $totals[]=array_sum($c['counts']);
            $configurationMatches = $configurationMatches && $c['enabled']===$configured[$name];
            if ($configured[$name] && ($c['counts']['unknown']>0 || $c['counts']['blocked']>0 || $c['counts']['inflight']>0
                    || in_array($c['last_cycle'],['retry','blocked','unknown'],true))) {
                $attention[] = $label;
            }
        }
        self::need($totals[0]===$totals[1]);
        if (!$configurationMatches) {
            return self::panel('<p role="alert">通知設定は有効（'.$channels.'）。設定変更後の通知処理を確認中です。</p>');
        }
        $pending = $v['worker']['status']!=='ok' || $attention!==[];
        $message = $pending
            ? '<p role="alert">通知処理に要確認の項目があります（'.($attention===[]?$channels:implode('・',$attention)).'）。</p>'
            : '<p role="status">通知処理の記録は正常です（'.$channels.'）。</p>';
        if ($v['issues']['critical']>0 || $v['issues']['warning']>0) {
            $message.='<p>通知対象の指摘：重大 '.$v['issues']['critical'].' 件 ／ 警告 '.$v['issues']['warning'].' 件</p>';
        }
        return self::panel($message);
    }

    private static function panel(string $content): string
    {
        return '<fieldset><legend>内部障害通知</legend>'.$content.'</fieldset>';
    }

    private static function validChannels(mixed $channels): void
    {
        self::keys($channels,array_keys(self::LABELS));
        foreach ($channels as $enabled) { self::need(is_bool($enabled)); }
    }

    private static function file(string $path,int $uid,int $gid,int $mode,int $limit,?int &$updated = null): string
    {
        $parents=[];$p=dirname($path);
        while($p!=='/' && $p!=='.') { $parents[]=$p;$p=dirname($p); }
        foreach(array_reverse($parents) as $parent) {
            $s=@lstat($parent);self::need(is_array($s) && ($s['mode']&0170000)===0040000 && ($s['mode']&0022)===0);
            self::need($s['uid']===0 || $parent==='/var/lib/mail-management-alerts-public-v1' && $s['uid']===$uid && $s['gid']===$gid && ($s['mode']&0777)===0750);
        }
        $before=@lstat($path);
        self::need(is_array($before) && ($before['mode']&0170000)===0100000 && $before['uid']===$uid &&
            $before['gid']===$gid && ($before['mode']&0777)===$mode && $before['nlink']===1 && $before['size']>0 && $before['size']<=$limit);
        $fd=@fopen($path,'rb');self::need(is_resource($fd));
        try {
            $held=fstat($fd);$raw=stream_get_contents($fd,$limit+1);clearstatcache(true,$path);$after=@lstat($path);
            self::need(is_string($raw) && strlen($raw)===$before['size']);
            foreach(['dev','ino','uid','gid','mode','nlink','size','mtime','ctime'] as $key) {
                self::need(is_array($held) && is_array($after) && $before[$key]===$held[$key] && $held[$key]===$after[$key]);
            }
            $updated = $held['mtime'];
            return $raw;
        } finally { fclose($fd); }
    }
    private static function keys(mixed $v,array $expected): void
    {
        self::need(is_array($v));$got=array_keys($v);sort($got);sort($expected);self::need($got===$expected);
    }
    private static function need(bool $ok): void { if(!$ok) { throw new \DomainException('invalid_alert_status'); } }
    private static function integer(mixed $n,int $max): void { self::need(is_int($n) && $n>=0 && $n<=$max); }
}
