<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Finite, aggregate-only status. Never reads a webhook or starts a process. */
final class InternalAlertsStatus
{
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
            $data=self::file('/var/lib/mail-management-alerts-public-v1/status.json',$v['worker_uid'],113,0640,16384);
            return self::fromJson($data,$now);
        } catch (\Throwable) {
            return '<fieldset><legend>内部障害通知</legend><p role="alert">通知状態を安全に読み取れません。通知が機能しているとは判定していません。</p></fieldset>';
        }
    }

    public static function fromJson(string $raw,int $now): string
    {
        self::need(strlen($raw)<=16384);
        $v=json_decode($raw,true,24,JSON_THROW_ON_ERROR);
        self::need(json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)===rtrim($raw,"\r\n"));
        self::keys($v,['version','observed_at','issues','channels','archived_events','mailbox_delivery_verified','external_liveness_monitoring','worker']);
        self::need($v['version']===1 && is_int($v['observed_at']) && $v['observed_at']>=0 && $v['observed_at']<=$now &&
            $v['mailbox_delivery_verified']===false && $v['external_liveness_monitoring']===false);
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
        $age=$now-$v['observed_at'];
        $body='<fieldset><legend>内部障害通知</legend><p>通知記録の経過 '.$age.' 秒</p>';
        if($age>180) { $body.='<p role="alert">通知記録が更新されていません。現在の通知動作は未確認です。</p>'; }
        if($v['worker']['status']!=='ok') { $body.='<p role="alert">通知処理の失敗があります。</p>'; }
        $body.='<p>継続中の指摘：重大 '.$v['issues']['critical'].' 件 ／ 警告 '.$v['issues']['warning'].' 件</p><p>履歴保管済み '.$v['archived_events'].' 件。以下は保持中の直近通知です。</p>';
        $totals=[];
        foreach(['email'=>'メール','discord'=>'Discord'] as $name=>$label) {
            $c=$v['channels'][$name];
            self::keys($c,['enabled','counts','last_cycle']);
            self::need(is_bool($c['enabled']) && in_array($c['last_cycle'],['disabled','accepted','retry','blocked','unknown','no_submission'],true));
            self::need(($c['last_cycle']==='disabled')===(!$c['enabled']));
            self::keys($c['counts'],['pending','inflight','accepted','unknown','blocked']);
            foreach($c['counts'] as $n) { self::integer($n,128); }
            self::need(array_sum($c['counts'])<=128);
            $totals[]=array_sum($c['counts']);
            $body.='<h3>'.$label.'：'.($c['enabled']?'有効':'無効').'</h3><p>';
            $names=['pending'=>'送信待ち','inflight'=>'処理中','accepted'=>$name==='email'?'メールサーバー受付済み':'投稿保存確認済み','unknown'=>'結果不明','blocked'=>'確認待ちで停止'];
            foreach($names as $k=>$title) { $body.=$title.' '.$c['counts'][$k].' 件 ／ '; }
            $body.='</p>';
            if($c['counts']['unknown']>0 || $c['counts']['blocked']>0 || $c['counts']['inflight']>0) {
                $body.='<p role="alert">'.$label.'通知には確認が必要な記録があります。結果不明の通知を自動再送しません。</p>';
            }
        }
        self::need($totals[0]===$totals[1]);
        return $body.'<p>この表示では送信処理を起動しません。メール到着・Discord閲覧の確認は別です。</p></fieldset>';
    }

    private static function file(string $path,int $uid,int $gid,int $mode,int $limit): string
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
