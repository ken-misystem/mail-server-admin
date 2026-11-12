<?php
declare(strict_types=1);
require __DIR__.'/PilotPreferenceDecoder.php';require __DIR__.'/Recipients.php';
function main():int
{
    $phase='arguments';
    try {
        if(PHP_SAPI!=='cli' || ($GLOBALS['argc']??0)!==2 || !in_array($GLOBALS['argv'][1],['--list','--eligible'],true))throw new RuntimeException('arguments');
        $phase='private_config';$path='/etc/mail-junk-digest-general.json';$m=lstat($path);
        if(!$m || is_link($path) || !is_file($path) || $m['uid']!==0 || ($m['mode']&0777)!==0600 || $m['nlink']!==1 || $m['size']>8192)throw new RuntimeException('config_boundary');
        $c=json_decode(file_get_contents($path),true,8,JSON_THROW_ON_ERROR);$db=[];
        foreach(['roundcube'=>'roundcube','mail'=>'mailserver'] as $key=>$schema){
            $v=$c[$key]??null;
            if(!is_array($v) || array_keys($v)!==['dsn','user','password'] || $v['user']!=='mail_junk_daily'
                || !preg_match('~\Amysql:unix_socket=/[A-Za-z0-9/._-]+;dbname='.$schema.';charset=utf8mb4\z~D',$v['dsn'])
                || !preg_match('/\A[0-9a-f]{64}\z/D',$v['password']))throw new RuntimeException('config_shape');
            $phase='database';$db[$key]=new PDO($v['dsn'],$v['user'],$v['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
            if($db[$key]->query('SELECT CURRENT_USER()')->fetchColumn()!=='mail_junk_daily@localhost')throw new RuntimeException('database_identity');
        }
        unset($c,$v);$phase='eligibility';$reader=new \MailServer\GeneralAccounts\Recipients($db['roundcube'],$db['mail']);
        if($GLOBALS['argv'][1]==='--list')$value=['recipients'=>$reader->candidates()];
        else {
            $raw=stream_get_contents(STDIN,2049);if(strlen($raw)>2048)throw new RuntimeException('input_bound');
            $expected=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
            $value=['eligible'=>is_array($expected) && $reader->stillEligible($expected)];
        }
        // Private pipe only. The caller never writes or prints the recipient list.
        echo json_encode(['status'=>'ok']+$value,JSON_THROW_ON_ERROR);return 0;
    }catch(Throwable $e){
        echo json_encode(['status'=>'fail','phase'=>$phase,'error_class'=>get_class($e)==='PDOException'?'PDOException':'runtime',
            'source_line'=>$e->getLine(),'raw_error_output'=>false]);return 1;
    }
}
if(!defined('GENERAL_JUNK_FIXTURE'))exit(main());
