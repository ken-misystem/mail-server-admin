<?php
declare(strict_types=1);
require __DIR__.'/PopSourcePolicy.php';require __DIR__.'/PopSealedBox.php';
require __DIR__.'/FetchmailConfig.php';require __DIR__.'/PopRunHistory.php';
use MailServer\Pop\{PopSourcePolicy,PopSealedBox,FetchmailConfig,PopRunHistory};
function workerDb():PDO {
    $p='/etc/mail-pop/worker.json';$m=lstat($p);
    if(!$m || is_link($p) || !is_file($p) || $m['uid']!==0 || ($m['mode']&0777)!==0640
        || $m['nlink']!==1 || $m['size']<1 || $m['size']>4096)throw new RuntimeException();
    $c=json_decode(file_get_contents($p),true,8,JSON_THROW_ON_ERROR);
    if(!is_array($c) || count($c)!==3 || ($c['user']??null)!=='mail_pop_worker'
        || !is_string($c['password']??null) || !preg_match('/\A[0-9a-f]{64}\z/D',$c['password'])
        || !preg_match('~\Amysql:unix_socket=/[A-Za-z0-9/._-]+;dbname=mail_management;charset=utf8mb4\z~D',$c['dsn']??''))throw new RuntimeException();
    $db=new PDO($c['dsn'],$c['user'],$c['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    unset($c);
    if($db->query('SELECT CURRENT_USER()')->fetchColumn()!=='mail_pop_worker@localhost')throw new RuntimeException();
    return $db;
}

function workerSource(PDO $db,string $id):array
{
    $db->exec('START TRANSACTION READ ONLY');
    try {
        $q=$db->prepare("SELECT a.id,a.user_id,a.remote_host,a.remote_port,a.remote_username,a.enabled,u.email,
            COALESCE(s.pop_account_limit,0) AS cap,COALESCE(s.pop_poll_seconds,300) AS seconds,
            (SELECT COUNT(*) FROM mail_pop_accounts b WHERE b.user_id=a.user_id AND b.enabled=1) AS active_count
            FROM mail_pop_accounts a JOIN mailserver.virtual_users u ON u.id=a.user_id
            JOIN mailserver.virtual_domains d ON d.id=u.domain_id LEFT JOIN mail_user_settings s ON s.user_id=u.id
            WHERE a.id=? AND u.active=1 AND d.active=1 AND COALESCE(a.last_result,'')<>'source_changed'");
        $q->execute([$id]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);$db->rollBack();
        if(count($rows)!==1 || (string)$rows[0]['id']!==$id)throw new RuntimeException('source_identity');
        $r=$rows[0];$r['id']=PopSourcePolicy::accountId((string)$r['id']);$r['user_id']=PopSourcePolicy::accountId((string)$r['user_id']);
        PopSourcePolicy::host($r['remote_host']);PopSourcePolicy::port((int)$r['remote_port']);
        PopSourcePolicy::username($r['remote_username']);PopSourcePolicy::recipient($r['email']);
        foreach(['remote_port','enabled','cap','seconds','active_count'] as $key)$r[$key]=(int)$r[$key];return $r;
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
}
function workerAllowed(array $r):void
{
    if($r['enabled']!==1 || $r['cap']<1 || $r['cap']>100 || $r['active_count']<1 || $r['active_count']>$r['cap']
        || $r['seconds']<60 || $r['seconds']>86400)throw new RuntimeException('source_not_allowed');
}
function main():int
{
    $phase='arguments';$db=null;
    try {
        if(PHP_SAPI!=='cli' || ($GLOBALS['argc']??0)!==3)throw new RuntimeException('arguments');
        $mode=$GLOBALS['argv'][1];$id=PopSourcePolicy::accountId($GLOBALS['argv'][2]);
        if(!in_array($mode,['--sources','--metadata','--config','--result','--history-start','--history-finish'],true))throw new RuntimeException('arguments');
        $phase='database';$db=workerDb();
        if($mode==='--sources'){
            $q=$db->query("SELECT a.id,COALESCE(s.pop_poll_seconds,300) AS seconds FROM mail_pop_accounts a
                JOIN mailserver.virtual_users u ON u.id=a.user_id JOIN mailserver.virtual_domains d ON d.id=u.domain_id
                LEFT JOIN mail_user_settings s ON s.user_id=u.id WHERE a.enabled=1 AND u.active=1 AND d.active=1
                AND COALESCE(a.last_result,'')<>'source_changed' AND COALESCE(s.pop_account_limit,0) BETWEEN 1 AND 100
                AND COALESCE(s.pop_poll_seconds,300) BETWEEN 60 AND 86400
                AND (SELECT COUNT(*) FROM mail_pop_accounts b WHERE b.user_id=a.user_id AND b.enabled=1)<=s.pop_account_limit
                ORDER BY a.id LIMIT 1001");$rows=$q->fetchAll(PDO::FETCH_ASSOC);
            if(count($rows)>1000)throw new RuntimeException('source_inventory_bound');
            foreach($rows as &$row){$row['id']=PopSourcePolicy::accountId((string)$row['id']);$row['seconds']=(int)$row['seconds'];}unset($row);
            echo json_encode(['status'=>'ok','sources'=>$rows],JSON_THROW_ON_ERROR);return 0;
        }
        if($mode==='--history-start'){echo json_encode(['status'=>'ok','run_id'=>PopRunHistory::start($db,$id)],JSON_THROW_ON_ERROR);return 0;}
        if($mode==='--metadata'){echo json_encode(['status'=>'ok','source'=>workerSource($db,$id)],JSON_THROW_ON_ERROR);return 0;}
        $raw=stream_get_contents(STDIN,16385);if(strlen($raw)>16384)throw new RuntimeException('input_bound');
        $request=json_decode($raw,true,16,JSON_THROW_ON_ERROR);if(!is_array($request))throw new RuntimeException('request_shape');
        if($mode==='--history-finish'){PopRunHistory::finish($db,$request,$id);echo '{"status":"ok"}';return 0;}
        $r=workerSource($db,$id);$phase='owner_binding';
        if(!is_array($request['source']??null))throw new RuntimeException('request_shape');
        if($mode==='--config'){
            workerAllowed($r);
            if(array_keys($request)!==['source','queryname'] || $r!==$request['source'])throw new RuntimeException('source_changed');
            $ip=PopSourcePolicy::publicIp($request['queryname']);$phase='private_config';
            $path='/etc/mail-pop/keypair.bin';$m=lstat($path);
            if(!$m || is_link($path) || !is_file($path) || $m['uid']!==0 || ($m['mode']&0777)!==0640 || $m['nlink']!==1
                || $m['size']!==SODIUM_CRYPTO_BOX_KEYPAIRBYTES)throw new RuntimeException('key_boundary');
            $q=$db->prepare('SELECT b.sealed_password FROM mail_pop_password_boxes b JOIN mail_pop_accounts a '
                .'ON a.id=b.account_id AND a.secret_reference=b.reference WHERE a.id=? AND a.user_id=? AND a.enabled=1');
            $q->execute([$id,$r['user_id']]);$boxes=$q->fetchAll(PDO::FETCH_COLUMN);
            if(count($boxes)!==1 || !is_string($boxes[0]))throw new RuntimeException('password_box');
            $key=file_get_contents($path);try{$plain=PopSealedBox::open($boxes[0],$key);}finally{sodium_memzero($key);}
            try{$config=FetchmailConfig::render($r['remote_host'],$r['remote_port'],$ip,$r['remote_username'],$plain,$r['email'],'127.0.0.1/10027');}
            finally{sodium_memzero($plain);}
            $command=FetchmailConfig::command($id);$command[6]='-f';$command[7]='-';
            $command[]='--pidfile';$command[]='/var/lib/mail-pop/accounts/'.$id.'/fetchmail.pid';
            echo json_encode(['status'=>'ok','config'=>$config,'argv'=>$command],JSON_THROW_ON_ERROR);return 0;
        }
        if(array_keys($request)!==['source','exit'] || !is_int($request['exit']) || $request['exit']<0 || $request['exit']>255)throw new RuntimeException('result_shape');
        foreach(['id','user_id','remote_host','remote_port','remote_username','email'] as $key){if($r[$key]!==($request['source'][$key]??null))throw new RuntimeException('result_owner');}
        $code=$request['exit'];$result=match($code){0=>'retrieved',1=>'no_mail',13=>'limit_reached',default=>'unverified'};
        $q=$db->prepare('UPDATE mail_pop_accounts SET last_result=?,last_success_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_success_at END WHERE id=? AND user_id=?');
        $q->execute([$result,in_array($code,[0,1,13],true)?1:0,$id,$r['user_id']]);
        if(!in_array($q->rowCount(),[0,1],true))throw new RuntimeException('result_rows');
        $q=$db->prepare('SELECT last_result FROM mail_pop_accounts WHERE id=? AND user_id=?');$q->execute([$id,$r['user_id']]);
        if($q->fetchAll(PDO::FETCH_COLUMN)!==[$result])throw new RuntimeException('result_readback');
        echo json_encode(['status'=>'ok','result'=>$result],JSON_THROW_ON_ERROR);return 0;
    }catch(Throwable $error){
        if($db instanceof PDO && $db->inTransaction())$db->rollBack();
        $i=$error instanceof PDOException?$error->errorInfo:null;
        echo json_encode(['status'=>'fail','raw_error_output'=>false,'diagnostic'=>[
            'error_class'=>in_array(get_class($error),['PDOException','RuntimeException','JsonException','TypeError','Error'],true)?get_class($error):'other',
            'source_line'=>$error->getLine(),'sqlstate'=>is_array($i)&&is_string($i[0]??null)&&preg_match('/\A[A-Z0-9]{5}\z/D',$i[0])?$i[0]:null,
            'native_code'=>is_array($i)&&is_int($i[1]??null)&&$i[1]>=0&&$i[1]<=65535?$i[1]:null,
            'missing_driver'=>$error instanceof PDOException&&str_contains($error->getMessage(),'could not find driver')]],JSON_THROW_ON_ERROR);return 1;
    }
}
if(!defined('GENERAL_POP_FIXTURE'))exit(main());
