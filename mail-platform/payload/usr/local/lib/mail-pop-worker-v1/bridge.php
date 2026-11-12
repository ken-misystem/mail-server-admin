<?php
declare(strict_types=1);
// CLI child only: metadata first, fresh permission before existing sealed-box open.
require __DIR__.'/PopSourcePolicy.php';
require __DIR__.'/PopSealedBox.php';
require __DIR__.'/FetchmailConfig.php';
require __DIR__.'/PopRunHistory.php';
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
function workerSource(PDO $db):array {
    $db->exec('START TRANSACTION READ ONLY');
    try {
        $q=$db->query("SELECT a.id,a.user_id,a.remote_host,a.remote_port,a.remote_username,a.enabled,u.email,
            COALESCE(s.pop_account_limit,0) AS cap,COALESCE(s.pop_poll_seconds,300) AS seconds,
            (SELECT COUNT(*) FROM mail_pop_accounts b WHERE b.user_id=a.user_id AND b.enabled=1) AS active_count
            FROM mail_pop_accounts a JOIN mailserver.virtual_users u ON u.id=a.user_id
            JOIN mailserver.virtual_domains d ON d.id=u.domain_id
            LEFT JOIN mail_user_settings s ON s.user_id=u.id
            WHERE a.id=1 AND u.email='ken@mi-sys.jp' AND u.active=1 AND d.name='mi-sys.jp' AND d.active=1");
        $r=$q->fetchAll(PDO::FETCH_ASSOC);$db->rollBack();
        if(count($r)!==1)throw new RuntimeException();$r=$r[0];
        if((string)$r['id']!=='1' || $r['remote_host']!=='mail.mi-sys.jp' || (int)$r['remote_port']!==995
            || $r['remote_username']!=='ken@mi-sys.jp' || $r['email']!=='ken@mi-sys.jp')throw new RuntimeException();
        PopSourcePolicy::accountId((string)$r['user_id']);
        $r['id']=(string)$r['id'];$r['user_id']=(string)$r['user_id'];
        foreach(['remote_port','enabled','cap','seconds','active_count'] as $key)$r[$key]=(int)$r[$key];
        return $r;
    } catch(Throwable $e) {if($db->inTransaction())$db->rollBack();throw $e;}
}
function workerAllowed(array $r):void {
    if($r['enabled']!==1 || $r['cap']<1 || $r['cap']>100 || $r['active_count']<1 || $r['active_count']>$r['cap']
        || $r['seconds']<60 || $r['seconds']>86400)throw new RuntimeException();
}
function workerVerifyResult(PDO $db,PDOStatement $q,string $owner,string $result):void {
    if(!in_array($q->rowCount(),[0,1],true))throw new RuntimeException();
    $v=$db->prepare('SELECT last_result FROM mail_pop_accounts WHERE id=1 AND user_id=?');
    $v->execute([$owner]);$seen=$v->fetchAll(PDO::FETCH_COLUMN);
    if(count($seen)!==1 || $seen[0]!==$result)throw new RuntimeException();
}
$mode=$argv[1]??'';$db=null;
try {
    if(PHP_SAPI!=='cli' || $argc!==2 || !in_array($mode,['--fixture','--metadata','--config','--result','--history-start','--history-finish'],true))throw new RuntimeException();
    if($mode==='--fixture') {
        // Native inert parse only; never read live configuration/keys/database.
        echo FetchmailConfig::render('fixture.example.invalid',995,'8.8.8.8','fixture','<synthetic>',
            'fixture@example.invalid','127.0.0.1/10027');exit(0);
    }
    $db=workerDb();
    if($mode==='--history-start'){
        echo json_encode(['status'=>'ok','run_id'=>PopRunHistory::start($db)],JSON_THROW_ON_ERROR);exit(0);
    }
    if($mode==='--history-finish'){
        $raw=stream_get_contents(STDIN,2049);
        if(strlen($raw)>2048)throw new RuntimeException();
        $value=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
        if(!is_array($value))throw new RuntimeException();
        PopRunHistory::finish($db,$value);echo '{"status":"ok"}';exit(0);
    }
    $r=workerSource($db);
    if($mode==='--metadata'){echo json_encode(['status'=>'ok','source'=>$r],JSON_THROW_ON_ERROR);exit(0);}
    $raw=stream_get_contents(STDIN,16385);
    if(strlen($raw)>16384)throw new RuntimeException();$request=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
    if(!is_array($request) || !is_array($request['source']??null))throw new RuntimeException();
    if($mode==='--config') {
        workerAllowed($r);
        if($r!==$request['source'] || array_keys($request)!==['source','queryname'])throw new RuntimeException();
        $ip=PopSourcePolicy::publicIp($request['queryname']);
        $m=lstat('/etc/mail-pop/keypair.bin');
        if(!$m || is_link('/etc/mail-pop/keypair.bin') || !is_file('/etc/mail-pop/keypair.bin') || $m['uid']!==0
            || ($m['mode']&0777)!==0640 || $m['nlink']!==1 || $m['size']!==SODIUM_CRYPTO_BOX_KEYPAIRBYTES)throw new RuntimeException();
        $q=$db->prepare('SELECT b.sealed_password FROM mail_pop_password_boxes b JOIN mail_pop_accounts a '
            .'ON a.id=b.account_id AND a.secret_reference=b.reference WHERE a.id=1 AND a.user_id=? AND a.enabled=1');
        $q->execute([$r['user_id']]);$box=$q->fetchAll(PDO::FETCH_COLUMN);
        if(count($box)!==1 || !is_string($box[0]))throw new RuntimeException();
        $key=file_get_contents('/etc/mail-pop/keypair.bin');
        try{$plain=PopSealedBox::open($box[0],$key);}finally{sodium_memzero($key);}
        try{$config=FetchmailConfig::render($r['remote_host'],$r['remote_port'],$ip,$r['remote_username'],$plain,$r['email'],'127.0.0.1/10027');}
        finally{sodium_memzero($plain);}
        $command=FetchmailConfig::command('1');
        if($command[6]!=='--rcfile' || $command[7]!=='/run/mail-pop/accounts/1/fetchmailrc')throw new RuntimeException();
        // Documented standard-input option: no plaintext rcfile or source password in argv.
        $command[6]='-f';$command[7]='-';
        $command[]='--pidfile';$command[]='/var/lib/mail-pop/accounts/1/fetchmail.pid';
        echo json_encode(['status'=>'ok','config'=>$config,'argv'=>$command],JSON_THROW_ON_ERROR);exit(0);
    }
    if(array_keys($request)!==['source','exit'] || !is_int($request['exit']) || $request['exit']<0 || $request['exit']>255)throw new RuntimeException();
    foreach(['id','user_id','remote_host','remote_port','remote_username','email'] as $key) {
        if($r[$key]!==($request['source'][$key]??null))throw new RuntimeException();
    }
    $code=$request['exit'];$result=match($code){0=>'retrieved',1=>'no_mail',13=>'limit_reached',default=>'unverified'};
    // Only worker-owned result/time columns; never enable/pause/change account identity.
    $q=$db->prepare('UPDATE mail_pop_accounts SET last_result=?,last_success_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_success_at END WHERE id=1 AND user_id=?');
    $q->execute([$result,in_array($code,[0,1,13],true)?1:0,$r['user_id']]);
    workerVerifyResult($db,$q,$r['user_id'],$result);
    echo json_encode(['status'=>'ok','result'=>$result],JSON_THROW_ON_ERROR);
} catch(Throwable $error) {
    if($db instanceof PDO){try{if($db->inTransaction())$db->rollBack();}catch(Throwable){}}
    $class=get_class($error);$class=in_array($class,['PDOException','RuntimeException','JsonException','TypeError','Error'],true)?$class:'other';
    $i=$error instanceof PDOException?$error->errorInfo:null;$s=is_array($i)?($i[0]??null):null;$n=is_array($i)?($i[1]??null):null;
    echo json_encode(['status'=>'fail','raw_error_output'=>false,'diagnostic'=>['error_class'=>$class,'source_line'=>$error->getLine(),
        'sqlstate'=>is_string($s)&&preg_match('/\A[A-Z0-9]{5}\z/D',$s)?$s:null,
        'native_code'=>is_int($n)&&$n>=0&&$n<=65535?$n:null,
        'missing_driver'=>$error instanceof PDOException&&str_contains($error->getMessage(),'could not find driver')]],JSON_THROW_ON_ERROR);exit(1);
}
