<?php
declare(strict_types=1);
// Newly reviewed deployment-only operations; never loaded by the public application.
ini_set('display_errors','0');ini_set('log_errors','0');ini_set('zend.exception_ignore_args','1');
$phase='input';$committing=false;$p=null;
function deployment_need(bool $ok,string $reason):void { if(!$ok)throw new DomainException($reason); }
try {
    $input=stream_get_contents(STDIN,8193);
    deployment_need(is_string($input)&&strlen($input)<=8192,'input_bound');
    $input=json_decode($input,true,8,JSON_THROW_ON_ERROR);
    deployment_need(is_array($input)&&in_array($input['action']??null,['seed','root_check','caller'],true),'action');
    if($input['action']!=='caller') {
        deployment_need(is_string($input['socket']??null)&&preg_match('~^/[A-Za-z0-9/_.-]+$~D',$input['socket'])===1,'socket_shape');
        $phase='root_connect';
        $p=new PDO('mysql:unix_socket='.$input['socket'].';dbname=mail_management;charset=utf8mb4','root','',
            [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
        deployment_need($p->query('SELECT CURRENT_USER()')->fetchColumn()==='root@localhost','root_principal');
        if($input['action']==='root_check'){echo json_encode(['status'=>'ok','root_identity_verified'=>true],JSON_THROW_ON_ERROR);return;}
        $phase='seed_locks';$p->beginTransaction();
        foreach(['alias_namespace','admin_roles']as$name){$q=$p->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');$q->execute([$name]);deployment_need($q->fetchColumn()===$name,'lock_row_missing');}
        $q=$p->prepare('SELECT id,active FROM mailserver.virtual_domains WHERE name=? FOR UPDATE');$q->execute(['yukido.co.jp']);$rows=$q->fetchAll(PDO::FETCH_ASSOC);
        deployment_need(count($rows)===1&&(string)$rows[0]['active']==='1','unique_active_seed_domain');
        deployment_need((int)$p->query('SELECT COUNT(*) FROM mail_domain_delivery_policy')->fetchColumn()===0,'new_policy_table_not_empty');
        $phase='seed_policy';$q=$p->prepare('INSERT INTO mail_domain_delivery_policy(domain_id,follow_mx,revision) VALUES(?,1,1)');$q->execute([$rows[0]['id']]);deployment_need($q->rowCount()===1,'seed_policy_affected_rows');
        $phase='seed_audit';$q=$p->prepare("INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(NULL,'domain_mx_follow_bootstrap','domain',?)");$q->execute([(string)$rows[0]['id']]);deployment_need($q->rowCount()===1,'seed_audit_affected_rows');
        $phase='seed_commit';$committing=true;deployment_need($p->commit(),'seed_commit_unverified');$committing=false;
        echo json_encode(['status'=>'ok','seed_rows'=>1,'audit_rows'=>1,'committed'=>true],JSON_THROW_ON_ERROR);
    } else {
        $phase='caller_config_data';$path='/etc/mail-management/admin.php';$before=lstat($path);
        deployment_need(is_array($before)&&($before['mode']&0170000)===0100000&&$before['uid']===0&&$before['gid']===113&&($before['mode']&0777)===0640&&$before['nlink']===1&&$before['size']<=4096,'caller_config_metadata');
        $fd=fopen($path,'rb');deployment_need(is_resource($fd),'caller_config_open');$on=fstat($fd);$raw=stream_get_contents($fd,4097);$end=fstat($fd);fclose($fd);$after=lstat($path);
        foreach(['dev','ino','uid','gid','mode','nlink','size','mtime','ctime']as$key)deployment_need($before[$key]===$on[$key]&&$before[$key]===$end[$key]&&$before[$key]===$after[$key],'caller_config_drift');
        $prefix="<?php\n// Private generated runtime configuration, not a public entry point.\nreturn json_decode('";$suffix="', true, 512, JSON_THROW_ON_ERROR);\n";
        deployment_need(is_string($raw)&&str_starts_with($raw,$prefix)&&str_ends_with($raw,$suffix),'caller_config_format');
        $c=json_decode(substr($raw,strlen($prefix),-strlen($suffix)),true,8,JSON_THROW_ON_ERROR);unset($raw);
        deployment_need(is_array($c)&&($c['db_user']??null)==='mail_management_app'&&is_string($c['db_password']??null)&&is_string($c['dsn']??null)&&preg_match('~^mysql:unix_socket=/[A-Za-z0-9/_.-]+;dbname=mail_management;charset=utf8mb4$~D',$c['dsn'])===1,'caller_profile');
        $phase='caller_connect';$p=new PDO($c['dsn'],$c['db_user'],$c['db_password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);unset($c);
        deployment_need($p->query('SELECT CURRENT_USER()')->fetchColumn()==='mail_management_app@localhost','caller_principal');
        $phase='caller_zero_rows';$p->exec('START TRANSACTION READ ONLY');
        $q=$p->query('SELECT domain_id,follow_mx,revision FROM mail_domain_delivery_policy WHERE 1=0');deployment_need($q->fetchAll(PDO::FETCH_ASSOC)===[],'caller_zero_row_select');
        $p->rollBack();echo json_encode(['status'=>'ok','effective_select'=>true,'application_rows_read'=>false],JSON_THROW_ON_ERROR);
    }
} catch(Throwable $e) {
    $f=['status'=>'fail','phase'=>$phase,'class'=>get_class($e),'reason'=>$e instanceof DomainException?$e->getMessage():'deployment_database_failure','commit_uncertain'=>$committing,'line'=>$e->getLine(),'sqlstate'=>null,'native_code'=>null];
    if($e instanceof PDOException){$f['sqlstate']=preg_match('/^[A-Z0-9]{5}$/D',(string)$e->getCode())?$e->getCode():null;$f['native_code']=is_int($e->errorInfo[1]??null)?$e->errorInfo[1]:null;}
    try{if($p instanceof PDO&&$p->inTransaction())$p->rollBack();}catch(Throwable $close){$f['rollback_class']=get_class($close);}
    fwrite(STDERR,(string)$e);echo json_encode($f,JSON_THROW_ON_ERROR);exit(1);
}
