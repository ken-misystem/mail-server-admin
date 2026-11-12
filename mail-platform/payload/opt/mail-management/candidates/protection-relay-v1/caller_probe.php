<?php
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');ini_set('zend.exception_ignore_args','1');
$phase='configuration';
try {
    $path='/etc/mail-management/admin.php';$a=lstat($path);
    if (!is_array($a)||($a['mode']&0170000)!==0100000||$a['uid']!==0||$a['gid']!==113||($a['mode']&0777)!==0640||$a['nlink']!==1||$a['size']>4096)throw new DomainException('configuration_guard');
    $fd=fopen($path,'rb');if(!is_resource($fd))throw new DomainException('configuration_open');
    $b=fstat($fd);$raw=stream_get_contents($fd,4097);$end=fstat($fd);fclose($fd);$after=lstat($path);
    foreach(['dev','ino','uid','gid','mode','nlink','size','mtime','ctime']as$key)if($a[$key]!==$b[$key]||$a[$key]!==$end[$key]||$a[$key]!==$after[$key])throw new DomainException('configuration_drift');
    $prefix="<?php\n// Private generated runtime configuration, not a public entry point.\nreturn json_decode('";$suffix="', true, 512, JSON_THROW_ON_ERROR);\n";
    if(!is_string($raw)||!str_starts_with($raw,$prefix)||!str_ends_with($raw,$suffix))throw new DomainException('configuration_format');
    $cfg=json_decode(substr($raw,strlen($prefix),-strlen($suffix)),true,8,JSON_THROW_ON_ERROR);unset($raw);
    if(!is_array($cfg)||($cfg['db_user']??null)!=='mail_management_app'||!is_string($cfg['db_password']??null)||!is_string($cfg['dsn']??null)||preg_match('~^mysql:unix_socket=/[A-Za-z0-9/_.-]+;dbname=mail_management;charset=utf8mb4$~D',$cfg['dsn'])!==1)throw new DomainException('caller_profile');
    $phase='caller_connect';$db=new PDO($cfg['dsn'],$cfg['db_user'],$cfg['db_password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);unset($cfg);
    if($db->query('SELECT CURRENT_USER()')->fetchColumn()!=='mail_management_app@localhost')throw new DomainException('caller_identity');
    $phase='zero_row_select';$db->exec('START TRANSACTION READ ONLY');
    $q=$db->query('SELECT c.id,c.login_id,c.user_id,c.enabled,c.revision,c.created_at,c.updated_at,u.email FROM mail_legacy_smtp_credentials c JOIN mailserver.virtual_users u ON u.id=c.user_id WHERE 1=0');
    if($q->fetchAll(PDO::FETCH_ASSOC)!==[])throw new DomainException('zero_rows');
    $phase='hash_select_denied';$denied=false;
    try{$db->query('SELECT password_hash FROM mail_legacy_smtp_credentials WHERE 1=0');}
    catch(PDOException $e){if(!in_array($e->errorInfo[1]??null,[1142,1143],true))throw $e;$denied=true;}
    if(!$denied)throw new DomainException('caller_hash_read_allowed');$db->rollBack();
    echo json_encode(['status'=>'ok','effective_metadata_select'=>true,'password_hash_select_denied'=>true,'application_rows_read'=>false],JSON_THROW_ON_ERROR);
}catch(Throwable $e){
    $failure=['status'=>'fail','phase'=>$phase,'class'=>get_class($e),'line'=>$e->getLine(),'sqlstate'=>$e instanceof PDOException?$e->getCode():null,'native_code'=>$e instanceof PDOException?($e->errorInfo[1]??null):null];
    fwrite(STDERR,(string)$e);echo json_encode($failure,JSON_THROW_ON_ERROR);exit(1);
}
