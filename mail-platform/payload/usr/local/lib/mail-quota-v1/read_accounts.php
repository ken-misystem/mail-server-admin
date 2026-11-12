<?php
declare(strict_types=1);
ini_set('display_errors','0'); ini_set('log_errors','0'); ini_set('zend.exception_ignore_args','1');
$phase='configuration';
try {
    $path='/etc/mail-management/admin.php';$a=lstat($path);
    if (!$a || ($a['mode']&0170000)!==0100000 || $a['uid']!==0 || $a['nlink']!==1
        || ($a['mode']&0027)!==0 || $a['size']>4096) throw new DomainException('config_attributes');
    $f=fopen($path,'rb');if (!$f) throw new DomainException('config_open');
    $b=fstat($f);$raw=stream_get_contents($f,4097);$c=fstat($f);fclose($f);clearstatcache(true,$path);$d=lstat($path);
    foreach (['dev','ino','uid','gid','mode','nlink','size','mtime','ctime'] as $k) {
        if ($a[$k]!==$b[$k] || $b[$k]!==$c[$k] || $c[$k]!==$d[$k]) throw new DomainException('config_drift');
    }
    $prefix="<?php\n// Private generated runtime configuration, not a public entry point.\nreturn json_decode('";
    $suffix="', true, 512, JSON_THROW_ON_ERROR);\n";
    if (!str_starts_with($raw,$prefix) || !str_ends_with($raw,$suffix)) throw new DomainException('config_format');
    $cfg=json_decode(substr($raw,strlen($prefix),-strlen($suffix)),true,8,JSON_THROW_ON_ERROR);unset($raw);
    if (($cfg['db_user']??null)!=='mail_management_app' || !is_string($cfg['db_password']??null)
        || !is_string($cfg['dsn']??null) || !preg_match('~^mysql:unix_socket=/[A-Za-z0-9/_.-]+;dbname=mail_management;charset=utf8mb4$~D',$cfg['dsn'])) {
        throw new DomainException('config_profile');
    }
    $phase='connect';$db=new PDO($cfg['dsn'],$cfg['db_user'],$cfg['db_password'],[
        PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false,PDO::ATTR_PERSISTENT=>false]);unset($cfg);
    $phase='readonly_inventory';$db->exec('START TRANSACTION READ ONLY');
    if ($db->query('SELECT CURRENT_USER()')->fetchColumn()!=='mail_management_app@localhost') throw new DomainException('principal');
    $rows=$db->query('SET STATEMENT max_statement_time=2 FOR SELECT u.id,u.email,u.quota_bytes,u.active,d.active AS domain_active '
        .'FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id ORDER BY u.id LIMIT 10001')->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows)>10000) throw new DomainException('inventory_bound');
    $db->rollBack();echo json_encode($rows,JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    if (isset($db) && $db->inTransaction()) { try {$db->rollBack();} catch(Throwable $close) {} }
    // Full reason remains in the caller's root-private stderr capture; never print credentials/trace arguments.
    fwrite(STDERR,json_encode(['phase'=>$phase,'class'=>get_class($e),'line'=>$e->getLine(),
        'sqlstate'=>$e instanceof PDOException?$e->getCode():null,
        'native_code'=>$e instanceof PDOException?($e->errorInfo[1]??null):null,
        'reason'=>$e instanceof DomainException?$e->getMessage():'private_pdo_failure',
        'private_reason'=>$e->getMessage()],JSON_THROW_ON_ERROR));exit(1);
}
