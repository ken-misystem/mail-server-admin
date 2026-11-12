<?php
declare(strict_types=1);

/** Dedicated SELECT-only role. Config is JSON data, never PHP/include. */
function routingReaderConfig(string $raw): array
{
    if (strlen($raw)>8192) { throw new DomainException('reader_config_profile'); }
    $data=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
    if (!is_array($data)) { throw new DomainException('reader_config_shape'); }
    $keys=array_keys($data);sort($keys);
    if ($keys!==['password','socket','user']||!is_string($data['socket'])
        ||$data['socket']===''||strpbrk($data['socket'],";\0\r\n")!==false||!is_string($data['user'])||!is_string($data['password'])) {
        throw new DomainException('reader_config_shape');
    }
    return $data;
}

if (realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__) {
    ini_set('display_errors','0'); ini_set('log_errors','0');
    try {
        // Parent anchored/no-follow reader passed this over a private anonymous pipe.
        $raw=stream_get_contents(STDIN,8193);
        if (!is_string($raw)||strlen($raw)>8192) { throw new DomainException('reader_config_profile'); }
        $data=routingReaderConfig($raw);
        $db=new PDO('mysql:unix_socket='.$data['socket'].';dbname=mail_management;charset=utf8mb4',$data['user'],$data['password'],
            [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false,PDO::ATTR_TIMEOUT=>2]);
        $db->exec('START TRANSACTION READ ONLY');
        $q=$db->query('SET STATEMENT max_statement_time=2 FOR SELECT d.id,d.name,COALESCE(p.follow_mx,0) AS follow_mx,'
            .'COALESCE(p.revision,0) AS revision FROM mailserver.virtual_domains d '
            .'LEFT JOIN mail_management.mail_domain_delivery_policy p ON p.domain_id=d.id WHERE d.active=1 ORDER BY d.id LIMIT 201');
        $rows=$q->fetchAll(PDO::FETCH_ASSOC); $db->rollBack();
        if (count($rows)>200) { throw new DomainException('domain_bound'); }
        echo json_encode(['status'=>'ok','rows'=>$rows],JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        $out=['status'=>'fail','failure'=>['class'=>get_class($e),'reason'=>'metadata_read_failed']];
        if ($e instanceof PDOException) {
            $out['failure']['sqlstate']=preg_match('/^[A-Z0-9]{5}$/D',(string)$e->getCode())?$e->getCode():null;
            $out['failure']['native_code']=is_int($e->errorInfo[1]??null)?$e->errorInfo[1]:null;
        }
        echo json_encode($out,JSON_THROW_ON_ERROR); exit(1);
    }
}
