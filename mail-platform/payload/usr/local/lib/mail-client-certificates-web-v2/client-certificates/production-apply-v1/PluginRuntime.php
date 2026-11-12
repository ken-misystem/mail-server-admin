<?php
declare(strict_types=1);
namespace MailServer\CertificateDeployment;
require_once __DIR__.'/../production-runtime-v1/OwnerRuntime.php';
require_once __DIR__.'/../web-runtime-v1/Endpoint.php';
use MailServer\CertificateWebCandidate as W;
use MailServer\CertificateProductionCandidate\OwnerRuntime;
use MailServer\CertificateSessionCandidate\BoundCurrentPolicy;

const RELEASE='/usr/local/lib/mail-client-certificates-web-v2';
final class Audit implements W\FailureAudit
{
    public function record(\Throwable $error,string $operation):void
    {
        $rows=[];$seen=[];$current=$error;
        do {
            $source=$current->getFile();$message=$current->getMessage();
            $rows[]=['class'=>get_class($current),'source'=>basename($source),'line'=>$current->getLine(),
                'reason'=>str_starts_with($source,RELEASE.'/')&&preg_match('/\A[a-z][a-z0-9_]{1,95}\z/D',$message)===1?$message:'unclassified'];
            $seen[spl_object_id($current)]=true;$current=$current->getPrevious();
        }while($current!==null&&!isset($seen[spl_object_id($current)])&&count($rows)<5);
        error_log(json_encode(['component'=>'mail_client_certificates_web','operation'=>in_array($operation,
            ['endpoint','response','retire','list','issue_options','issue_finish','revoke_options','revoke_finish','download','bootstrap'],true)?$operation:'unclassified',
            'failures'=>$rows,'raw_error_saved'=>false],JSON_THROW_ON_ERROR));
    }
}

function check(bool $value,string $code):void {if(!$value)throw new \RuntimeException($code);}

function protectedWebConfiguration(string $path='/etc/mail-client-certificates-v1/web.json'):array
{
    check($path==='/etc/mail-client-certificates-v1/web.json','fixed_web_configuration');
    $parts=explode('/',substr($path,1));$current='';
    foreach($parts as $part){
        $current.='/'.$part;$s=lstat($current);check(is_array($s)&&$s['uid']===0&&($s['mode']&0022)===0,'web_configuration_parent');
        check(($s['mode']&0170000)===($current===$path?0100000:0040000),'web_configuration_no_symlinks');
    }
    $before=lstat($path);check($before['nlink']===1&&$before['size']>0&&$before['size']<=8192&&($before['mode']&0007)===0,'web_configuration_metadata');
    $raw=file_get_contents($path);$after=lstat($path);check(is_string($raw)&&strlen($raw)===$before['size']&&$before===$after,'web_configuration_stable');
    $value=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
    check(is_array($value)&&array_keys($value)===['version','owner_uid','owner_gid']&&$value['version']===1
        &&is_int($value['owner_uid'])&&$value['owner_uid']>0&&is_int($value['owner_gid'])&&$value['owner_gid']>0,'web_configuration_fields');
    return $value;
}

function endpoint(\rcmail $rc,array $config):W\Endpoint
{
    check(isset($config['owner_uid'],$config['owner_gid'])&&is_int($config['owner_uid'])&&is_int($config['owner_gid'])
        &&$config['owner_uid']>0&&$config['owner_gid']>0,'web_owner_configuration');
    // Never discard data emitted by Roundcube or another plugin. Only empty,
    // removable buffers may be closed before the fixed binary response path.
    while(ob_get_level()>0){check(ob_get_contents()==='','web_prior_output_present');check(ob_end_clean(),'web_output_buffer_not_removable');}
    $path='/run/mail-client-certificates-v1/owner/owner.sock';
    $guard=static function()use($path,$config):void {
        $directory=lstat(dirname($path));$socket=lstat($path);
        check(is_array($directory)&&($directory['mode']&0170000)===0040000&&$directory['uid']===$config['owner_uid']
            &&$directory['gid']===$config['owner_gid']&&($directory['mode']&0022)===0,'web_owner_parent');
        check(is_array($socket)&&($socket['mode']&0170000)===0140000&&$socket['uid']===$config['owner_uid']
            &&$socket['gid']===$config['owner_gid']&&($socket['mode']&0777)===0660&&$socket['nlink']===1,'web_owner_socket');
    };
    $state=new W\NativeSessionState();$sink=new W\NativeHttpSink();$audit=new Audit();
    $wire=new OwnerRuntime($path,$config['owner_uid'],$config['owner_gid'],$guard,static fn():string=>session_id(),$sink,static fn():float=>hrtime(true)/1e9);
    return new W\Endpoint(new W\RoundcubeBridge($rc,$state,new BoundCurrentPolicy($state,$wire),$wire,$audit),new W\ResponseEmitter($sink,$audit));
}
