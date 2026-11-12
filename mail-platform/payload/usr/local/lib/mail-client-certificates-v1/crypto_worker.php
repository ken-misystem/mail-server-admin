<?php
declare(strict_types=1);
// Template rendered from a held release manifest; no HTTP/environment path input.
const RELEASE_ROOT = '/usr/local/lib/mail-client-certificates-v1';
const VENDOR_AUTOLOAD = '/opt/roundcube-auth/vendor/autoload.php';
set_error_handler(static function(int $level,string $message,string $file,int $line):never {
    throw new ErrorException('native_php_warning',0,$level,$file,$line);
});
$result=['ok'=>false];$phase='public_dependencies';
function boundedFd(int $fd,int $maximum):string {
    $stream=fopen('php://fd/'.$fd,'rb');if(!is_resource($stream))throw new RuntimeException('worker_fd_open');
    try {$info=fstat($stream);if(!is_array($info)||$info['size']>$maximum)throw new RuntimeException('worker_fd_bound');
        $raw=stream_get_contents($stream,$maximum+1);if(!is_string($raw)||strlen($raw)>$maximum)throw new RuntimeException('worker_fd_bound');
        // Locked memfds have fixed capacity. Parent supplies a bounded JSON
        // frame, followed by zeros; consume only its explicit four-byte length.
        if(strlen($raw)<4)throw new RuntimeException('worker_fd_frame');
        $size=unpack('Nsize',substr($raw,0,4))['size'];
        if($size<1||$size>$maximum-4||strlen($raw)<4+$size)throw new RuntimeException('worker_fd_frame');
        return substr($raw,4,$size);
    } finally {fclose($stream);}
}
function from64(mixed $value,int $maximum):string {
    if(!is_string($value))throw new RuntimeException('worker_base64_type');
    $raw=base64_decode($value,true);
    if(!is_string($raw)||strlen($raw)>$maximum||base64_encode($raw)!==$value)throw new RuntimeException('worker_base64_shape');
    return $raw;
}
function recordFd(int $size):string {
    if($size<1||$size>131072)throw new RuntimeException('worker_record_input_bound');
    $stream=fopen('php://fd/5','rb');if(!is_resource($stream))throw new RuntimeException('worker_record_input');
    try {$raw=stream_get_contents($stream,$size);if(!is_string($raw)||strlen($raw)!==$size)throw new RuntimeException('worker_record_short_read');return $raw;}
    finally {fclose($stream);}
}
try {
    foreach(['token_get_all','ctype_digit','mb_strlen','openssl_verify']as $required)
        if(!function_exists($required))throw new RuntimeException('required_builtin_missing_'.$required);
    foreach(['RegistrationConfig','RegistrationException','AssertionValidator','StoredCredential','ValidatedAssertion','WebauthnLibAssertionValidator']as $file)
        require_once RELEASE_ROOT.'/deps/'.$file.'.php';
    require_once VENDOR_AUTOLOAD;
    $request=json_decode(boundedFd(3,131072),true,32,JSON_THROW_ON_ERROR);
    if(!is_array($request)||!is_string($request['operation']??null))throw new RuntimeException('worker_request_shape');
    $validator=\MailServer\RoundcubeAuth\WebauthnLibAssertionValidator::create();
    if($request['operation']==='options') {
        $phase='existing_assertion_options';$descriptors=$request['descriptors']??null;
        if(!is_array($descriptors)||!array_is_list($descriptors)||count($descriptors)<1||count($descriptors)>128)throw new RuntimeException('worker_descriptors');
        $decoded=[];
        foreach($descriptors as $item) {
            if(!is_array($item)||array_keys($item)!==['id','transports']||!is_array($item['transports']))throw new RuntimeException('worker_descriptor');
            $decoded[]=['id'=>from64($item['id'],1023),'transports'=>$item['transports']];
        }
        $options=$validator->createOptions(random_bytes(32),$decoded);
        $value=json_decode($options,true,32,JSON_THROW_ON_ERROR);
        if(($value['userVerification']??null)!=='required')throw new RuntimeException('worker_uv_not_required');
        $result=['ok'=>true,'options'=>$value];
    } elseif($request['operation']==='verify') {
        $phase='existing_assertion_verification';
        $metadata=json_decode(boundedFd(6,8192),true,8,JSON_THROW_ON_ERROR);
        if(!is_int($metadata['record_length']??null)||!is_array($request['assertion']??null))throw new RuntimeException('worker_verification_shape');
        $stored=new \MailServer\RoundcubeAuth\StoredCredential(from64($metadata['credential_id']??null,1023),
            from64($metadata['user_handle']??null,32),recordFd($metadata['record_length']));
        $validated=$validator->validate(json_encode($request['assertion'],JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),
            boundedFd(4,131072),$stored,from64($metadata['expected_handle']??null,32));
        $raw=$validated->credentialRecordJson;if(strlen($raw)<1||strlen($raw)>131072)throw new RuntimeException('worker_record_bound');
        $output=fopen('php://fd/8','wb');if(!is_resource($output))throw new RuntimeException('worker_record_output');
        try {if(fwrite($output,$raw)!==strlen($raw)||!fflush($output))throw new RuntimeException('worker_record_short_write');}finally{fclose($output);}
        $result=['ok'=>true,'credential_id'=>base64_encode($validated->credentialId),'user_handle'=>base64_encode($validated->userHandle),
            'sign_count'=>$validated->signCount,'record_length'=>strlen($raw)];
    } else throw new RuntimeException('worker_operation');
} catch(Throwable $error) {
    $frames=[];$cause=$error;
    for($i=0;$cause!==null&&$i<4;$i++,$cause=$cause->getPrevious()) {
        $code=$cause instanceof \MailServer\RoundcubeAuth\RegistrationException?$cause->diagnosticCode:
            (preg_match('/\A[a-z_]{1,90}\z/D',$cause->getMessage())?$cause->getMessage():null);
                $builtin=null;
        if($cause instanceof Error && preg_match('/\A(?:Call to undefined function |Call to undefined method )([A-Za-z_\\\\][A-Za-z0-9_\\\\:]*)(?:\(\))?/', $cause->getMessage(),$match))$builtin=$match[1];
        $frames[]=['class'=>get_class($cause),'code'=>$code,'builtin'=>$builtin,'source'=>basename($cause->getFile()),'line'=>$cause->getLine()];
    }
    $result=['ok'=>false,'phase'=>$phase,'causes'=>$frames,'raw_error_saved'=>false];
} finally {restore_error_handler();}
$raw=json_encode($result,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
if(strlen($raw)>131072||fwrite(STDOUT,$raw)!==strlen($raw)||!fflush(STDOUT))exit(74);
exit($result['ok']?0:1);
