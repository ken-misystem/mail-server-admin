<?php
declare(strict_types=1);
// Public fixed source; secret inputs arrive only AFTER the existing C FD barrier.
set_error_handler(static function(int $level,string $message,string $file,int $line):never{throw new ErrorException('issuer_check_php_warning',0,$level,$file,$line);});
function framed(int $fd,int $maximum):string {
    $file=fopen('php://fd/'.$fd,'rb');if(!is_resource($file))throw new RuntimeException('issuer_check_fd');
    try{$raw=stream_get_contents($file,$maximum+1);}finally{fclose($file);}
    if(!is_string($raw)||strlen($raw)<4||strlen($raw)>$maximum)throw new RuntimeException('issuer_check_frame_bound');
    $length=unpack('Nsize',substr($raw,0,4))['size'];
    if($length<1||$length>$maximum-4||strlen($raw)<$length+4)throw new RuntimeException('issuer_check_frame_size');return substr($raw,4,$length);
}
try{
    $request=json_decode(framed(3,131072),true,8,JSON_THROW_ON_ERROR);
    if($request!==['operation'=>'issuer_key_pair'])throw new RuntimeException('issuer_check_operation');
    $metadata=json_decode(framed(6,8192),true,8,JSON_THROW_ON_ERROR);
    if(!is_int($metadata['record_length']??null)||$metadata['record_length']<1||$metadata['record_length']>65536||!is_string($metadata['password']??null))throw new RuntimeException('issuer_check_metadata');
    $password=base64_decode($metadata['password'],true);if(!is_string($password)||$password===''||strlen($password)>1024)throw new RuntimeException('issuer_check_password_shape');
    $file=fopen('php://fd/5','rb');try{$encrypted=stream_get_contents($file,$metadata['record_length']);}finally{fclose($file);}
    if(!is_string($encrypted)||strlen($encrypted)!==$metadata['record_length'])throw new RuntimeException('issuer_check_key_size');
    $private=openssl_pkey_get_private($encrypted,$password);if($private===false)throw new RuntimeException('issuer_check_decryption');
    $certificate=openssl_x509_read(framed(4,131072));if($certificate===false)throw new RuntimeException('issuer_check_certificate');
    $result=['ok'=>true,'matched'=>openssl_x509_check_private_key($certificate,$private)];
}catch(Throwable $error){$result=['ok'=>false,'phase'=>'issuer_key_pair','causes'=>[['class'=>get_class($error),'code'=>preg_match('/\A[a-z_]{1,90}\z/D',$error->getMessage())?$error->getMessage():null,'source'=>basename($error->getFile()),'line'=>$error->getLine()]],'raw_error_saved'=>false];}
restore_error_handler();$raw=json_encode($result,JSON_THROW_ON_ERROR);if(fwrite(STDOUT,$raw)!==strlen($raw)||!fflush(STDOUT))exit(74);exit($result['ok']?0:1);
