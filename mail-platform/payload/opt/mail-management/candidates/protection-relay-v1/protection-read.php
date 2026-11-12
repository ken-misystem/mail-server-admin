<?php
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');ini_set('zend.exception_ignore_args','1');
try {
 require $argv[1].'/bootstrap.php';
 foreach(['ProtectionController','UnixProtectionStore','ProtectionStore'] as $name) {
  $full='MailServer\\Management\\'.$name;
  if (!class_exists($full) && !interface_exists($full)) throw new DomainException('protection_class_missing');
 }
 $names=array_map(fn($p)=>$p->getName(),(new ReflectionClass('MailServer\\Management\\ConsoleKernel'))->getConstructor()->getParameters());
 if (!in_array('protectionStore',$names,true)) throw new DomainException('protection_kernel_binding');
 $input=json_decode(stream_get_contents(STDIN,1024),true,8,JSON_THROW_ON_ERROR);
 $client=new MailServer\Management\FeatureControlClient();
 foreach (['scanner','upstream'] as $kind) {
  $row=$client->call(['operation'=>'protection.read','actor'=>$input['actor'],'epoch'=>$input['epoch'],'kind'=>$kind]);
  if ($row['kind']!==$kind || $row['phase']!=='applied' || $row['revision']!==1 || $row['applied_revision']!==1 || $row['credential_present']!==false) throw new DomainException('protection_initial_state');
 }
 echo json_encode(['status'=>'pass','read_only'=>true,'settings'=>2,'credentials_exported'=>false],JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
 echo json_encode(['status'=>'fail','class'=>get_class($e),'source'=>basename($e->getFile()),'line'=>$e->getLine()]);
 exit(1);
}
