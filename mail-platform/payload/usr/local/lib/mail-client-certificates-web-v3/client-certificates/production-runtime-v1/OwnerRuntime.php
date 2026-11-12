<?php
declare(strict_types=1);
namespace MailServer\CertificateProductionCandidate;
require_once __DIR__.'/../production-preflight-v1/PeerGreeting.php';
require_once __DIR__.'/../live-transport-v1/Wire.php';
require_once __DIR__.'/../session-broker-v1/CurrentPolicy.php';
use MailServer\CertificatePeerCandidate\GreetingConnection;
use MailServer\CertificateTransportCandidate\{ByteWire,PacketWire,PullLease};
use MailServer\CertificateWebCandidate\{OwnerChannel,HttpSink,P12Stream};
use MailServer\CertificateSessionCandidate\{EpochReader,EpochView};
use MailServer\ClientCertificatesCandidate\DownloadStream;
use function MailServer\CertificateWebCandidate\guard;

/** No HMAC key or database credential in the shared PHP-FPM worker. */
final class OwnerRuntime implements OwnerChannel,EpochReader
{
    public function __construct(private string $socketPath,private int $uid,private int $gid,
        private \Closure $parentGuard,private \Closure $reference,private HttpSink $sink,private \Closure $clock) {}
    private function open(string $operation,array $input):ByteWire {
        $connection=GreetingConnection::open($this->socketPath,$this->uid,$this->gid,$this->parentGuard);
        try{
            $wire=new PacketWire($connection->stream(),fn($stream)=>$connection->requirePeer($stream),$this->clock,($this->clock)()+($operation==='issue_finish'?220:15));
            $reference=($this->reference)();
            guard(is_string($reference)&&preg_match('/\A[A-Za-z0-9,-]{16,256}\z/D',$reference)===1,'owner_session_reference');
            $wire->send(['operation'=>$operation,'input'=>(object)$input,'session_ref'=>$reference]);return $wire;
        }catch(\Throwable $error){$connection->close();throw $error;}
    }
    public function current(int $roundcubeId,string $username):EpochView {
        $wire=$this->open('current',[]);
        try{
            $value=$wire->receive();
            guard(array_keys($value)===['roundcube_id','username','epoch','active']
                &&$value['roundcube_id']===$roundcubeId&&$value['username']===$username
                &&is_int($value['epoch'])&&$value['epoch']>=0&&$value['active']===true,'owner_epoch_reply');
            return new EpochView($roundcubeId,$username,$value['epoch'],true);
        }finally{$wire->close();}
    }
    private function context(object $context):void {
        $reference=($this->reference)();
        guard(is_string($reference)&&isset($context->binding_hash)&&is_string($context->binding_hash)
            &&hash_equals(hash('sha256',"mail-device-v1\0".$reference),$context->binding_hash),'owner_context_changed');
    }
    public function call(string $operation,object $context,array $input):array {
        guard(in_array($operation,['list','issue_options','issue_finish','revoke_options','revoke_finish','verification_status','verification_options','verification_finish','verification_authorize','verification_consume','verification_invalidate'],true),'owner_operation');
        $this->context($context);$wire=$this->open($operation,$input);
        try{$value=$wire->receive();$this->context($context);return $value;}finally{$wire->close();}
    }
    public function claim(object $context,array $input):DownloadStream {
        guard(count($input)===2&&array_diff(array_keys($input),['device_id','download_handle'])===[],'owner_download_fields');
        $this->context($context);$wire=$this->open('download',$input);
        try{$lease=new PullLease($wire,fn()=>$this->context($context));return new P12Stream($lease,$this->sink,$this->clock);}
        catch(\Throwable $error){$wire->close();throw $error;}
    }
}
