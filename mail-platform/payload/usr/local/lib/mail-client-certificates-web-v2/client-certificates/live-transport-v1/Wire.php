<?php
declare(strict_types=1);
namespace MailServer\CertificateTransportCandidate;
require_once __DIR__.'/../session-broker-v1/OwnerChannel.php';
use MailServer\CertificateSessionCandidate\{AuthenticatedWire,OwnerWireFactory,DownloadClaim};
use MailServer\CertificateWebCandidate\DownloadLease;
use function MailServer\CertificateWebCandidate\guard;

interface ByteWire extends AuthenticatedWire { public function bytes(int $maximum): string; }

/** Connected private stream; peer verification is supplied by reviewed native adapter. */
final class PacketWire implements ByteWire
{
    private bool $closed=false;
    public function __construct(private mixed $stream, private \Closure $peer,
        private \Closure $clock, private float $deadline)
    {
        $now=($clock)();
        guard(is_resource($stream)&&get_resource_type($stream)==='stream'
            &&is_finite($deadline)&&$deadline>$now&&$deadline<=$now+220,'packet_wire_setup');
    }
    public function requirePeer(): void {
        guard(!$this->closed&&($this->clock)()<$this->deadline,'packet_wire_deadline');
        ($this->peer)($this->stream);
    }
    private function exact(int $count): string {
        $raw='';
        while(strlen($raw)<$count){
            $this->requirePeer();guard(stream_set_timeout($this->stream,1),'packet_timeout_setting');
            $part=fread($this->stream,$count-strlen($raw));
            if(($part===false||$part==='')&&(stream_get_meta_data($this->stream)['timed_out']??false)===true)continue;
            guard(is_string($part)&&$part!=='','packet_wire_eof');$raw.=$part;
        }
        return $raw;
    }
    private function packet(int $maximum): string {
        $size=unpack('Nsize',$this->exact(4))['size'];
        guard($size>0&&$size<=$maximum,'packet_wire_bound');return $this->exact($size);
    }
    public function send(array $value): void {
        $raw=json_encode((object)$value,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
        guard(strlen($raw)<=131072,'packet_wire_bound');$raw=pack('N',strlen($raw)).$raw;$at=0;
        while($at<strlen($raw)){
            $this->requirePeer();guard(stream_set_timeout($this->stream,1),'packet_timeout_setting');
            $count=fwrite($this->stream,substr($raw,$at));
            if($count===0&&(stream_get_meta_data($this->stream)['timed_out']??false)===true)continue;
            guard(is_int($count)&&$count>0,'packet_wire_write');$at+=$count;
        }
    }
    public function receive(): array {
        $raw=$this->packet(65536);$value=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
        guard(is_array($value)&&!array_is_list($value),'packet_json_object');return $value;
    }
    public function bytes(int $maximum): string {
        guard($maximum>0&&$maximum<=8192,'packet_chunk_bound');$raw=$this->packet($maximum+1);
        guard($raw[0]==='B'&&strlen($raw)>1,'packet_binary_type');return substr($raw,1);
    }
    public function close(): void {
        if(!$this->closed){$this->closed=true;guard(fclose($this->stream),'packet_close_failed');}
    }
}

/** Session reference never becomes HTTP body data or public result metadata. */
final class SessionReferenceWire implements AuthenticatedWire
{
    private bool $first=true;
    public function __construct(private AuthenticatedWire $wire,private \Closure $sessionReference) {}
    public function requirePeer():void{$this->wire->requirePeer();}
    public function send(array $value):void {
        $this->wire->requirePeer();
        if($this->first){
            guard(array_keys($value)===['operation','input'],'reference_request_shape');
            $reference=($this->sessionReference)();
            guard(is_string($reference)&&preg_match('/\A[A-Za-z0-9,-]{16,256}\z/D',$reference)===1,'reference_shape');
            $value['session_ref']=$reference;$this->first=false;
        }
        $this->wire->send($value);
    }
    public function receive():array{return $this->wire->receive();}
    public function close():void{$this->wire->close();}
    public function byteWire():ByteWire{
        guard($this->wire instanceof ByteWire,'reference_binary_wire');return $this->wire;
    }
    public static function nativeReference():string {
        guard(session_status()===PHP_SESSION_ACTIVE,'reference_session_inactive');return session_id();
    }
}

final class PullLease implements DownloadLease
{
    private int $remaining;private bool $completed=false;private bool $retired=false;
    public function __construct(private ByteWire $wire,private \Closure $current){
        $wire->requirePeer();($current)();$metadata=$wire->receive();
        guard(array_keys($metadata)===['p12_length']&&is_int($metadata['p12_length'])
            &&$metadata['p12_length']>0&&$metadata['p12_length']<=131072,'pull_lease_length');
        $this->remaining=$metadata['p12_length'];$this->length=$this->remaining;
    }
    private readonly int $length;
    public function length():int{return $this->length;}
    public function requireActive():void {
        guard(!$this->retired,'pull_lease_retired');$this->wire->requirePeer();($this->current)();
    }
    public function read(int $maximum,float $deadline):string {
        $this->requireActive();guard(!$this->completed&&$maximum>0&&$maximum<=8192&&$this->remaining>0
            &&hrtime(true)/1e9<$deadline,'pull_lease_read_scope');
        $maximum=min($maximum,$this->remaining);$this->wire->send(['read'=>$maximum]);
        $bytes=$this->wire->bytes($maximum);
        guard(strlen($bytes)===$maximum,'pull_lease_short_read');$this->remaining-=strlen($bytes);return $bytes;
    }
    public function complete():void {
        $this->requireActive();guard(!$this->completed&&$this->remaining===0,'pull_lease_premature_complete');
        $this->wire->send(['complete'=>true]);
        guard($this->wire->receive()===['complete'=>true,'retired'=>true],'pull_lease_completion_unverified');
        $this->completed=true;$this->retire();
    }
    public function retire():void {
        if($this->retired)return;$this->retired=true;
        try{
            if(!$this->completed){$this->wire->requirePeer();$this->wire->send(['retire'=>true]);
                guard($this->wire->receive()===['retired'=>true],'pull_lease_retirement_unverified');}
        }finally{$this->wire->close();}
    }
}

final class PullClaim implements DownloadClaim
{
    public function __construct(private \Closure $current) {}
    public function claim(AuthenticatedWire $wire,object $context,array $input):DownloadLease {
        guard($wire instanceof SessionReferenceWire,'pull_reference_wire_required');
        try{return new PullLease($wire->byteWire(),fn()=>($this->current)($context));}
        catch(\Throwable $error){$wire->close();throw $error;}
    }
}
