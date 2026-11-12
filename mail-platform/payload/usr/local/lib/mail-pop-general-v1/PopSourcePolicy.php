<?php
declare(strict_types=1);
namespace MailServer\Pop;

/** Source syntax/public-IP guards; owner/quota come from server rows, source choice from the owner. */
final class PopSourcePolicy
{
    public static function host(string $host):string
    {
        $host=strtolower($host);
        if(strlen($host)>253 || !str_contains($host,'.') || filter_var($host,FILTER_VALIDATE_IP)!==false) {
            throw new \DomainException('invalid_pop_host');
        }
        foreach(explode('.',$host) as $label) {
            if(!preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D',$label))throw new \DomainException('invalid_pop_host');
        }
        return $host;
    }
    public static function port(int $port):int
    {
        if($port<1 || $port>65535)throw new \DomainException('invalid_pop_port');
        return $port;
    }
    /** Legacy helper; self-selected registration/worker does not use an administrator allowlist. */
    public static function providerMatch(string $host,int $port,string $approvedHost,int $approvedPort):void
    {
        if(self::host($host)!==self::host($approvedHost) || self::port($port)!==self::port($approvedPort)) {
            throw new \DomainException('pop_provider_not_allowed');
        }
    }
    public static function publicIp(string $ip):string
    {
        if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_GLOBAL_RANGE)===false)throw new \DomainException('pop_endpoint_not_public');
        return $ip;
    }
    public static function username(string $value):string {return self::text($value,320,'invalid_pop_username');}
    public static function password(#[\SensitiveParameter] string $value):string {return self::text($value,1024,'invalid_pop_password');}
    private static function text(#[\SensitiveParameter] string $value,int $max,string $error):string
    {
        if($value==='' || strlen($value)>$max || preg_match('//u',$value)!==1 || preg_match('/[\x00-\x1f\x7f]/',$value))throw new \DomainException($error);
        return $value; // Preserve case, spaces, quote/backslash and legacy carrier login spelling.
    }
    public static function recipient(string $address):string
    {
        $parts=explode('@',$address);
        if(strlen($address)>254 || count($parts)!==2 || !preg_match('/\A[a-z0-9][a-z0-9._-]{0,63}\z/iD',$parts[0])
            || str_ends_with($parts[0],'.') || str_contains($parts[0],'..'))throw new \DomainException('invalid_local_recipient');
        self::host($parts[1]);
        return $address; // Only the active authenticated owner's stored mailbox, supplied by future repository.
    }
    public static function accountId(string $id):string
    {
        if(!preg_match('/\A[1-9][0-9]{0,19}\z/D',$id) || (strlen($id)===20 && strcmp($id,'18446744073709551615')>0)) {
            throw new \DomainException('invalid_pop_id');
        }
        return $id;
    }
    public static function deliveryEndpoint(string $endpoint):string
    {
        if(!preg_match('~\A127\.0\.0\.1/([1-9][0-9]{0,4})\z~D',$endpoint,$m)
            || (int)$m[1]<1024 || (int)$m[1]>65535 || (int)$m[1]===10026) {
            throw new \DomainException('pop_scan_endpoint_required');
        }
        return $endpoint; // Syntax only: a separately approved, scan-bound dedicated ingress is mandatory.
    }
}
