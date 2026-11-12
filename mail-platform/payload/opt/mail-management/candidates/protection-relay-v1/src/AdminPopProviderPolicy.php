<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Provider metadata only. Public-IP/TLS binding is required separately at polling. */
final class AdminPopProviderPolicy
{
    public static function host(string $host):string
    {
        try{return AdminMailPolicy::domain($host);}
        catch(\DomainException){throw new \DomainException('invalid_pop_provider');}
    }
    public static function label(string $label):string
    {
        $label=trim($label);
        if($label==='' || strlen($label)>128 || preg_match('//u',$label)!==1
            || preg_match('/[\x00-\x1f\x7f]/',$label))throw new \DomainException('invalid_pop_provider');
        return $label;
    }
    public static function port(string $port):int
    {
        if(!preg_match('/\A[1-9][0-9]{0,4}\z/D',$port) || (int)$port>65535)throw new \DomainException('invalid_pop_provider');
        return (int)$port;
    }
    public static function identity(string $host,int $port):string {return self::host($host).':'.self::port((string)$port);}
}
