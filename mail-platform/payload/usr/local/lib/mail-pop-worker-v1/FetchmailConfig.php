<?php
declare(strict_types=1);
namespace MailServer\Pop;

/** One account -> one fixed local owner. No network/process/file execution in this builder. */
final class FetchmailConfig
{
    public static function render(string $host,int $port,string $resolvedPublicIp,string $username,
        #[\SensitiveParameter] string $password,string $localRecipient,string $scanEndpoint):string
    {
        $host=PopSourcePolicy::host($host);PopSourcePolicy::port($port);
        PopSourcePolicy::publicIp($resolvedPublicIp);PopSourcePolicy::username($username);PopSourcePolicy::password($password);
        PopSourcePolicy::recipient($localRecipient);PopSourcePolicy::deliveryEndpoint($scanEndpoint);
        // Explicit pinned IP avoids a second hostname lookup changing the destination after public-IP validation.
        // TLS still verifies the approved original hostname, never a caller-supplied alternate certificate name.
        return "set no syslog\nset no bouncemail\nset no spambounce\nset softbounce\n"
            .'poll '.self::quote($host).' via '.self::quote($resolvedPublicIp).' protocol POP3 service '.self::quote((string)$port)."\n"
            ."  timeout 60 uidl no dns bad-header accept\n"
            .'  user '.self::quote($username).' there with password '.self::quote($password).' is '.self::quote($localRecipient)." here\n"
            .'  ssl sslcertck sslproto "TLS1.2+" sslcommonname '.self::quote($host)."\n"
            .'  smtphost '.self::quote($scanEndpoint)." keep fetchlimit 50\n";
    }
    private static function quote(#[\SensitiveParameter] string $value):string
    {
        return '"'.strtr($value,['\\'=>'\\\\','"'=>'\\"']).'"';
    }
    /** Fixed argv only; credentials remain in the future private0600 transient rcfile. */
    public static function command(string $accountId):array
    {
        $id=PopSourcePolicy::accountId($accountId);
        return ['/usr/bin/fetchmail','--nodetach','--daemon','0','--nosyslog','--silent',
            '--rcfile','/run/mail-pop/accounts/'.$id.'/fetchmailrc',
            '--idfile','/var/lib/mail-pop/accounts/'.$id.'/fetchids'];
    }
}
