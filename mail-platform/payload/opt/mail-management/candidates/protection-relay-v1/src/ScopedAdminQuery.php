<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Shared HTTP/PDO input contract. SQL identifiers never come from a request. */
final class ScopedAdminQuery
{
    public const SECTIONS = ['mailboxes'=>'mailbox.read', 'aliases'=>'alias.read', 'forwards'=>'forward.read', 'usage'=>'usage.read'];
    public static function section(string $section): string
    {
        if (!isset(self::SECTIONS[$section])) { throw new \DomainException('invalid_section'); }
        return self::SECTIONS[$section];
    }
    public static function id(mixed $id, bool $zero = false): string
    {
        if (!is_string($id) || !preg_match($zero ? '/^(?:0|[1-9][0-9]{0,19})$/D' : '/^[1-9][0-9]{0,19}$/D', $id)
            || (strlen($id) === 20 && strcmp($id, '18446744073709551615') > 0)) { throw new \DomainException('invalid_identifier'); }
        return $id;
    }
    public static function filter(array $input): array
    {
        if (array_diff(array_keys($input), ['domain_id','prefix','state','size','after'])) { throw new \DomainException('invalid_filter'); }
        $domain = self::id($input['domain_id'] ?? '0', true);
        if (strlen($domain)>10 || (strlen($domain)===10 && strcmp($domain,'4294967295')>0)) { throw new \DomainException('invalid_domain'); }
        $prefix=$input['prefix']??''; $state=$input['state']??'any'; $size=$input['size']??'25';
        if (!is_string($prefix) || strlen($prefix)>320 || preg_match('/[^\x21-\x7e]/', $prefix)
            || !in_array($state,['any','0','1'],true) || !in_array($size,['25','50','100'],true)) { throw new \DomainException('invalid_filter'); }
        return ['domain_id'=>$domain,'prefix'=>strtolower($prefix),'state'=>$state,'size'=>$size,'after'=>self::id($input['after']??'0',true)];
    }
    public static function pattern(string $prefix): string { return strtr($prefix,['='=>'==','%'=>'=%','_'=>'=_']).'%'; }
}
