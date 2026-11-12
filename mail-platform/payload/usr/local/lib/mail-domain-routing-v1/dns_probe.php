<?php
declare(strict_types=1);

/** One domain per child. Parent bounds real time/output and kills a blocked resolver. */
function routingDnsProbe(string $domain, Closure $lookup): array
{
    if (strlen($domain)>253 || !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',$domain)) {
        throw new DomainException('invalid_domain');
    }
    try {
        $mx=$lookup($domain,DNS_MX);
        if ($mx===false) { return ['failure'=>'dns_failure']; }
        if (!is_array($mx)) { return ['failure'=>'dns_shape']; }
        if (count($mx)===0) { return ['failure'=>'no_mx']; }
        if (count($mx)>16) { return ['failure'=>'dns_bound']; }
        $out=[];
        foreach ($mx as $record) {
            if (($record['type']??null)!=='MX'||!is_string($record['target']??null)||!is_int($record['pri']??null)||!is_int($record['ttl']??null)) {
                return ['failure'=>'dns_shape'];
            }
            if ($record['target']==='.'||$record['target']==='') { return ['failure'=>'null_mx']; }
            $host=strtolower(rtrim($record['target'],'.'));
            if (strlen($host)>253||!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',$host)) {
                return ['failure'=>'dns_shape'];
            }
            $addresses=[];
            foreach ([DNS_A=>'A',DNS_AAAA=>'AAAA'] as $type=>$label) {
                $rows=$lookup($host,$type);
                if ($rows===false) { return ['failure'=>'address_lookup_failed']; }
                if (!is_array($rows)||count($rows)>32) { return ['failure'=>'dns_bound']; }
                foreach ($rows as $row) {
                    $value=$row[$label==='A'?'ip':'ipv6']??null;
                    if (($row['type']??null)!==$label||!is_string($value)||!is_int($row['ttl']??null)
                        ||strtolower(rtrim((string)($row['host']??''),'.'))!==$host) {
                        return ['failure'=>'dns_shape'];
                    }
                    $addresses[]=['ip'=>$value,'ttl'=>$row['ttl']];
                }
            }
            if (!$addresses||count($addresses)>32) { return ['failure'=>'address_lookup_failed']; }
            $out[]=['host'=>$host,'preference'=>$record['pri'],'ttl'=>$record['ttl'],'addresses'=>$addresses];
        }
        return ['mx'=>$out];
    } catch (Throwable) {
        // Never return resolver errors, stack arguments or arbitrary upstream data.
        return ['failure'=>'dns_failure'];
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__) {
    ini_set('display_errors','0');
    ini_set('log_errors','0');
    $input=stream_get_contents(STDIN,513);
    if (!is_string($input)||strlen($input)>512) { exit(1); }
    try {
        $body=json_decode($input,true,4,JSON_THROW_ON_ERROR);
        if (!is_array($body)||array_keys($body)!==['domain']||!is_string($body['domain'])) { throw new DomainException('invalid_input'); }
        $reply=routingDnsProbe($body['domain'],static fn(string $host,int $type)=>@dns_get_record($host,$type));
        echo json_encode($reply,JSON_THROW_ON_ERROR);
    } catch (Throwable) { echo '{"failure":"dns_shape"}'; exit(1); }
}
