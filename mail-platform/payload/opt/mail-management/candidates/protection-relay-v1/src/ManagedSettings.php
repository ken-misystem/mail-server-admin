<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Typed configuration only. No paths, commands, credentials, or executable text. */
final class ManagedSettings
{
    public const KINDS=['access','spam'];
    public const REASONS=['abuse','malware','operator','migration'];
    public static function defaults(string $kind):array
    {return match($kind){'access'=>['rules'=>[]],'spam'=>['profiles'=>[['domain_id'=>0,'greylist'=>4,'add_header'=>6,'reject'=>20]]],default=>throw new \DomainException('invalid_setting_kind')};}
    private static function keys(array $row,array $keys):void
    {$actual=array_keys($row);sort($actual);sort($keys);if($actual!==$keys){throw new \DomainException('invalid_setting_fields');}}
    public static function network(string $value):string
    {
        if(substr_count($value,'/')!==1||str_contains($value,'%')){throw new \DomainException('invalid_network');}[$host,$prefix]=explode('/',$value);
        if(filter_var($host,FILTER_VALIDATE_IP)===false){throw new \DomainException('invalid_network');}$packed=inet_pton($host);if($packed===false||inet_ntop($packed)!==$host||!preg_match('/^(?:0|[1-9][0-9]{0,2})$/D',$prefix)||(int)$prefix>strlen($packed)*8){throw new \DomainException('invalid_network');}
        $bits=(int)$prefix;for($i=0;$i<strlen($packed);++$i){$remaining=max(0,min(8,$bits-$i*8));$mask=$remaining===0?255:(255>>$remaining);if((ord($packed[$i])&$mask)!==0){throw new \DomainException('network_host_bits');}}
        return $value;
    }
    public static function validate(string $kind,array $payload):array
    {
        if(!in_array($kind,self::KINDS,true)){throw new \DomainException('invalid_setting_kind');}
        if($kind==='access'){
            self::keys($payload,['rules']);if(!is_array($payload['rules'])||!array_is_list($payload['rules'])||count($payload['rules'])>10000){throw new \DomainException('rule_inventory_bound');}$seen=[];$output=[];
            foreach($payload['rules']as $row){if(!is_array($row)){throw new \DomainException('invalid_rule');}self::keys($row,['kind','scope','value','effect','expires','domain_id','reason']);
                if(!in_array($row['kind'],['ip','address','domain'],true)||!in_array($row['scope'],['client','sender','recipient','spam'],true)||!in_array($row['effect'],['allow','deny'],true)||!in_array($row['reason'],self::REASONS,true)||!is_string($row['value'])||!is_int($row['expires'])||$row['expires']<0||$row['expires']>4102444800||!is_int($row['domain_id'])||$row['domain_id']<0||$row['domain_id']>4294967295){throw new \DomainException('invalid_rule');}
                if($row['kind']==='ip'){if(!in_array($row['scope'],['client','spam'],true)||$row['domain_id']!==0){throw new \DomainException('invalid_client_scope');}self::network($row['value']);}
                elseif($row['kind']==='address'){if(!in_array($row['scope'],['sender','recipient','spam'],true)){throw new \DomainException('invalid_address_scope');}ForwardPlan::address($row['value']);}
                else{if(!in_array($row['scope'],['sender','recipient','spam'],true)||$row['value']!==AdminMailPolicy::domain($row['value'])){throw new \DomainException('invalid_domain_scope');}}
                $key=json_encode([$row['kind'],$row['scope'],$row['value'],$row['domain_id']],JSON_THROW_ON_ERROR);if(isset($seen[$key])){throw new \DomainException('duplicate_or_conflicting_rule');}$seen[$key]=true;$output[]=$row;
            }
            return ['rules'=>$output];
        }
        self::keys($payload,['profiles']);if(!is_array($payload['profiles'])||!array_is_list($payload['profiles'])||count($payload['profiles'])<1||count($payload['profiles'])>1001){throw new \DomainException('spam_profile_bound');}$seen=[];$profiles=[];
        foreach($payload['profiles']as $row){if(!is_array($row)){throw new \DomainException('invalid_spam_profile');}self::keys($row,['domain_id','greylist','add_header','reject']);
            if(!is_int($row['domain_id'])||$row['domain_id']<0||$row['domain_id']>4294967295||isset($seen[$row['domain_id']])){throw new \DomainException('duplicate_spam_domain');}
            foreach(['greylist','add_header','reject']as $key){if((!is_int($row[$key])&&!is_float($row[$key]))||!is_finite((float)$row[$key])||$row[$key]<0||$row[$key]>100){throw new \DomainException('invalid_spam_threshold');}}
            if($row['greylist']>=$row['add_header']||$row['add_header']>=$row['reject']){throw new \DomainException('spam_threshold_order');}$seen[$row['domain_id']]=true;$profiles[]=$row;
        }
        if(!isset($seen[0])){throw new \DomainException('default_spam_profile_required');}usort($profiles,static fn($a,$b)=>$a['domain_id']<=>$b['domain_id']);return ['profiles'=>$profiles];
    }
}
