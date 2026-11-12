<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Complete local inventory, not only the domains visible on the current page. */
final class ForwardPlan
{
    public static function address(string $value):string
    {
        if(strlen($value)>254||$value!==strtolower($value)||substr_count($value,'@')!==1){throw new \DomainException('invalid_forward_address');}
        [$local,$host]=explode('@',$value);if($host!==AdminMailPolicy::domain($host)){throw new \DomainException('invalid_forward_address');}
        if(strlen($local)<1||strlen($local)>64){throw new \DomainException('invalid_forward_address');}
        foreach(explode('.',$local)as $atom){if($atom===''||strspn($atom,"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+/=?^_`{|}~-")!==strlen($atom)){throw new \DomainException('invalid_forward_address');}}
        return $value;
    }
    public static function targets(array $values):array
    {
        if(!array_is_list($values)||count($values)>10){throw new \DomainException('forward_target_bound');}
        $result=[];foreach($values as $value){if(!is_string($value)){throw new \DomainException('invalid_forward_address');}$result[]=self::address($value);}
        if(count(array_unique($result))!==count($result)){throw new \DomainException('duplicate_forward_target');}sort($result,SORT_STRING);return $result;
    }
    public static function project(array $routes,array $domains,array $domainAliases,array $users,array $aliases):array
    {
        foreach([[$domains,10000],[$domainAliases,1000],[$users,10000],[$aliases,10000],[$routes,10000]]as[$rows,$bound]){if(count($rows)>$bound){throw new \DomainException('forward_inventory_bound');}}
        $hosts=[];foreach($domains as $row){$host=AdminMailPolicy::domain($row['name']);if(isset($hosts[$host])){throw new \DomainException('forward_domain_ambiguous');}$hosts[$host]=(string)$row['id'];}
        $domainMap=[];foreach($domainAliases as $row){$alias=AdminMailPolicy::domain($row['alias_domain']);$target=array_search((string)$row['target_domain_id'],$hosts,true);if($target===false||isset($hosts[$alias])||isset($domainMap[$alias])){throw new \DomainException('forward_domain_alias_invalid');}$domainMap[$alias]=$target;}
        $key=static function(string $value)use($hosts,$domainMap):string{[$local,$host]=explode('@',self::address($value));$host=$domainMap[$host]??$host;return isset($hosts[$host])?str_replace('.','',explode('+',$local,2)[0]).'@'.$host:$value;};
        $mailboxes=[];foreach($users as $row){$email=self::address($row['email']);$host=explode('@',$email)[1];$k=$key($email);if(!isset($hosts[$host])||$hosts[$host]!== (string)$row['domain_id']||isset($mailboxes[$k])){throw new \DomainException('forward_mailbox_ambiguous');}$mailboxes[$k]=$row;}
        $mapping=[];foreach($aliases as $row){$source=self::address($row['source']);$host=explode('@',$source)[1];$k=$key($source);if((!isset($hosts[$host])&&!isset($domainMap[$host]))||isset($mapping[$k])||isset($mailboxes[$k])){throw new \DomainException('forward_alias_ambiguous');}
            $targets=self::targets(explode(',',$row['destination']));if(!$targets){throw new \DomainException('forward_alias_targets');}$mapping[$k]=['targets'=>$targets,'domain_id'=>(string)$row['domain_id']];}
        $resolve=static function(string $value)use($key,$hosts,$domainMap,$mailboxes,$mapping):array{
            $pending=[[$value,[]]];$leaves=[];$affected=[];$steps=0;
            while($pending){[$value,$trail]=array_pop($pending);if(++$steps>10000||count($trail)>64){throw new \DomainException('forward_alias_depth');}$host=explode('@',$value)[1];
                if(!isset($hosts[$host])&&!isset($domainMap[$host])){$leaves[$value]=true;continue;}$k=$key($value);if(isset($trail[$k])){throw new \DomainException('forward_alias_cycle');}$trail[$k]=true;
                $primary=$domainMap[$host]??$host;$affected[$hosts[$primary]]=true;
                if(isset($mailboxes[$k])){$leaves[$mailboxes[$k]['email']]=true;continue;}
                if(!isset($mapping[$k])){throw new \DomainException('forward_local_destination_missing');}$affected[$mapping[$k]['domain_id']]=true;
                foreach($mapping[$k]['targets']as $target){$pending[]=[$target,$trail];}
            }
            if(count($leaves)>10){throw new \DomainException('forward_target_bound');}$targets=array_keys($leaves);sort($targets,SORT_STRING);return [$targets,array_map(strval(...),array_keys($affected))];
        };
        $graph=[];$projected=[];
        foreach($routes as $row){$source=self::address($row['source']);$k=$key($source);if(!isset($mailboxes[$k])||$mailboxes[$k]['email']!==$source||isset($graph[$source])){throw new \DomainException('forward_source_invalid');}
            $targets=[];$affected=[(string)$mailboxes[$k]['domain_id']];foreach(self::targets($row['destinations'])as $target){[$resolved,$ids]=$resolve($target);$targets=[...$targets,...$resolved];$affected=[...$affected,...$ids];}
            $targets=array_values(array_unique($targets));sort($targets,SORT_STRING);if(count($targets)>10){throw new \DomainException('forward_target_bound');}
            $graph[$source]=$targets;$projected[$source]=['destinations'=>$targets,'domain_ids'=>array_values(array_unique($affected))];
        }
        $state=[];
        foreach(array_keys($graph)as $source){$stack=[[$source,false]];while($stack){[$node,$done]=array_pop($stack);if($done){$state[$node]=2;continue;}if(($state[$node]??0)===1){throw new \DomainException('forward_cycle');}if(($state[$node]??0)===2){continue;}$state[$node]=1;$stack[]=[$node,true];foreach($graph[$node]??[]as $target){if(($state[$target]??0)===1){throw new \DomainException('forward_cycle');}if(isset($graph[$target])&&($state[$target]??0)!==2){$stack[]=[$target,false];}}}}
        return $projected;
    }
}
