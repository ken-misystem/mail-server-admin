<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** Called inside the existing alias_namespace lock, including disabled reservations. */
final class MailboxNamespaceGuard
{
    public static function available(PDO $db,string $local,array $domain):void
    {
        if((string)($domain['active']??'')!=='1'){throw new \DomainException('inactive_domain');}
        $q=$db->prepare('SELECT alias_domain FROM mailserver.virtual_domain_aliases WHERE target_domain_id=? ORDER BY alias_domain LIMIT 1001');$q->execute([$domain['id']]);
        $aliases=$q->fetchAll(PDO::FETCH_COLUMN);if(count($aliases)>1000){throw new \DomainException('namespace_inventory_bound');}
        $names=array_unique([$domain['name'],...$aliases]);$addresses=[];$sources=[$local];
        foreach($names as $name){$name=AdminMailPolicy::domain($name);$addresses[]=$local.'@'.$name;$sources[]=$local.'@'.$name;$sources[]='@'.$name;}
        foreach([['mailserver.virtual_users','email',$addresses],['mailserver.virtual_aliases','source',$sources],['mail_owned_aliases','source',$addresses]] as [$table,$column,$values]){
            foreach(array_chunk($values,256) as $chunk){
                $sql='SELECT 1 FROM '.$table.' WHERE ('.AliasPolicy::namespaceSql($column).') IN ('.implode(',',array_fill(0,count($chunk),'?')).') LIMIT 1';
                $q=$db->prepare($sql);$q->execute($chunk);if($q->fetchColumn()!==false){throw new \DomainException('namespace_unavailable');}
            }
        }
    }
}
