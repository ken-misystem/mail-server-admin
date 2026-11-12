<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Root-owned public projection only. No credentials, original logs or mailbox data. */
final class FileFeatureObservations implements FeatureObservations
{
    public function __construct(private readonly string $directory='/run/mail-feature-health-v1'){}
    private function read(string $name,int $maximum=2097152):array
    {
        if(!preg_match('/^(?:status|dns-[a-f0-9]{64})\.json$/D',$name)){throw new \DomainException('observation_name');}
        $parent=lstat($this->directory);if(!$parent||($parent['mode']&0170000)!==0040000||$parent['uid']!==0||($parent['mode']&0022)!==0){throw new \DomainException('observation_parent');}
        $path=$this->directory.'/'.$name;$before=lstat($path);if(!$before||($before['mode']&0170000)!==0100000||$before['uid']!==0||$before['nlink']!==1||($before['mode']&0777)!==0640||$before['size']<2||$before['size']>$maximum){throw new \DomainException('observation_file');}
        $stream=fopen($path,'rb');if(!$stream){throw new \DomainException('observation_open');}
        try{$opened=fstat($stream);$raw=stream_get_contents($stream,$maximum+1);$after=fstat($stream);clearstatcache(true,$path);$named=lstat($path);
            foreach(['dev','ino','uid','gid','mode','size','mtime','ctime','nlink']as $field){if($before[$field]!==$opened[$field]||$before[$field]!==$after[$field]||$before[$field]!==($named[$field]??null)){throw new \DomainException('observation_changed');}}
            if($raw===false||strlen($raw)!==$before['size']){throw new \DomainException('observation_read_bound');}$value=json_decode($raw,true,32,JSON_THROW_ON_ERROR);if(!is_array($value)){throw new \DomainException('observation_shape');}return $value;
        }finally{fclose($stream);}
    }
    public static function validate(array $value,int $now):array
    {
        if(($value['version']??null)!==1||!is_int($value['observed_at']??null)||$value['observed_at']>$now+5||$value['observed_at']<$now-300){throw new \DomainException('observation_stale');}
        $out=['version'=>1,'observed_at'=>$value['observed_at']];
        foreach(['authentication','backup','scanner','upstream','forwarding','configuration']as $key){
            $section=$value[$key]??null;if(!is_array($section)||!in_array($section['state']??null,['ok','unavailable','incomplete','not_configured','unverified'],true)){throw new \DomainException('observation_section');}
            $out[$key]=['state'=>$section['state']];
        }
        $auth=$value['authentication'];
        if($auth['state']==='ok'||$auth['state']==='incomplete'){
            if(($auth['requested_seconds']??null)!==86400||!is_array($auth['totals']??null)||count($auth['totals'])>1008||!is_array($auth['top_IPs']??null)||count($auth['top_IPs'])>100||($auth['full_period_coverage_proven']??null)!==false){throw new \DomainException('auth_observation_bound');}
            $out['authentication']['totals']=[];$out['authentication']['top_IPs']=[];$out['authentication']['full_period_coverage_proven']=false;
            foreach($auth['totals']as $row){if(!is_array($row)||!is_int($row['at']??null)||!is_int($row['count']??null)||$row['count']<0||!in_array($row['category']??null,['access','smtp_in','smtp_out','web','security','system'],true)){throw new \DomainException('auth_observation_row');}$out['authentication']['totals'][]=array_intersect_key($row,array_flip(['at','count','category']));}
            foreach($auth['top_IPs']as $row){if(!is_array($row)||!is_string($row['ip']??null)||!filter_var($row['ip'],FILTER_VALIDATE_IP)||!is_int($row['count']??null)||$row['count']<0){throw new \DomainException('auth_observation_IP');}$out['authentication']['top_IPs'][]=['ip'=>$row['ip'],'count'=>$row['count']];}
        }
        $backup=$value['backup'];if($backup['state']==='ok'){
            if(!is_string($backup['sha256']??null)||!preg_match('/^[a-f0-9]{64}$/D',$backup['sha256'])||!is_int($backup['bytes']??null)||$backup['bytes']<1||($backup['restore_test']??null)!==false||($backup['complete_mail_archive']??null)!==false||($backup['external_copy_currently_accessible']??null)!==false){throw new \DomainException('backup_observation');}
            $out['backup']+=['sha256'=>$backup['sha256'],'bytes'=>$backup['bytes'],'restore_test'=>false,'complete_mail_archive'=>false,'external_copy_currently_accessible'=>false];
        }
        foreach(['engine_present','configured','daemon_running','detection_verified','attachment_rules_configured']as $field){if(!is_bool($value['scanner'][$field]??null)){throw new \DomainException('scanner_observation');}$out['scanner'][$field]=$value['scanner'][$field];}
        if(!$out['scanner']['engine_present']&&($out['scanner']['daemon_running']||$out['scanner']['detection_verified'])){throw new \DomainException('scanner_evidence_inconsistent');}
        foreach(['relay_configured','credentials_configured','direct_MX']as $field){if(!is_bool($value['upstream'][$field]??null)){throw new \DomainException('upstream_observation');}$out['upstream'][$field]=$value['upstream'][$field];}
        foreach(['configured','held','scripts']as $field){if(!is_int($value['forwarding'][$field]??null)||$value['forwarding'][$field]<0||$value['forwarding'][$field]>10000){throw new \DomainException('forward_observation');}$out['forwarding'][$field]=$value['forwarding'][$field];}
        foreach(['access','spam']as $kind){$row=$value['configuration'][$kind]??null;if(!is_array($row)||!is_int($row['desired_revision']??null)||$row['desired_revision']<0||!is_int($row['applied_revision']??null)||$row['applied_revision']<0||$row['applied_revision']>$row['desired_revision']){throw new \DomainException('configuration_observation');}$out['configuration'][$kind]=['desired_revision'=>$row['desired_revision'],'applied_revision'=>$row['applied_revision']];}
        if(!is_array($value['domains']??null)||!array_is_list($value['domains'])||count($value['domains'])>10000){throw new \DomainException('DNS_domain_catalog');}$out['domains']=[];
        foreach($value['domains']as $host){if(!is_string($host)||$host!==AdminMailPolicy::domain($host)){throw new \DomainException('DNS_domain_catalog');}$out['domains'][]=$host;}
        return $out;
    }
    public function status(int $now):array{return self::validate($this->read('status.json'),$now);}
    public function dns(string $domain,int $now):array
    {
        if($domain!==AdminMailPolicy::domain($domain)||!in_array($domain,$this->status($now)['domains'],true)){throw new \DomainException('unknown_DNS_domain');}
        $value=$this->read('dns-'.hash('sha256',$domain).'.json',262144);
        if(($value['domain']??null)!==$domain||!is_int($value['observed_at']??null)||$value['observed_at']>$now+5||$value['observed_at']<$now-3600||!is_array($value['records']??null)||count($value['records'])>10){throw new \DomainException('DNS_observation');}
        $out=['domain'=>$domain,'observed_at'=>$value['observed_at'],'records'=>[],'DNS_changed'=>false];
        foreach($value['records']as $record){if(!is_array($record)||!in_array($record['type']??null,['MX','SPF','DKIM','DMARC','PTR'],true)||!in_array($record['state']??null,['consistent','resolver_disagreement','unavailable','selector_unknown'],true)||!is_array($record['values']??null)||count($record['values'])>100){throw new \DomainException('DNS_record');}
            $row=['type'=>$record['type'],'state'=>$record['state'],'values'=>[]];foreach($record['values']as $answer){if(!is_string($answer)||strlen($answer)>8192||preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/',$answer)){throw new \DomainException('DNS_record_value');}$row['values'][]=$answer;}$out['records'][]=$row;}
        return $out;
    }
}
