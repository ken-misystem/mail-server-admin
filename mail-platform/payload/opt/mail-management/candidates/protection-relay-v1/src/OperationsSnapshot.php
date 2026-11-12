<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Closed aggregate schema. No command, configuration, address or raw error rendering. */
final class OperationsSnapshot
{
    public const SOURCE_SHA = '353ea8a1c444da78fb25580621feaf027ba3d57289a1dae23d1419d11098f219';
    public const MAX_AGE = 180; // Display freshness, not a notification threshold.
    public const UNITS = ['postfix.service','dovecot.service','mariadb.service','rspamd.service',
        'redis-server.service','nginx.service','php8.4-fpm.service','fail2ban.service',
        'postsrsd.service','ufw.service','mail-pop-general-dispatch.service','mail-junk-digest-general.service',
        'mail-pop-general-dispatch.timer','mail-junk-digest-general.timer','mail-client-cert-network.service','mail-client-cert-milter.service','mail-client-cert-coordination.service','mail-client-cert-postfix-backend.service','mail-client-cert-dovecot-backend.service','mail-client-cert-issuer.service','mail-client-cert-lifecycle.service','mail-client-cert-verifier.service','mail-client-cert-gate.service','mail-client-cert-owner.service','mail-client-cert-gate.socket','mail-client-cert-health.service','mail-client-cert-health.timer','mail-legacy-smtp-auth.service','mail-quota-collect-v1.service','mail-management-log-viewer.service','mail-management-log-viewer.timer','mail-domain-routing.service','mail-domain-routing.socket','mail-domain-routing-collect.service','mail-domain-routing-collect.timer','mail-management-alerts-v1.service','mail-management-alerts-v1.timer','mail-access-admin-v1.service','mail-access-admin-v1.socket','mail-send-limits-v1.service','mail-send-limits-v1.socket','mail-feature-admin-v1.service','mail-feature-admin-v1.socket','mail-feature-access-v1.service','mail-feature-access-v1.socket','mail-feature-config-v1.service','mail-feature-observer-v1.service','mail-feature-observer-v1.timer','mail-feature-rspamd-native-v1.service','mail-feature-rspamd-native-v1.socket','mail-protection-clamav-v1.service','mail-protection-definitions-v1.service','mail-protection-definitions-v1.timer','mail-protection-publish-v1.service','mail-protection-publish-v1.timer'];
    public const REASONS = ['permission','missing','unsupported','native_exit','stderr','timeout','output_bound','shape','io','internal'];
    public const UNIT_VALUES = [
        'load'=>['loaded','not-found','error','bad-setting','masked','stub','merged','other'],
        'active'=>['active','inactive','failed','activating','deactivating','reloading','maintenance','refreshing','other'],
        'sub'=>['running','exited','dead','waiting','failed','start','stop','auto-restart','listening','elapsed','other'],
        'result'=>['','success','exit-code','signal','core-dump','timeout','resources','start-limit-hit','watchdog','protocol','condition','assert','other'],
        'enabled'=>['','enabled','enabled-runtime','disabled','static','indirect','alias','masked','masked-runtime','generated','transient','linked','linked-runtime','not-found','bad','other'],
    ];

    private function __construct(public readonly int $observedAt, public readonly int $age,
        public readonly array $checks, public readonly array $findings, public readonly bool $complete) {}

    public function stale(): bool { return $this->age > self::MAX_AGE; }

    public static function fromJson(string $raw, int $now): self
    {
        self::need(strlen($raw) <= 65536);
        try { $v = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); }
        catch (\Throwable) { throw new \DomainException('invalid_snapshot'); }
        // Collector emits compact ASCII JSON. Canonical equality rejects duplicate keys too.
        self::need(is_array($v) && json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) === rtrim($raw, "\r\n"));
        self::keys($v, 'operation source_sha256 observed_utc status checks evaluation server_write service_action database_query manual_pop mail_content_read uidl_read raw_output_saved atomic_snapshot');
        self::need($v['operation']==='management-operations-read-v1' && $v['source_sha256']===self::SOURCE_SHA);
        $observed = self::timestamp($v['observed_utc']);
        if ($observed > $now) { throw new \DomainException('future_snapshot'); }
        foreach (['server_write','service_action','database_query','manual_pop','mail_content_read','uidl_read','raw_output_saved','atomic_snapshot'] as $key) { self::need($v[$key]===false); }
        self::keys($v['checks'], 'units queue system_storage mail_storage certificate client_certificates');
        $incomplete=[]; $findings=[];
        foreach ($v['checks'] as $name=>$check) {
            self::keys($check,'status data native failure'); self::need(in_array($check['status'],['ok','fail'],true));
            $native=$check['native'];
            if ($native!==null) {
                self::need(in_array($name,['units','queue','certificate'],true));
                self::keys($native,'exit stdout_bytes stderr_bytes timed_out bounded reason');
                self::integer($native['exit'],-128,4294967295); self::integer($native['stdout_bytes'],0,['units'=>65536,'queue'=>8388608,'certificate'=>4096][$name]);
                self::integer($native['stderr_bytes'],0,8192); self::need(is_bool($native['timed_out']) && is_bool($native['bounded']));
                self::need($native['reason']===null || in_array($native['reason'],self::REASONS,true));
                if ($native['reason']===null) { self::need($native['exit']===0 && $native['stderr_bytes']===0 && !$native['timed_out'] && $native['bounded']); }
            }
            if ($check['status']==='fail') {
                $incomplete[]=$name; self::need($check['data']===null); $f=$check['failure'];
                self::keys($f,'reason error_class errno source_line'); self::need(in_array($f['reason'],self::REASONS,true));
                self::need(in_array($f['error_class'],['Guard','OSError','PermissionError','FileNotFoundError','ValueError','UnicodeDecodeError','JSONDecodeError','TypeError','other'],true));
                if ($f['errno']!==null) { self::integer($f['errno'],0,4095); }
                if ($f['source_line']!==null) { self::integer($f['source_line'],1,10000); }
                continue;
            }
            self::need($check['failure']===null && ($native===null || $native['reason']===null));
            self::need(($native!==null) === in_array($name,['units','queue','certificate'],true));
            $data=$check['data'];
            if ($name==='units') {
                self::need(is_array($data) && count($data)<=count(self::UNITS)+200);
                foreach (self::UNITS as $required) { self::need(array_key_exists($required,$data)); }
                foreach (array_keys($data) as $unit) { self::need(in_array($unit,self::UNITS,true) || self::sourceUnit($unit)); }
                foreach ($data as $unit=>$u) {
                    self::keys($u,'load active sub result main_exit enabled');
                    foreach (self::UNIT_VALUES as $key=>$values) { self::need(in_array($u[$key],$values,true)); }
                    if ($u['main_exit']!==null) { self::integer($u['main_exit'],0,4294967295); }
                    $reason = $u['active']==='failed' ? 'unit_failed' : ($u['load']!=='loaded' ? 'unit_not_loaded' :
                        (str_ends_with($unit,'.timer') && $u['active']!=='active' ? 'timer_not_active' :
                        (!str_ends_with($unit,'.timer') && (!in_array($u['result'],['','success'],true) || !in_array($u['main_exit'],[null,0],true)) ? 'last_run_failed' :
                        (!in_array($unit,['mail-pop-general-dispatch.service','mail-junk-digest-general.service','mail-client-cert-health.service','mail-management-log-viewer.service','mail-domain-routing-collect.service','mail-management-alerts-v1.service','mail-access-admin-v1.service','mail-feature-observer-v1.service','mail-protection-definitions-v1.service','mail-protection-publish-v1.service'],true) && !self::sourceUnit($unit) && !str_ends_with($unit,'.timer') && $u['active']!=='active' ? 'unit_not_active' : null))));
                    if ($reason!==null) { $findings[]=['check'=>'units','item'=>$unit,'reason'=>$reason]; }
                }
            } elseif ($name==='queue') {
                self::keys($data,'records unique_observed_entries duplicate_observations by_queue total_message_bytes oldest_age_seconds future_arrival_observations atomic_snapshot addresses_output queue_ids_output');
                self::keys($data['by_queue'],'active deferred hold incoming maildrop corrupt other');
                foreach (['records','unique_observed_entries','duplicate_observations','future_arrival_observations'] as $key) { self::integer($data[$key],0,20000); }
                foreach ($data['by_queue'] as $n) { self::integer($n,0,20000); }
                self::integer($data['total_message_bytes']); self::integer($data['oldest_age_seconds'],0,$observed);
                self::need($data['records']===$data['unique_observed_entries']+$data['duplicate_observations'] && array_sum($data['by_queue'])===$data['unique_observed_entries']);
                self::need($data['future_arrival_observations']<=$data['unique_observed_entries']);
                foreach (['atomic_snapshot','addresses_output','queue_ids_output'] as $key) { self::need($data[$key]===false); }
                foreach (['deferred','hold','corrupt','other'] as $q) { if ($data['by_queue'][$q]>0) { $findings[]=['check'=>'queue','item'=>$q,'reason'=>'queue_entries_observed']; } }
            } elseif ($name==='client_certificates') {
                self::keys($data,'observed_utc status seconds_remaining finding_codes renewal_action');
                self::need(self::timestamp($data['observed_utc'])<=$observed && in_array($data['status'],['ok','warning','failed'],true));
                self::keys($data['seconds_remaining'],'server_tls root_ca issuer_ca crl');
                foreach($data['seconds_remaining'] as $seconds) { self::integer($seconds,-1099511627776,1099511627776); }
                self::need(is_array($data['finding_codes']) && array_is_list($data['finding_codes']) && count($data['finding_codes'])<=17 && count(array_unique($data['finding_codes']))===count($data['finding_codes']));
                $allowed=['private_unit_not_active','gate_observation_missing','gate_observation_stale','gate_threads_failed','crl_expiring','crl_expired','tls_expiring','tls_expired','root_ca_expiring','root_ca_expired','issuer_ca_expiring','issuer_ca_expired','tls_reload_unverified','tls_source_invalid','tls_refresh_failed','health_collection_failed','health_snapshot_stale'];
                foreach($data['finding_codes'] as $code) { self::need(in_array($code,$allowed,true)); $findings[]=['check'=>'client_certificates','item'=>'certificate_gate','reason'=>$code]; }
                self::need(($data['status']==='ok')===($data['finding_codes']===[]) && in_array($data['renewal_action'],['none','prepared','gate_restarted','refresh_refused','restart_unverified'],true));
            } elseif ($name==='certificate') {
                self::keys($data,'expires_utc seconds_remaining expired served_certificate_verified');
                $expiry=self::timestamp($data['expires_utc']); self::integer($data['seconds_remaining'],-1099511627776,1099511627776);
                self::need($data['seconds_remaining']===$expiry-$observed && $data['expired']===($expiry<=$observed) && $data['served_certificate_verified']===false);
                if ($data['expired']) { $findings[]=['check'=>'certificate','item'=>'local_certificate','reason'=>'expired']; }
            } else {
                self::keys($data,'total_bytes available_bytes available_inodes same_filesystem_key');
                foreach ($data as $n) { self::integer($n); }
                self::need($data['available_bytes']<=$data['total_bytes']);
                if ($data['available_bytes']===0 || $data['available_inodes']===0) { $findings[]=['check'=>$name,'item'=>'filesystem','reason'=>'no_available_capacity']; }
            }
        }
        // Match collector evaluation order independently of JSON object key ordering.
        $ordered=[];
        foreach (['units','queue','system_storage','mail_storage','certificate','client_certificates'] as $key) {
            if ($key==='units') {
                $unitOrder=[...self::UNITS,...array_values(array_diff(array_keys($v['checks']['units']['data'] ?? []),self::UNITS))];
                $extra=array_slice($unitOrder,count(self::UNITS)); sort($extra,SORT_STRING); $unitOrder=[...self::UNITS,...$extra];
                foreach ($unitOrder as $unit) { foreach ($findings as $f) { if ($f['check']==='units' && $f['item']===$unit) { $ordered[]=$f; } } }
                continue;
            }
            foreach ($findings as $f) { if ($f['check']===$key) { $ordered[]=$f; } }
        }
        $incomplete=array_values(array_filter(['units','queue','system_storage','mail_storage','certificate','client_certificates'],static fn(string $key): bool=>in_array($key,$incomplete,true)));
        $complete=$incomplete===[];
        self::need($v['status']===($complete?'ok':'fail'));
        $expected=['collection'=>$complete?'complete':'incomplete','incomplete_checks'=>$incomplete,
            'findings'=>$ordered,'thresholds_configured'=>false,'notification_configured'=>false,
            'delivery_health_proven'=>false,'deployment_authorized'=>false];
        self::need(self::canonical($v['evaluation'])===self::canonical($expected));
        return new self($observed,$now-$observed,$v['checks'],$ordered,$complete);
    }

    private static function canonical(mixed $v): mixed
    {
        if (!is_array($v)) { return $v; }
        if (!array_is_list($v)) { ksort($v,SORT_STRING); }
        foreach ($v as &$item) { $item=self::canonical($item); }
        return $v;
    }
    private static function sourceUnit(string $name): bool
    {
        if (!preg_match('/\Amail-pop-source@([1-9][0-9]{0,19})\.service\z/',$name,$m)) { return false; }
        return strlen($m[1])<20 || strcmp($m[1],'18446744073709551615')<=0;
    }
    private static function keys(mixed $value,string $names): void
    {
        self::need(is_array($value)); $a=array_keys($value); $b=explode(' ',$names); sort($a); sort($b); self::need($a===$b);
    }
    private static function need(bool $value): void { if (!$value) { throw new \DomainException('invalid_snapshot'); } }
    private static function integer(mixed $v,int $low=0,int $high=PHP_INT_MAX): void { self::need(is_int($v) && $v>=$low && $v<=$high); }
    private static function timestamp(mixed $value): int
    {
        self::need(is_string($value) && (bool)preg_match('/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00\z/',$value));
        $date=\DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:sP',$value);
        self::need($date!==false && $date->format('Y-m-d\TH:i:sP')===$value); return $date->getTimestamp();
    }
}
