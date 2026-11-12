<?php
declare(strict_types=1);
namespace MailServer\Pop;
use PDO;

/** Pilot worker metadata only; no secrets, raw diagnostics or message identifiers. */
final class PopRunHistory
{
    public const OUTCOMES=['success','no_mail','limit_reached','warning','failed'];
    public const PHASES=['preconditions','policy','binding','private_config','native_fetch','result_update','complete'];
    public const DETAILS=['none','smtp_observed','auth_failed','tls_failed','connection_failed','timeout',
        'protocol_failed','native_failed','preflight_failed','source_not_allowed','history_unverified',
        'result_unverified','interrupted','smtp_reject_temporary','smtp_reject_permanent','smtp_reject_mixed','smtp_connect_failed','smtp_failure_unclassified','smtp_legacy_unverified','diagnostic_incomplete','retry_wait','retry_state_changed','retry_reserved','retry_blocked','socket_unclassified','socket_connect_timeout','socket_server_timeout','socket_refused','socket_reset','socket_eof','network_unreachable','host_unreachable','dns_temporary','uidl_write_failed','smtp_timeout'];

    public static function start(PDO $db):string
    {
        // Invoked under the existing worker lock, before policy/DNS/decryption.
        // No history write may enable a source or change its current reservation.
        if($db->inTransaction())throw new \RuntimeException();
        $db->beginTransaction();
        try {
            $q=$db->query('SELECT id FROM mail_pop_accounts WHERE id=1');
            if((string)$q->fetchColumn()!=='1')throw new \RuntimeException();
            $db->exec("INSERT INTO mail_pop_run_history(account_id,started_at,outcome,phase,detail_code) VALUES(1,UTC_TIMESTAMP(6),'running','preconditions','none')");
            $id=PopSourcePolicy::accountId($db->lastInsertId());
            $keep=$db->query('SELECT id FROM mail_pop_run_history WHERE account_id=1 ORDER BY id DESC LIMIT 1 OFFSET 9')->fetchColumn();
            if($keep!==false){
                PopSourcePolicy::accountId((string)$keep);
                $db->prepare('DELETE FROM mail_pop_run_history WHERE account_id=1 AND id<?')->execute([(string)$keep]);
            }
            if(!$db->commit())throw new \RuntimeException();
            return $id;
        }catch(\Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
    }

    public static function finish(PDO $db,array $v):void
    {
        if(array_keys($v)!==['run_id','outcome','phase','detail_code','fetched_count','native_exit'])throw new \RuntimeException();
        PopSourcePolicy::accountId($v['run_id']);
        foreach(['outcome'=>self::OUTCOMES,'phase'=>self::PHASES,'detail_code'=>self::DETAILS] as $k=>$allowed){
            if(!is_string($v[$k]) || !in_array($v[$k],$allowed,true))throw new \RuntimeException();
        }
        foreach(['fetched_count'=>50,'native_exit'=>255] as $k=>$max){
            if($v[$k]!==null && (!is_int($v[$k]) || $v[$k]<0 || $v[$k]>$max))throw new \RuntimeException();
        }
        $q=$db->prepare("UPDATE mail_pop_run_history SET finished_at=UTC_TIMESTAMP(6),outcome=?,phase=?,detail_code=?,fetched_count=?,native_exit=? WHERE id=? AND account_id=1 AND outcome='running'");
        $q->execute([$v['outcome'],$v['phase'],$v['detail_code'],$v['fetched_count'],$v['native_exit'],$v['run_id']]);
        if($q->rowCount()!==1)throw new \RuntimeException();
    }
}
