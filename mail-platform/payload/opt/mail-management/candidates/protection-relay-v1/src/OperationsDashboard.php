<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Existing validated snapshots only. No command, database, HTTP or mail action. */
final class OperationsDashboard
{
    public static function attention(OperationsSnapshot $s, string $prefix = '/mail-admin/operations-status'): string
    {
        if (!$s->stale() && $s->complete && $s->findings === []) { return ''; }
        $out='<section class="dashboard-attention" role="alert" aria-label="確認が必要な項目"><h2>確認が必要な項目</h2>';
        if ($s->stale()) { $out.='<p>観測情報が古いため、現在の正常稼働を確認できません。</p>'; }
        if (!$s->complete) { $out.='<p>一部の情報を取得できていません。未確認を正常とは判定しません。</p>'; }
        if ($s->findings !== []) {
            $out.='<p>確認が必要な観測項目 '.count($s->findings).' 件。</p><ul>';
            foreach ($s->findings as $f) {
                $section=$f['check']==='mail_storage'?'system_storage':$f['check'];
                $label=match($f['check']){'units'=>'サービス','queue'=>'配送待ち','certificate'=>'サーバー証明書','client_certificates'=>'端末証明書','system_storage','mail_storage'=>'保存領域',default=>'観測項目'};
                $item=match($f['item']){'mail-junk-digest-general.service'=>'Junk日報','deferred'=>'配送保留','hold'=>'管理保留','corrupt'=>'破損区分',default=>$f['item']};
                $reason=match($f['reason']){'unit_failed','last_run_failed'=>'直近の実行が失敗','unit_not_active'=>'稼働していません','unit_not_loaded'=>'サービス定義を確認できません','timer_not_active'=>'定期実行が停止','queue_entries_observed'=>'対象メールあり',default=>'確認が必要です'};
                $out.='<li><a href="'.ConsoleController::escape($prefix.'#operations-'.$section).'">'.ConsoleController::escape($label.'：'.$item.' — '.$reason).'</a></li>';
            }
            $out.='</ul>';
        }
        return $out.'</section>';
    }

    public static function render(?OperationsSnapshot $s, string $notifications): string
    {
        $out=$s===null?'<section class="dashboard-attention" role="alert"><h2>観測情報を取得できません</h2><p>現在の状態は未確認です。稼働状況の詳細を確認してください。</p></section>':self::attention($s);
        // Notification failures must also be visible before all overview cards.
        $out.='<div class="dashboard-notifications">'.$notifications.'</div>';
        if ($s!==null) {
            $time=(new \DateTimeImmutable('@'.$s->observedAt))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y-m-d H:i:s');
            $out.='<p>観測：'.$time.' JST ／ 経過 '.$s->age.' 秒'.($s->stale()?'（古い情報）':'').'</p>';
        }
        $cards=[
            ['稼働状況','/mail-admin/operations-status',$s===null?'未確認':($s->stale()?'現在の状態は未確認':(!$s->complete?'取得失敗あり':($s->findings!==[]?'確認が必要な観測項目あり':'観測項目に指摘なし')))],
            ['配送待ち','/mail-admin/queue',self::queue($s)],
            ['保存領域','/mail-admin/operations-status#operations-system_storage',self::storage($s)],
            ['証明書','/mail-admin/operations-status#operations-client_certificates',self::certificate($s)],
            ['転送・設定反映','/mail-admin/feature-status/forwarding','公開世代・転送状態を確認'],
            ['迷惑メール対策','/mail-admin/feature-settings/spam','現在の判定設定を確認'],
            ['バックアップ','/mail-admin/feature-status/backup','最新の退避記録を確認'],
            ['不正アクセス','/mail-admin/access-blacklist','検出・自動ブロックを確認'],
        ];
        $out.='<div class="dashboard-grid">';
        foreach ($cards as [$title,$url,$value]) {
            $out.='<section class="dashboard-card"><h2>'.ConsoleController::escape($title).'</h2><p>'.ConsoleController::escape($value).'</p><a href="'.ConsoleController::escape($url).'">詳細を開く</a></section>';
        }
        return $out.'</div><p>保存済み観測情報の表示です。画面表示で収集・送信・設定変更は行いません。</p>';
    }
    private static function data(?OperationsSnapshot $s,string $name): ?array
    { return $s!==null && !$s->stale() && $s->checks[$name]['status']==='ok' ? $s->checks[$name]['data'] : null; }
    private static function queue(?OperationsSnapshot $s): string
    { $d=self::data($s,'queue');return $d===null?'現在の件数は未確認':'観測 '.$d['unique_observed_entries'].'件 ／ 配送保留 '.$d['by_queue']['deferred'].'件 ／ 管理保留 '.$d['by_queue']['hold'].'件'; }
    private static function storage(?OperationsSnapshot $s): string
    { $d=self::data($s,'mail_storage');return $d===null?'現在の容量は未確認':'メール領域の空き '.number_format($d['available_bytes']/1073741824,1).' GiB'; }
    private static function certificate(?OperationsSnapshot $s): string
    { $d=self::data($s,'client_certificates');return $d===null?'現在の期限は未確認':'メーラー接続TLS：残り '.number_format($d['seconds_remaining']['server_tls']/86400,1).'日 ／ '.($d['status']==='ok'?'監視上の指摘なし':'要確認'); }
    public static function stylesheet(): string
    {
        return '.dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:16px}.dashboard-card{background:#2d373c;border:1px solid #52636b;border-radius:8px;padding:16px;min-width:0}.dashboard-card h2{margin-top:0}.dashboard-card a{display:inline-block;min-height:44px;padding:8px 0}.dashboard-attention{padding:16px;margin:0 0 18px;border:2px solid #eabf47;border-radius:8px;background:#42391f;color:#fff2bd}.dashboard-attention h2{margin:0 0 8px}.dashboard-attention a{color:#fff2bd}.dashboard-attention li{margin:8px 0;overflow-wrap:anywhere}.dashboard-notifications{margin-bottom:18px}.dashboard-notifications fieldset{padding:12px}.dashboard-notifications h3,.dashboard-notifications p{margin:6px 0}';
    }
}
