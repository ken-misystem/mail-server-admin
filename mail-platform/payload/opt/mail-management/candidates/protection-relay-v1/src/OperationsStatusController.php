<?php
declare(strict_types=1);
namespace MailServer\Management;

require_once __DIR__.'/InternalAlertsStatus.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class OperationsStatusController
{
    public function __construct(private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf, private readonly OperationsStatusStore $store) {}

    public function show(Request $request): Response
    {
        if (!$request->isMethod('GET')) { return new Response('',405,['Allow'=>'GET','Cache-Control'=>'no-store']); }
        $actor=$this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser || !$actor->active || !$actor->systemAdmin
            || $request->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN) { return ConsoleController::page('アクセス拒否','',403); }
        if (!AdminFactorGate::permits($actor,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time())) {
            return ConsoleController::factorRequired($request,$this->csrf);
        }
        $nav='<p><a href="/mail-admin/">メール管理に戻る</a> ／ <a href="/mail-admin/operations-status">表示を更新</a></p>';
        $alerts=InternalAlertsStatus::read(time());
        try { $snapshot=$this->store->read(time()); }
        catch (\Throwable $error) {
            $message=$error instanceof \DomainException ? match($error->getMessage()) {
                'missing_snapshot'=>'稼働状況はまだ取得されていません。',
                'future_snapshot'=>'取得時刻が未来になっています。時刻の整合を確認してください。',
                'changed_snapshot'=>'更新中のため取得結果を確認できません。',
                'unsafe_snapshot','unreadable_snapshot'=>'取得結果を安全に読み取れません。',
                default=>'取得結果の形式を確認できません。',
            } : '取得結果を読み取れません。';
            return ConsoleController::page('稼働状況',$nav.'<p role="alert">'.$message.' 正常とは判定していません。</p>'
                .'<p>この画面は読取り専用です。設定変更や取得処理の起動は行いません。</p>'.$alerts,503);
        }
        return ConsoleController::page('稼働状況',$nav.self::render($snapshot).$alerts,200,
            '.operations-grid{display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr))}.operations-grid fieldset{padding:18px;min-width:0;margin:0}.operations-grid legend{font-weight:650;padding:0 6px}.operations-scroll{overflow-x:auto}.operations-meta{font-size:14px;color:#bac7cf}.operations-grid p{overflow-wrap:anywhere}');
    }

    public static function render(OperationsSnapshot $s): string
    {
        $fresh=$s->stale() ? '古い取得結果です。現在の状態とは判定できません。' : '直近の取得結果です。';
        $role=$s->stale() || !$s->complete || $s->findings!==[] ? 'alert' : 'status';
        $body='<p role="'.$role.'">取得時刻 '.self::date($s->observedAt).' ／ 経過 '.$s->age.' 秒。'.$fresh
            .($s->complete?'':' 一部の項目を取得できませんでした。').'</p>'
            .'<p class="operations-meta">読取り専用。表示の更新では収集処理を起動しません。配送全体の正常を保証する表示ではありません。障害通知の状態は下欄に表示します。自動停止は行いません。</p>'
            .'<div class="operations-grid">';
        foreach (['units'=>'サービス','system_storage'=>'保存領域','queue'=>'配送キュー','certificate'=>'証明書期限','client_certificates'=>'端末証明書監視'] as $name=>$title) {
            $body.='<fieldset><legend>'.$title.'</legend>';
            if ($name==='system_storage') {
                $a=$s->checks['system_storage']; $b=$s->checks['mail_storage'];
                $same=$a['status']==='ok' && $b['status']==='ok' && $a['data']['same_filesystem_key']===$b['data']['same_filesystem_key'];
                if ($same) { $body.='<p>システム領域とメール保存領域は同一のファイルシステムです。容量を合算しません。</p>'; }
                foreach (['system_storage'=>'システム領域','mail_storage'=>'メール保存領域'] as $key=>$label) {
                    $body.='<h2>'.$label.'</h2>';
                    if ($s->checks[$key]['status']!=='ok') { $body.=self::failure($s->checks[$key]); continue; }
                    $d=$s->checks[$key]['data'];
                    $body.='<p>空き '.self::gib($d['available_bytes']).' GiB ／ 総容量 '.self::gib($d['total_bytes']).' GiB<br>空きinode '.number_format($d['available_inodes']).'</p>';
                }
            } elseif ($s->checks[$name]['status']!=='ok') { $body.=self::failure($s->checks[$name]); }
            elseif ($name==='units') {
                $body.='<div class="operations-scroll"><table><thead><tr><th>サービス</th><th>観測状態</th><th>直近結果</th><th>終了値</th></tr></thead><tbody>';
                foreach ($s->checks[$name]['data'] as $unit=>$u) {
                    $label=match($unit){'mail-pop-general-dispatch.service'=>'POP取得ディスパッチャー',
                        'mail-pop-general-dispatch.timer'=>'POP定期タイマー',
                        'mail-junk-digest-general.service'=>'Junk日報（実行時のみ起動）',
                        'mail-junk-digest-general.timer'=>'Junk日報タイマー',
                        'mail-client-cert-health.service'=>'端末証明書・TLS監視',
                        'mail-client-cert-health.timer'=>'端末証明書監視タイマー',
                        'mail-legacy-smtp-auth.service'=>'互換SMTP認証',
                        'mail-quota-collect-v1.service'=>'メールボックス容量収集',
                        'mail-management-log-viewer.service'=>'ログ収集（定期実行）',
                        'mail-management-log-viewer.timer'=>'ログ収集タイマー',
                        'mail-domain-routing.service'=>'配送先照会',
                        'mail-domain-routing.socket'=>'配送先照会ソケット',
                        'mail-domain-routing-collect.service'=>'配送先DNS更新（定期実行）',
                        'mail-domain-routing-collect.timer'=>'配送先DNS更新タイマー',
                        'mail-management-alerts-v1.service'=>'内部障害通知（定期実行）',
                        'mail-management-alerts-v1.timer'=>'内部障害通知タイマー',
                        'mail-access-admin-v1.service'=>'不正アクセス管理',
                        'mail-access-admin-v1.socket'=>'不正アクセス管理ソケット',
                        'mail-send-limits-v1.service'=>'本人単位の送信量制限',
                        'mail-send-limits-v1.socket'=>'送信量制限ソケット',
                        'mail-feature-admin-v1.service'=>'送信停止・配送待ち管理',
                        'mail-feature-admin-v1.socket'=>'送信停止・配送待ち管理ソケット',
                        'mail-feature-access-v1.service'=>'追加のSMTP許否判定',
                        'mail-feature-access-v1.socket'=>'SMTP許否判定ソケット',
                        'mail-feature-config-v1.service'=>'転送・設定の反映',
                        'mail-feature-observer-v1.service'=>'管理情報・公開DNS収集',
                        'mail-feature-observer-v1.timer'=>'管理情報収集タイマー',
'mail-feature-rspamd-native-v1.service'=>'Rspamd設定照会',
'mail-feature-rspamd-native-v1.socket'=>'Rspamd設定照会ソケット',
'mail-protection-clamav-v1.service'=>'ウイルス検査',
'mail-protection-definitions-v1.service'=>'ウイルス定義更新',
'mail-protection-definitions-v1.timer'=>'ウイルス定義更新タイマー',
'mail-protection-publish-v1.service'=>'保護・上流設定の反映',
'mail-protection-publish-v1.timer'=>'保護・上流設定の反映タイマー',



                        default=>str_starts_with($unit,'mail-pop-source@')?'POP取得元 '.substr($unit,16,-8):substr($unit,0,-8)};
                    $active=match($u['active']){'active'=>'稼働中','inactive'=>'待機・停止','failed'=>'失敗','activating'=>'起動中','deactivating'=>'停止中','reloading'=>'再読込み中',default=>'未分類'};
                    $body.='<tr><td>'.ConsoleController::escape($label).'</td><td>'.$active.' / '.ConsoleController::escape(match($u['sub']){'running'=>'実行中','exited'=>'処理終了','dead'=>'停止','waiting'=>'待機中','listening'=>'接続待ち','failed'=>'失敗','start'=>'起動処理中','stop'=>'停止処理中',default=>'未分類'})
                        .($u['load']==='loaded'?'':'（未読込み）').'</td><td>'.ConsoleController::escape(match($u['result']){'success'=>'正常終了',''=>'対象外','exit-code'=>'非0終了','timeout'=>'時間切れ','signal'=>'シグナル終了','other'=>'未分類',default=>$u['result']})
                        .'</td><td>'.($u['main_exit']===null?'対象外':(string)$u['main_exit']).'</td></tr>';
                }
                $body.='</tbody></table></div><p class="operations-meta">POP取得の実行間の待機・停止と、単発処理の終了後の稼働状態は、一律に障害扱いしません。終了値は直近の値です。</p>';
            } elseif ($name==='queue') {
                $d=$s->checks[$name]['data']; $body.='<p>観測件数 '.$d['unique_observed_entries'].' 件 ／ 最古の経過 '.$d['oldest_age_seconds'].' 秒</p><dl>';
                foreach (['active'=>'配送処理中','deferred'=>'配送保留','hold'=>'管理保留','incoming'=>'受付後処理中','maildrop'=>'ローカル受付待ち','corrupt'=>'破損区分','other'=>'未分類'] as $q=>$label) {
                    $body.='<dt>'.$label.'</dt><dd>'.$d['by_queue'][$q].' 件</dd>';
                }
                $body.='</dl><p class="operations-meta">非原子的な列挙です。重複観測 '.$d['duplicate_observations'].' 件。保留件数は最終配送失敗数ではありません。宛先・本文・キューIDは表示しません。</p>';
            } elseif ($name==='client_certificates') {
                $d=$s->checks[$name]['data'];
                $body.='<p>監視時刻 '.self::date(strtotime($d['observed_utc'])).' ／ '.ConsoleController::escape($d['status']).'</p>';
                foreach(['server_tls'=>'メーラー接続用TLS','root_ca'=>'ルートCA','issuer_ca'=>'発行用CA','crl'=>'失効情報CRL'] as $key=>$label) {
                    $body.='<p>'.$label.'：残り '.number_format($d['seconds_remaining'][$key]/86400,1).' 日</p>';
                }
                foreach($d['finding_codes'] as $code) {
                    $message=match($code) {
                        'private_unit_not_active'=>'専用サービスが稼働していません。',
                        'gate_observation_missing'=>'ゲートの状態記録がありません。',
                        'gate_observation_stale'=>'ゲートの状態記録が古いか時刻が不整合です。',
                        'gate_threads_failed'=>'ゲートの処理が停止しています。',
                        'crl_expiring'=>'失効情報CRLの期限が近づいています。', 'crl_expired'=>'失効情報CRLが期限切れです。',
                        'tls_expiring'=>'メーラー接続用TLS証明書の期限が近づいています。', 'tls_expired'=>'メーラー接続用TLS証明書が期限切れです。',
                        'root_ca_expiring'=>'ルートCAの期限が近づいています。', 'root_ca_expired'=>'ルートCAが期限切れです。',
                        'issuer_ca_expiring'=>'発行用CAの期限が近づいています。', 'issuer_ca_expired'=>'発行用CAが期限切れです。',
                        'tls_reload_unverified'=>'更新されたTLS証明書のゲート反映を確認できません。',
                        'tls_source_invalid'=>'更新元のTLS証明書または秘密鍵を検証できません。',
                        'tls_refresh_failed'=>'TLS証明書の反映処理が失敗しました。',
                        'health_snapshot_stale'=>'証明書監視の結果が更新されていません。',
                        default=>'証明書監視の収集処理が失敗しました。',
                    };
                    $body.='<p role="alert">'.ConsoleController::escape($message).'</p>';
                }
            } else {
                $d=$s->checks[$name]['data'];
                $body.='<p>ローカル証明書の期限 '.self::date(strtotime($d['expires_utc'])).'<br>観測時点の残り '.number_format($d['seconds_remaining']/86400,1).' 日</p>'
                    .($d['expired']?'<p role="alert">期限切れです。</p>':'')
                    .'<p class="operations-meta">ディスク上の証明書の値です。外部に提供中の証明書や更新動作を再試験した結果ではありません。</p>';
            }
            $body.='</fieldset>';
        }
        if ($s->findings!==[]) { $body.='<p role="alert">確認が必要な観測項目 '.count($s->findings).' 件。各枠の状態を確認してください。</p>'; }
        return $body.'</div>';
    }
    private static function failure(array $check): string
    {
        $reason=match($check['failure']['reason']){
            'permission'=>'読取り権限不足','missing'=>'読取り対象なし','unsupported'=>'未対応の形式またはオプション',
            'native_exit'=>'確認コマンドが非0終了','stderr'=>'診断出力があるため結果未確認','timeout'=>'確認処理の時間切れ',
            'output_bound'=>'読取り上限超過','shape'=>'結果形式の不一致','io'=>'読取りエラー',default=>'確認処理の内部エラー',
        };
        $exit=$check['native']===null?'不明':(string)$check['native']['exit'];
        return '<p role="alert">取得失敗：'.$reason.'。正常とは判定していません。</p><p class="operations-meta">実終了値 '.$exit
            .' ／ 確認コード行 '.($check['failure']['source_line']??'不明').'</p>';
    }
    private static function date(int $epoch): string { return (new \DateTimeImmutable('@'.$epoch))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y-m-d H:i:s').' JST'; }
    private static function gib(int $bytes): string { return number_format($bytes/1073741824,1); }
}
