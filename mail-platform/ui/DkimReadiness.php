<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Public DNS checklist only; no private-key access or shell execution. */
final class DkimReadiness
{
    private const FILE='/var/lib/mail-platform-dkim/status.json';
    public static function render(?array $fixture=null, ?int $now=null): string
    {
        $now ??= time();
        try {
            if ($fixture === null) {
                $s=@lstat(self::FILE);
                if (!is_array($s) || ($s['mode']&0170000)!==0100000 || $s['uid']!==0 || ($s['mode']&0022)!==0 || $s['size']>131072) {
                    throw new \RuntimeException('status_unavailable');
                }
                $fixture=json_decode((string)file_get_contents(self::FILE),true,16,JSON_THROW_ON_ERROR);
                $failure=@lstat(dirname(self::FILE).'/refresh-failure.json');
                if (is_array($failure)) {
                    if (($failure['mode']&0170000)!==0100000 || $failure['uid']!==0 || ($failure['mode']&0022)!==0 || $failure['size']>4096) {
                        throw new \RuntimeException('refresh_status_trust');
                    }
                    $error=json_decode((string)file_get_contents(dirname(self::FILE).'/refresh-failure.json'),true,8,JSON_THROW_ON_ERROR);
                    if (!is_int($error['observed_at']??null) || $error['observed_at']>=($fixture['observed_at']??0)) {
                        throw new \RuntimeException('refresh_failed');
                    }
                }
            }
            if (($fixture['format']??null)!==1 || !is_int($fixture['observed_at']??null)
                || !is_array($fixture['entries']??null) || count($fixture['entries'])>32
                || !is_array($fixture['warnings']??null)) { throw new \RuntimeException('status_shape'); }
            $stale=$fixture['observed_at']>$now+60 || $now-$fixture['observed_at']>1800;
            $labels=[
                'ready'=>'鍵と公開DNSが一致',
                'dns_missing'=>'DNSへのTXT登録が必要',
                'dns_mismatch'=>'DNSの公開鍵が一致しません',
                'dns_conflict'=>'DNSの重複・形式を確認してください',
                'dns_propagating'=>'DNSの反映待ち・応答不一致',
                'dns_unavailable'=>'DNSを確認できません',
                'dns_policy_review'=>'DNSの署名方式・用途制限の確認が必要',
                'policy_review'=>'署名対象・公開鍵照合設定の確認が必要',
                'activation_pending'=>'DNS一致・鍵の有効化待ち',
                'key_missing'=>'鍵の補完が必要',
                'key_review'=>'既存鍵の形式・権限の確認が必要',
            ];
            $attention=$stale || $fixture['warnings']!==[] || $fixture['entries']===[];
            foreach ($fixture['entries'] as $row) {
                if (!is_array($row) || !isset($labels[$row['state']??''])) { throw new \RuntimeException('entry_shape'); }
                $attention=$attention || $row['state']!=='ready';
            }
            $e=static fn(mixed $v):string=>htmlspecialchars(is_string($v)?$v:'',ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
            $html='<section aria-labelledby="dkim-checklist-title"><h2 id="dkim-checklist-title">メール署名・DNSの確認リスト</h2>';
            $html.=$attention?'<p role="alert"><strong>手動対応または確認が必要です。</strong>導入・更新の完了とは別に、以下の項目を確認してください。</p>':'<p role="status">すべてのDKIM確認項目が完了しています。</p>';
            if ($stale) { $html.='<p role="alert">確認結果が古い、または時刻が不正です。現在の正常状態を保証する表示ではありません。</p>'; }
            if ($fixture['warnings']!==[]) {
                $html.='<p role="alert">署名ドメインの選択、独自設定、重複設定、または復旧後の確認が残っています。既存設定を確認してから再実行してください。</p><ul>';
                $actions=[
                    'public_key_policy_requires_review'=>'サーバー管理者がDKIM設定を確認してください。check_pubkey=true、allow_pubkey_mismatch=false、sign_inbound=falseをそれぞれ1件に揃え、構文・署名対象を確認します。既存の独自設定は自動で置き換えません。',
                    'notification_domain_ESLD_requires_review'=>'サーバー通知に使うホスト名と署名ドメインの選択を確認してください。公開サフィックスを推測して鍵を有効化する処理は行いません。',
                    'duplicate_boolean_values'=>'重複設定が残っています。下記dkim-applyで一致する値の重複だけを整理できます。',
                    'manual_review:conflicting_boolean_values'=>'同じDKIM設定にtrueとfalseが混在しています。管理者が意図した値を確認し、1件に整理してください。',
                    'manual_review:custom_signing_requires_review'=>'独自のmap・Redis等の署名設定です。独自設定の鍵とDNSを管理者が確認してください。',
                    'manual_review:signing_disabled'=>'DKIM署名が無効です。無効化が意図した設定かを確認してください。',
                    'update_rolled_back_keys_retained'=>'更新を復旧しました。生成した鍵は保管済みです。設定を確認し、下記の読取り照合から続行してください。',
                ];
                foreach (array_slice($fixture['warnings'],0,16) as $warning) { $html.='<li>'.$e($actions[is_string($warning)?$warning:'']??'サーバー管理者による確認が必要です。').' <code>'.$e($warning).'</code></li>'; }
                $html.='</ul>';
            }
            foreach ($fixture['entries'] as $row) {
                $html.='<details'.($row['state']!=='ready'?' open':'').'><summary>'.$e($row['domain']??'').' — '.$e($labels[$row['state']]).'</summary>';
                $html.='<p>DNS名：<code style="overflow-wrap:anywhere">'.$e($row['dns_name']??'').'</code> ／ 種別：TXT</p>';
                if (is_string($row['txt']??null)) {
                    $html.='<label>DNS管理画面へ登録する値（公開鍵）<textarea readonly rows="4" style="width:100%;box-sizing:border-box;overflow-wrap:anywhere">'.$e($row['txt']).'</textarea></label>';
                }
                $html.='</details>';
            }
            $html.='<p>DNSの登録は、ご契約のDNS管理画面で行ってください。既存TXTを確認せず上書きしないでください。秘密鍵をDNSへ登録する操作はありません。</p>';
            $html.='<p>登録後は稼働中の更新確認timerによる確認を待つか、サーバー管理者が次を実行してください。初期公開前などtimerが停止中の場合は手動で確認します。DNS照合ができるまで新しい鍵は署名に使用しません。</p>';
            $html.='<pre style="white-space:pre-wrap;overflow-wrap:anywhere">sudo python3 -I -S -B /usr/local/lib/mail-platform-update/entry.py dkim-check</pre>';
            $html.='<p>「鍵の有効化待ち」の場合は、管理者が次を実行してください。DNSへの書込みやメール送信は行いません。</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">sudo python3 -I -S -B /usr/local/lib/mail-platform-update/entry.py dkim-apply</pre>';
            $html.='<p>この確認はDKIM用です。SPF・DMARC・MX・逆引き・実際の受信先での判定まで正常とする表示ではありません。</p></section>';
            return $html;
        } catch (\Throwable) {
            return '<section><h2>メール署名・DNSの確認リスト</h2><p role="alert">DKIMの確認結果を取得できません。正常扱いにはしていません。サーバー管理者へ再確認を依頼してください。</p></section>';
        }
    }
}
