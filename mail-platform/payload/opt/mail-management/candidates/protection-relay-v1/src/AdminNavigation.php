<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Static navigation only. Never queries storage, changes settings or starts collection. */
final class AdminNavigation
{
    public static function groups(): array
    {
        return [
            '利用者・ドメイン'=>[
                ['CSV一括登録','/mail-admin/bulk',['CSV一括登録','CSV登録の事前確認','CSV登録の結果']],
                ['利用者・利用上限','/mail-admin/manage?section=users',['利用者・利用上限']],
                ['ドメイン','/mail-admin/manage?section=domains',['ドメイン管理']],
                ['ドメイン別名','/mail-admin/domain-aliases',['ドメイン別名管理']],
                ['受信エイリアス','/mail-admin/manage?section=aliases',['受信エイリアス管理']],
            ],
            '配送・SMTP送信'=>[
                ['転送・設定反映の状態','/mail-admin/feature-status/forwarding',['転送・設定反映の状態']],
                ['上流SMTPの状態','/mail-admin/feature-status/upstream',['上流SMTPの状態']],
                ['上流SMTP設定','/mail-admin/protection/upstream',['上流SMTP設定']],
                ['転送設定','/mail-admin/scoped/forwards',['委任範囲：転送','転送設定','転送設定の保存結果']],
                ['本人別送信状況・緊急停止','/mail-admin/send-status',['本人別送信状況・緊急停止','送信停止の操作結果']],
                ['配送待ちメール','/mail-admin/queue',['配送待ちメール','配送待ちの操作結果']],
                ['配送先の切替え（移行用）','/mail-admin/domain-delivery',['ドメインの配送切替']],
                ['SMTP送信アカウント','/mail-admin/legacy-smtp',['旧XMail互換 SMTP送信','SMTP互換送信']],
            ],
            '容量・稼働状況'=>[
                ['バックアップの記録','/mail-admin/feature-status/backup',['バックアップの記録']],
                ['公開DNS・送信ドメイン','/mail-admin/feature-status/dns',['公開DNS・送信ドメイン']],
                ['メールボックス容量','/mail-admin/mailbox-quota',['メールボックス容量制限']],
                ['稼働状況','/mail-admin/operations-status',['稼働状況','メールサーバー稼働状況']],
                ['各種ログ','/mail-admin/logs',['各種ログ']],
            ],
            'セキュリティ'=>[
                ['許否リスト','/mail-admin/feature-settings/access',['許否リスト']],
                ['迷惑メール判定設定','/mail-admin/feature-settings/spam',['迷惑メール判定設定']],
                ['認証失敗の推移','/mail-admin/feature-status/authentication',['認証失敗の推移']],
                ['危険添付・ウイルス検査','/mail-admin/feature-status/scanner',['危険添付・ウイルス検査']],
                ['危険添付・ウイルス設定','/mail-admin/protection/scanner',['危険添付・ウイルス設定']],
                ['送信量制限','/mail-admin/send-limits',['本人単位の送信量制限']],
                ['不正アクセス・自動ブロック','/mail-admin/access-blacklist',['不正アクセス・自動ブロック']],
            ],
            '管理者・監査'=>[
                ['ソフトウェア更新','/mail-admin/updates',['ソフトウェア更新']],
                ['ドメイン別の管理委任','/mail-admin/delegation',['ドメイン別の管理委任','管理委任の保存結果']],
                ['委任された管理','/mail-admin/scoped',['委任された管理']],
                ['管理者','/mail-admin/manage?section=admins',['管理者一覧']],
                ['管理者のパスキー','/mail-admin/#admin-passkey',[]],
                ['管理操作履歴','/mail-admin/audit',['管理操作履歴']],
            ],
        ];
    }

    public static function render(string $title, ?array $groups = null): string
    {
        $out='<aside class="admin-navigation"><nav aria-label="管理メニュー"><a class="admin-nav-home" href="/mail-admin/">メール管理</a>';
        foreach ($groups ?? self::groups() as $name=>$items) {
            $open=$title==='メール管理'||($title==='メール管理設定'&&in_array($name,['利用者・ドメイン','管理者・監査'],true));
            foreach ($items as $item) { if (in_array($title,$item[2],true)) { $open=true; } }
            $out.='<details'.($open?' open':'').'><summary>'.ConsoleController::escape($name).'</summary><ul>';
            foreach ($items as [$label,$href,$titles]) {
                $out.='<li><a href="'.ConsoleController::escape($href).'"'.(in_array($title,$titles,true)?' aria-current="page"':'').'>'
                    .ConsoleController::escape($label).'</a></li>';
            }
            $out.='</ul></details>';
        }
        return $out.'</nav></aside>';
    }

    public static function stylesheet(): string
    {
        return <<<'CSS'
.admin-shell{display:grid;grid-template-columns:250px minmax(0,1fr);max-width:1440px;margin:auto;min-height:100vh}.admin-shell>main{width:100%;min-width:0;margin:0}.admin-navigation{background:#253036;border-right:1px solid #52636b;padding:24px 14px}.admin-navigation nav{position:sticky;top:16px}.admin-navigation a{display:block;color:#d3dfe7;text-decoration:none;border-radius:6px;padding:8px 10px;overflow-wrap:anywhere}.admin-nav-home{font-weight:700;margin-bottom:14px}.admin-navigation details{border-top:1px solid #52636b;padding:8px 0}.admin-navigation summary{cursor:pointer;padding:8px 4px;color:#e6edf0;font-weight:650}.admin-navigation ul{list-style:none;margin:4px 0 0;padding:0 0 0 12px}.admin-navigation a:hover,.admin-navigation a[aria-current=page]{background:#33454e;color:#78d4fa}.admin-navigation a[aria-current=page]{border-left:3px solid #78d4fa}.admin-navigation a:focus-visible,.admin-navigation summary:focus-visible{outline:3px solid #78d4fa;outline-offset:2px}main input[type=checkbox]{width:auto;align-self:flex-start}@media(max-width:800px){.admin-shell{grid-template-columns:minmax(0,1fr)}.admin-navigation{border-right:0;border-bottom:1px solid #52636b;padding:12px}.admin-navigation nav{position:static}.admin-navigation details{padding:2px 0}.admin-navigation ul{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}}
CSS;
    }
}
