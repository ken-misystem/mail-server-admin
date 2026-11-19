<?php
declare(strict_types=1);

namespace MailServer\Management;

final class ScannerTabs
{
    public const TITLE = '危険添付・ウイルス対策';

    public static function navigation(string $selected): string
    {
        $links = [
            'status'=>['/mail-admin/feature-status/scanner','検査状況'],
            'settings'=>['/mail-admin/protection/scanner','設定'],
        ];
        $html = '<nav class="scanner-tabs" aria-label="危険添付・ウイルス対策">';
        foreach ($links as $key=>[$url,$label]) {
            $html .= '<a href="'.$url.'"'.($key===$selected?' aria-current="page"':'').'>'.$label.'</a>';
        }
        return $html.'</nav>';
    }

    public static function stylesheet(): string
    {
        return '.scanner-tabs{display:flex;gap:.45rem;border-bottom:1px solid #52636b;margin:0 0 1.25rem}.scanner-tabs a{padding:.7rem .9rem;text-decoration:none}.scanner-tabs a[aria-current=page]{border-bottom:3px solid #78d4fa;font-weight:700}.scanner-tabs a:focus-visible{outline:2px solid #78d4fa;outline-offset:-2px}';
    }

    public static function status(array $state): string
    {
        if ($state['state']==='unavailable') {
            return '<p role="alert">検査の観測結果を取得できません。</p>';
        }
        $rows = [
            '検査エンジン'=>$state['engine_present']?'ClamAV':'未導入',
            'ウイルス検査設定'=>$state['configured']?'有効':'無効',
            '検査プロセス'=>$state['daemon_running']?'稼働中':'停止中',
            '危険添付ルール'=>$state['attachment_rules_configured']?'有効':'未設定',
            '実検出の検証'=>$state['detection_verified']?'確認済み':'未確認',
        ];
        $html = '<dl>';
        foreach ($rows as $label=>$value) { $html .= '<dt>'.$label.'</dt><dd>'.$value.'</dd>'; }
        return $html.'</dl>';
    }
}
