<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Compact table; edit forms are disclosed individually, without JavaScript. */
final class QuotaListView
{
    private static function e(mixed $v): string { return ConsoleController::escape((string)$v); }

    public static function render(array $data, QuotaListFilter $filter, string $token): string
    {
        $p = $data['pagination'];
        $h = '<form method="get" action="/mail-admin/mailbox-quota" role="search"><fieldset><legend>利用者を絞り込む</legend>';
        $h .= '<label>ドメイン（空欄はすべて）<input type="text" name="domain" list="quota-domains" maxlength="253" value="'.self::e($filter->domain).'" placeholder="example.jp"></label><datalist id="quota-domains">';
        foreach ($data['domains'] as $domain) { $h .= '<option value="'.self::e($domain['name']).'"></option>'; }
        $h .= '</datalist>';
        if ($data['domains_truncated']) { $h .= '<p>候補は先頭200ドメインです。候補外のドメインも直接入力できます。</p>'; }
        $h .= '<label>メールアドレス（前方一致）<input type="search" name="q" maxlength="128" value="'.self::e($filter->q).'" placeholder="ユーザー名またはメールアドレス"></label>';
        $h .= '<label>1ページの件数<select name="per_page">';
        foreach ([25,50,100] as $size) { $h .= '<option value="'.$size.'"'.($size === $filter->perPage ? ' selected' : '').'>'.$size.'件</option>'; }
        $h .= '</select></label><button type="submit">検索する</button> <a href="/mail-admin/mailbox-quota">絞り込みを解除</a></fieldset></form>';
        $h .= '<p role="status">該当 '.self::e($p['total']).'件 ／ '.($p['total'] ? self::e($p['offset']+1).'～'.self::e($p['offset']+count($data['rows'])) : '0').'件を表示</p>';
        $h .= self::navigation($p, $filter);
        $h .= '<div class="quota-table"><table><caption>メールボックス容量</caption><thead><tr><th scope="col">メールアドレス／状態</th><th scope="col">使用量</th><th scope="col">上限</th><th scope="col">計測時刻（日本時間）</th><th scope="col">操作</th></tr></thead><tbody>';
        foreach ($data['rows'] as $row) {
            $usage = $row['usage'];
            $active = (string)$row['active'] === '1' && (string)$row['domain_active'] === '1';
            $h .= '<tr><th scope="row">'.self::e($row['email']).'<br><small>'.($active ? '有効' : '停止中').'</small></th>';
            $h .= '<td>'.(is_array($usage) ? self::size($usage['used_bytes_upper_bound']) : '未確認').'</td>';
            $h .= '<td>'.((string)$row['quota_bytes'] === '0' ? '無制限' : self::size($row['quota_bytes'])).'</td>';
            $h .= '<td>'.(is_array($usage) ? self::e(gmdate('Y-m-d H:i:s', $usage['observed_at']+32400)) : '未計測・期限切れ・反映待ち').'</td>';
            $h .= '<td><details><summary>'.self::e($row['email']).' の上限を変更</summary>'
                .CutoverController::quotaForm($row, $token, $filter->url($p['page'])).'</details></td></tr>';
        }
        if (!$data['rows']) { $h .= '<tr><td colspan="5">該当する利用者はいません。</td></tr>'; }
        return $h.'</tbody></table></div>'.self::navigation($p, $filter);
    }

    public static function styles(): string
    {
        return '.quota-table{overflow-x:auto}.quota-table table{width:100%;border-collapse:collapse}'
            .'.quota-table th,.quota-table td{text-align:left;vertical-align:top;padding:.65rem;border-bottom:1px solid #64748b}'
            .'.quota-table th[scope=row]{overflow-wrap:anywhere}.quota-table details{min-width:10rem}'
            .'.quota-table details[open]{min-width:20rem}.quota-table summary{cursor:pointer}'
            .'.quota-table details section{margin:0;padding:.5rem}nav[aria-label="容量一覧のページ"] a{display:inline-block;padding:.3rem .6rem}';
    }

    public static function size(mixed $bytes): string
    {
        $n = PdoCutoverStore::bytes($bytes);
        if ($n < 1024) { return self::e($n).' B'; }
        foreach (['GiB'=>1073741824, 'MiB'=>1048576, 'KiB'=>1024] as $unit=>$divisor) {
            if ($n >= $divisor) { return self::e(number_format($n / $divisor, 1)).' '.$unit; }
        }
        throw new \LogicException('size_unit');
    }

    public static function navigation(array $p, QuotaListFilter $filter): string
    {
        $h = '<nav aria-label="容量一覧のページ"><p>';
        if ($p['page'] > 1) { $h .= '<a href="'.self::e($filter->url($p['page']-1)).'">前へ</a> '; }
        $numbers = array_unique(array_merge([1], range(max(1,$p['page']-2), min($p['pages'],$p['page']+2)), [$p['pages']]));
        sort($numbers); $last = 0;
        foreach ($numbers as $page) {
            if ($last && $page > $last+1) { $h .= ' … '; }
            $h .= $page === $p['page'] ? '<strong aria-current="page">'.$page.'</strong> ' : '<a href="'.self::e($filter->url($page)).'">'.$page.'</a> ';
            $last = $page;
        }
        if ($p['page'] < $p['pages']) { $h .= '<a href="'.self::e($filter->url($p['page']+1)).'">次へ</a>'; }
        return $h.'（'.$p['page'].' / '.$p['pages'].'ページ）</p></nav>';
    }
}
