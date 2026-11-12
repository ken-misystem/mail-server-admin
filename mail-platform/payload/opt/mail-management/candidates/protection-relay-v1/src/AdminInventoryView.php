<?php
declare(strict_types=1);
namespace MailServer\Management;

final class AdminInventoryView
{
    private static function e(mixed $value): string { return ConsoleController::escape((string)$value); }

    public static function render(array $data, AdminInventoryFilter $filter, string $policyToken, string $operationToken): string
    {
        $window = $data['pagination'];
        $html = '<nav class="admin-tabs" aria-label="管理対象">';
        foreach (AdminInventoryFilter::TITLES as $section=>$title) {
            $html .= '<a href="/mail-admin/manage?section=' . $section . '"'
                . ($section === $filter->section ? ' aria-current="page"' : '') . '>' . $title . '</a>';
        }
        $html .= '</nav><p>一覧の切替・検索・再読込みの前に、編集した内容を保存してください。</p>'
            . '<form method="get" action="/mail-admin/manage" role="search">'
            . '<input type="hidden" name="section" value="' . $filter->section . '">'
            . '<label>名前・アドレス（前方一致）<input type="search" name="q" maxlength="128" value="' . self::e($filter->search->q) . '"></label>';
        if ($filter->section !== 'admins') {
            $html .= '<label>ドメイン（完全一致）<input name="domain" maxlength="253" value="' . self::e($filter->search->domain) . '"></label>';
        }
        $html .= '<label>状態<select name="state">';
        foreach ([''=>'すべて', '1'=>'有効', '0'=>'停止'] as $value=>$label) {
            $html .= '<option value="' . $value . '"' . ((string)$value === $filter->state ? ' selected' : '') . '>' . $label . '</option>';
        }
        $html .= '</select></label><label>表示件数<select name="per_page">';
        foreach ([25,50,100] as $size) {
            $html .= '<option' . ($size === $filter->search->perPage ? ' selected' : '') . ' value="' . $size . '">' . $size . '件</option>';
        }
        $html .= '</select></label><button>検索</button></form>';
        if (in_array($filter->section, ['users','aliases'], true)) {
            $html .= '<details><summary>新規作成・配送先変更の選択候補を検索</summary>'
                . '<p>候補は最大25件です。候補外のドメイン・配送先は完全な名前を入力して検索してください。</p>'
                . '<form method="get" action="/mail-admin/manage">';
            foreach ($filter->values($window['page']) as $key=>$value) {
                if (!in_array($key, ['domain_choice','destination_choice'], true)) {
                    $html .= '<input type="hidden" name="' . $key . '" value="' . self::e($value) . '">';
                }
            }
            $html .= '<label>作成先ドメイン（完全一致）<input name="domain_choice" maxlength="253" value="' . self::e($filter->domainChoice) . '"></label>'
                . '<label>エイリアス配送先（有効メールボックス・完全一致）<input type="email" name="destination_choice" maxlength="254" value="' . self::e($filter->destinationChoice) . '"></label>'
                . '<button>選択候補を検索</button></form></details>';
            foreach (['domains'=>'作成先ドメイン','users'=>'配送先メールボックス'] as $key=>$label) {
                $html .= '<p>' . $label . '候補 ' . count($data['choices'][$key]['rows']) . '件'
                    . ($data['choices'][$key]['truncated'] ? '（続きは完全一致検索で選択）' : '') . '</p>';
            }
        }
        $html .= '<details class="admin-create"><summary>新規追加</summary><div class="admin-editor">'
            . AdminOperationsForms::creation($filter->section, $data['choices'], $operationToken) . '</div></details>';
        $html .= '<p role="status">該当 ' . $window['total'] . '件 ／ '
            . ($window['total'] ? $window['offset']+1 : 0) . '～' . ($window['offset']+count($data['rows'])) . '件を表示</p>';
        $html .= self::pages($window, $filter);
        foreach ($data['rows'] as $row) {
            $name = match ($filter->section) { 'domains'=>$row['name'], 'aliases'=>$row['source'], default=>$row['email'] };
            $html .= '<details class="admin-record"><summary>' . self::e($name) . ' ／ '
                . ((string)$row['active'] === '1' ? '有効' : '停止') . '</summary><div class="admin-editor">';
            if ($filter->section === 'users') {
                $html .= '<p>所属ドメイン ' . self::e($row['domain_name']) . ' ／ '
                    . ((string)$row['domain_active'] === '1' ? '有効' : '停止') . ' ／ 所有エイリアス '
                    . self::e($row['owned_alias_count']) . '件</p>'
                    . AdminSettingsController::policyForm($row, self::e($policyToken));
            }
            $html .= AdminOperationsForms::record($filter->section, $row, $data['choices'], $operationToken) . '</div></details>';
        }
        if (!$data['rows']) { $html .= '<p>該当する項目はありません。</p>'; }
        $html .= self::pages($window, $filter);
        $return = '<input type="hidden" name="return_to" value="' . self::e($filter->url($window['page'])) . '">';
        return preg_replace_callback('/(<form method="post" action="\/mail-admin\/(?:operation\/[a-z_]+|user-policy)">)/',
            static fn(array $match): string => $match[1] . $return, $html) ?? throw new \LogicException('form_binding');
    }

    private static function pages(array $window, AdminInventoryFilter $filter): string
    {
        $html = '<nav aria-label="管理一覧のページ"><p>';
        $pages = array_unique(array_merge([1], range(max(1,$window['page']-2), min($window['pages'],$window['page']+2)), [$window['pages']]));
        sort($pages);
        if ($window['page'] > 1) { $html .= '<a href="' . self::e($filter->url($window['page']-1)) . '">前へ</a> '; }
        foreach ($pages as $page) {
            $html .= $page === $window['page'] ? '<strong aria-current="page">' . $page . '</strong> '
                : '<a href="' . self::e($filter->url($page)) . '">' . $page . '</a> ';
        }
        if ($window['page'] < $window['pages']) { $html .= '<a href="' . self::e($filter->url($window['page']+1)) . '">次へ</a>'; }
        return $html . '（' . $window['page'] . ' / ' . $window['pages'] . 'ページ）</p></nav>';
    }
}
