<?php

declare(strict_types=1);

namespace MailServer\Management;

/** Small HTML forms, no JavaScript values, credentials, remembered password inputs or unsafe HTML. */
final class AdminOperationsForms
{
    public static function render(array $data, string $token): string
    {
        $body = '<h2>管理者操作</h2><p>新規ドメイン・メールボックス・エイリアス・管理者は停止状態で作成します。'
            . 'DNSは自動変更しません。メール本文やMaildirを削除する操作はありません。'
            . '状態変更やパスワード再設定は対象アドレスを入力して確認してください。</p>';
        foreach (['domains', 'users', 'aliases', 'admins'] as $group) {
            $body .= self::creation($group, $data, $token);
        }
        foreach (['domains', 'users', 'aliases', 'admins'] as $group) {
            foreach ($data[$group]['rows'] as $row) { $body .= self::record($group, $row, $data, $token); }
        }
        return $body . '<p>ドメイン／メールボックスの名前変更・物理削除、ドメイン別名変更、外部宛て転送設定はこの画面では行いません。</p>';
    }

    public static function creation(string $group, array $data, string $token): string
    {
        return match ($group) {
            'domains' => '<fieldset><legend>受信ドメインを作成</legend>' . self::form('domain_create', $token,
                self::input('name', 'ドメイン名（ASCII）', '', 'text', 253)) . '</fieldset>',
            'users' => '<fieldset><legend>メールボックスを作成</legend>' . self::form('mailbox_create', $token,
                self::select('domain_id', 'ドメイン', $data['domains']['rows'], 'name')
                . self::input('local_part', 'アカウント名（@より前）', '', 'text', 64) . self::receivingHint() . self::passwords()) . '</fieldset>',
            'aliases' => '<fieldset><legend>受信エイリアスを作成</legend>' . self::form('alias_create', $token,
                self::select('domain_id', 'ドメイン', $data['domains']['rows'], 'name')
                . self::input('local_part', '受信名（@より前）', '', 'text', 64)
                . self::receivingHint()
                . self::select('destination_id', '配送先（有効ローカルメールボックス）', $data['users']['rows'], 'email')) . '</fieldset>',
            'admins' => '<fieldset><legend>独立した管理者IDを追加</legend>' . self::form('admin_create', $token,
                self::input('email', '管理者ID（運用していないドメインも指定可）', '', 'email', 254) . self::passwords()) . '</fieldset>',
            default => throw new \DomainException('invalid_ui_group'),
        };
    }

    public static function record(string $group, array $row, array $data, string $token): string
    {
        if ($group === 'domains') {
            return '<fieldset><legend>ドメイン: ' . ConsoleController::escape($row['name']) . '</legend>'
                . '<p>停止は受信に影響し、所属利用者のWebセッションを失効させます。既存IMAP/POP接続は強制切断しません。</p>'
                . self::form('domain_state', $token, self::target($row['id'], $row['name']) . self::state((string) $row['active'])) . '</fieldset>';
        }
        if ($group === 'users') {
            $target = self::target($row['id'], $row['email']);
            return '<fieldset><legend>メールボックス: ' . ConsoleController::escape($row['email']) . '</legend>'
                . self::form('mailbox_state', $token, $target . self::state((string) $row['active']))
                . '<p>メール用パスワードの再設定はIMAP/POP/SMTPクライアントとRoundcubeの通常パスワードに作用します。独立管理者パスワードとは別です。</p>'
                . self::form('mailbox_password', $token, $target . self::passwords()) . '</fieldset>';
        }
        if ($group === 'aliases') {
            $target = self::target($row['id'], $row['source']);
            return '<fieldset><legend>受信エイリアス: ' . ConsoleController::escape($row['source']) . '</legend>'
                . '<p>配送先: ' . ConsoleController::escape($row['destination']) . '</p>'
                . self::form('alias_state', $token, $target . self::state((string) $row['active']))
                . self::form('alias_destination', $token, $target
                    . self::select('destination_id', '配送先（有効ローカルメールボックス）', $data['users']['rows'], 'email'))
                . self::form('alias_remove', $token, $target . '<p>受信経路を削除します。保存済みメールは削除しません。</p>', '受信経路を削除') . '</fieldset>';
        }
        if ($group === 'admins') {
            $target = self::target($row['id'], $row['email']);
            return '<fieldset><legend>独立管理者: ' . ConsoleController::escape($row['email']) . '</legend>'
                . self::form('admin_state', $token, $target . self::state((string) $row['active'])
                    . '<label>システム管理権限<select name="system_admin"><option value="0"'
                    . ((string) $row['is_system_admin'] === '0' ? ' selected' : '') . '>なし（自身の本人確認のみ）</option><option value="1"'
                    . ((string) $row['is_system_admin'] === '1' ? ' selected' : '') . '>あり</option></select></label>')
                . self::form('admin_identity', $token, $target . self::input('email', '新しい独立管理者ID', '', 'email', 254))
                . self::form('admin_password', $token, $target . self::passwords()) . '</fieldset>';
        }
        throw new \DomainException('invalid_ui_group');
    }

    private static function form(string $action, string $token, string $fields, string $button = '保存'): string
    {
        return '<form method="post" action="/mail-admin/operation/' . $action . '"><input type="hidden" name="_csrf_token" value="'
            . ConsoleController::escape($token) . '">' . $fields . '<button type="submit">' . $button . '</button></form>';
    }
    private static function input(string $name, string $label, string $value = '', string $type = 'text', int $max = 320): string
    {
        return '<label>' . $label . '<input required type="' . $type . '" name="' . $name . '" maxlength="' . $max
            . '" autocomplete="' . ($type === 'password' ? 'new-password' : 'off') . '" value="' . ConsoleController::escape($value) . '"></label>';
    }
    private static function passwords(): string
    { return self::input('new_password', '新しいパスワード', '', 'password', 1024) . self::input('repeat_password', '確認入力', '', 'password', 1024); }
    private static function receivingHint(): string
    { return '<p>途中のドットを除いた名前を登録します。+タグは登録不要です。先頭・末尾・連続ドットは使用できません。</p><output data-receiving-preview aria-live="polite"></output>'; }
    private static function target(string $id, string $name): string
    {
        return '<input type="hidden" name="id" value="' . ConsoleController::escape($id) . '">'
            . self::input('confirm_target', '対象名を確認入力: ' . ConsoleController::escape($name));
    }
    private static function state(string $active): string
    { return '<label>状態<select name="enabled"><option value="0"' . ($active === '0' ? ' selected' : '')
        . '>停止</option><option value="1"' . ($active === '1' ? ' selected' : '') . '>有効</option></select></label>'; }
    private static function select(string $name, string $label, array $rows, string $display): string
    {
        $html = '<label>' . $label . '<select name="' . $name . '" required><option value="">選択してください</option>';
        foreach ($rows as $row) { $html .= '<option value="' . ConsoleController::escape((string) $row['id']) . '">'
            . ConsoleController::escape($row[$display]) . '</option>'; }
        return $html . '</select></label>';
    }
}
