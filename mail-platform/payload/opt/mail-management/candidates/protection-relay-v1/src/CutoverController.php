<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{Request, Response, RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken, CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class CutoverController
{
    public function __construct(private readonly TokenStorageInterface $tokens, private readonly CsrfTokenManagerInterface $csrf,
        private readonly CutoverStore $store, private readonly RateLimiterFactory $limiter) {}

    public function show(Request $request, string $section): Response
    {
        if (!in_array($section, ['mailbox-quota'], true)) { return ConsoleController::page('対象がありません','',404); }
        $actor = $this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser || !$actor->active || !$actor->systemAdmin) { return ConsoleController::page('アクセス拒否','',403); }
        if (!AdminFactorGate::permits($actor, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time())) {
            return ConsoleController::factorRequired($request, $this->csrf);
        }
        if (!in_array($request->getMethod(), ['GET','POST'], true)) { return ConsoleController::page('許可されない操作です','',405); }
        if (!$this->limiter->create($actor->id.':'.$request->getClientIp())->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です','',429);
        }
        try {
            $filter = QuotaListFilter::fromArray($request->query->all());
            if ($request->isMethod('POST')) {
                if (strlen($request->getContent()) > 4096 || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
                    || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN) { return ConsoleController::page('アクセス拒否','',403); }
                $input = $request->request->all();
                $allowed = $section === 'domain-aliases'
                    ? ['_csrf_token','operation','id','alias_domain','confirm_alias','target_name','enabled','expected_target_domain_id','expected_enabled']
                    : ['_csrf_token','id','confirm','expected_bytes','mode','limit_kib','confirm_unlimited'];
                if (array_diff(array_keys($input), $allowed)) { throw new \DomainException('invalid_input'); }
                foreach ($input as $v) { if (!is_string($v) || strlen($v) > 512) { throw new \DomainException('invalid_input'); } }
                if (!isset($input['_csrf_token']) || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_'.$section, $input['_csrf_token']))) {
                    return ConsoleController::page('画面を更新してください','',403);
                }
                unset($input['_csrf_token']); $this->store->save($actor, $section, $input);
                $request->getSession()->set('cutover_saved_'.$section, true);
                return new RedirectResponse($filter->url(),303,['Cache-Control'=>'no-store']);
            }
            $data = $this->store->overview($actor, $section, '0', $request->query->all());
            $token = $this->csrf->getToken('mail_admin_'.$section)->getValue();
            $body = '<p><a href="/mail-admin/">メール管理</a> ／ <a href="/mail-admin/mailbox-quota">メールボックス容量</a></p>';
            if ($request->getSession()->remove('cutover_saved_'.$section) === true) {
                $body .= '<p role="status">設定値を保存しました。容量の実効状態は次の測定で確認します。</p>';
            }
            if ($section === 'domain-aliases') {
                $body .= '<p>別名ドメイン宛を登録済みの本ドメインへ対応付けます。新規登録は無効で作成します。転送先の変更は無効にしてから行ってください。DNS・配送先の切替設定は変更しません。</p>';
                $body .= self::aliasForm(null, $token);
            } else {
                $body .= '<p>単位はKiB（1 KiB＝1024バイト）です。使用量は直近の観測値で、その後の着信で増減します。未確認・期限切れ・反映待ちでは変更できません。変更は既存メールを削除しません。</p>';
                $body .= '<p>保存と実効反映は別です。変更後の計測時に、この利用者の既存IMAP・POP接続を切断します。Roundcube・メーラーは再接続してください。反映確認まで次の変更は停止します。</p>';
            }
            $body .= QuotaListView::render($data, $filter, $token);
            return ConsoleController::page($section === 'domain-aliases' ? 'ドメイン別名管理' : 'メールボックス容量制限', $body, 200, QuotaListView::styles());
        } catch (\Throwable $e) {
            if ($e instanceof CutoverFailure) { error_log(json_encode(['component'=>'cutover_admin','failure'=>$e->detail], JSON_THROW_ON_ERROR)); }
            elseif (!$e instanceof \DomainException) {
                error_log(json_encode(['component'=>'cutover_admin','failure'=>(new CutoverFailure('controller',$e,false))->detail], JSON_THROW_ON_ERROR));
            }
            return ConsoleController::page('操作できません', '<p role="alert">'.self::reason($e).'</p>', $e instanceof \DomainException ? 409 : 503);
        }
    }

    private static function e(mixed $s): string { return ConsoleController::escape((string)$s); }
    private static function hidden(string $name, mixed $value): string
    { return '<input type="hidden" name="'.$name.'" value="'.self::e($value).'">'; }

    public static function aliasForm(?array $r, string $token): string
    {
        $h = '<section><h2>'.($r ? self::e($r['alias_domain']).'（'.((string)$r['active'] === '1' ? '有効' : '無効').'）' : '別名を新規登録').'</h2>';
        $h .= '<form method="post" action="/mail-admin/domain-aliases">'.self::hidden('_csrf_token',$token);
        if ($r) {
            foreach (['id','alias_domain'] as $k) { $h .= self::hidden($k, $r[$k]); }
            $h .= self::hidden('expected_target_domain_id',$r['target_domain_id']).self::hidden('expected_enabled',$r['active']);
            $h .= '<label>操作<select name="operation"><option value="set_state">有効／無効の変更</option>'
                .((string)$r['active'] === '0' ? '<option value="repoint">本ドメインの変更（無効のまま）</option>' : '').'</select></label>';
        } else {
            $h .= self::hidden('operation','create').'<label>別名ドメイン<input name="alias_domain" maxlength="253" required></label>';
        }
        $h .= '<label>対応先の本ドメイン<input name="target_name" value="'.self::e($r['target_name'] ?? '').'" maxlength="253" required></label>';
        $h .= $r ? '<label>状態<select name="enabled"><option value="0"'.((string)$r['active'] === '0' ? ' selected' : '').'>無効</option><option value="1"'.((string)$r['active'] === '1' ? ' selected' : '').'>有効</option></select></label>' : self::hidden('enabled','0');
        return $h.'<label>別名ドメインを確認入力<input name="confirm_alias" maxlength="253" required autocomplete="off"></label><button type="submit">保存する</button></form></section>';
    }

    public static function quotaForm(array $r, string $token, string $returnUrl = "/mail-admin/mailbox-quota"): string
    {
        $ready = is_array($r['usage']) && (string)$r['active'] === '1' && (string)$r['domain_active'] === '1';
        $h = '<section><h2>'.self::e($r['email']).'</h2><p>保存された上限：'.((string)$r['quota_bytes'] === '0' ? '無制限' : self::e($r['quota_bytes']).' バイト').'</p>';
        if (is_array($r['usage'])) { $h .= '<p>観測使用量（上限換算）：'.self::e($r['usage']['used_bytes_upper_bound']).' バイト ／ 観測時刻：'.self::e(gmdate('Y-m-d H:i:s',$r['usage']['observed_at']+32400)).' JST</p>'; }
        else { $h .= '<p role="status">容量計測・実効制限が未確認、期限切れ、または反映待ちです。変更を停止しています。</p>'; }
        $h .= '<form method="post" action="'.self::e($returnUrl).'"><fieldset'.($ready ? '' : ' disabled').'>';
        foreach (['_csrf_token'=>$token,'id'=>$r['id'],'expected_bytes'=>$r['quota_bytes']] as $k=>$v) { $h .= self::hidden($k,$v); }
        return $h.'<label>制限<select name="mode"><option value="limited">上限を設定</option><option value="unlimited">無制限</option></select></label>'
            .'<label>上限（KiB）<input name="limit_kib" inputmode="numeric" pattern="[1-9][0-9]{0,9}"></label>'
            .'<label><input type="checkbox" name="confirm_unlimited" value="1">無制限への変更を承認する</label>'
            .'<label>対象メールアドレスを確認入力<input name="confirm" required maxlength="254" autocomplete="off"></label>'
            .'<button type="submit">保存する</button></fieldset></form></section>';
    }

    public static function reason(\Throwable $e): string
    {
        return match ($e->getMessage()) {
            'stale_form'=>'別の操作で更新されています。画面を読み直してください。',
            'confirmation_required'=>'確認入力が一致しません。',
            'primary_domain_required','inactive_destination'=>'対応先には有効な本ドメインを指定してください。',
            'namespace_unavailable','snapshot_conflict'=>'既存の本ドメインまたは別名と競合しています。',
            'disable_before_repoint','unexpected_repoint'=>'本ドメインの変更は別名を無効にした後、専用の操作を選んでください。',
            'quota_below_usage_or_overflow'=>'観測使用量以上の上限を指定してください。',
            'unlimited_confirmation_required'=>'無制限への変更には確認チェックが必要です。',
            'quota_backend_unverified','quota_usage_stale','quota_binding_changed','quota_snapshot_invalid'=>'容量の計測・実効反映を確認できません。変更していません。',
            'snapshot_incomplete'=>'管理対象が一括照合の上限を超えています。変更していません。',
            'browse_capacity'=>'検索条件を絞り込んでください。一覧件数の処理上限を超えています。',
            'invalid_input','invalid_domain','invalid_quota','create_disabled_only'=>'入力形式を確認してください。新規別名は無効で登録します。',
            default=>'操作結果を確認できません。自動再試行は行いません。',
        };
    }
}
