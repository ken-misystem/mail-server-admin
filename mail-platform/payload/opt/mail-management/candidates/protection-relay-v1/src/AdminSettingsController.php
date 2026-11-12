<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class AdminSettingsController
{
    public function __construct(private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf, private readonly AdminSettingsStore $store) {}

    public function show(Request $request): Response
    {
        $actor = $this->actor($request);
        if (!$actor) { return $this->factorOrDenial($request); }
        try { $filter = AdminInventoryFilter::fromArray($request->query->all()); }
        catch (\DomainException) { return ConsoleController::page('検索条件を確認してください', '', 400); }
        try {
            if (!$this->store instanceof AdminInventoryStore) { throw new \DomainException('inventory_unavailable'); }
            $data = $this->store->browse($actor, $filter);
        } catch (\Throwable) { return ConsoleController::page('管理データを取得できません', '', 503); }
        $notice = '';
        if ($request->getSession()->remove('mail_admin_policy_saved') === true
            || $request->getSession()->remove('mail_admin_operation_saved') === true) {
            $notice = '<p role="status">設定を保存しました。</p>';
        }
        $body = AdminInventoryView::render($data, $filter,
            $this->csrf->getToken('mail_admin_policy')->getValue(),
            $this->csrf->getToken('mail_admin_operation')->getValue());
        return ConsoleController::page(AdminInventoryFilter::TITLES[$filter->section], $notice . $body, 200, self::stylesheet());
    }

    public static function policyForm(array $row, string $token): string
    {
        $body = '<fieldset><legend>利用者別エイリアス・POP取得上限</legend>'
            . '<form method="post" action="/mail-admin/user-policy"><input type="hidden" name="_csrf_token" value="' . $token . '">'
            . '<input type="hidden" name="user_id" value="' . ConsoleController::escape((string) $row['id']) . '">';
        foreach (['alias_limit' => ['エイリアス上限', 0, 1000], 'pop_account_limit' => ['POP取得アカウント上限（0は非許可）', 0, 100]] as $name => [$label, $min, $max]) {
            $body .= '<label>' . $label . '<input type="number" name="' . $name . '" min="' . $min . '" max="' . $max
                . '" step="1" required value="' . ConsoleController::escape((string) $row[$name]) . '"></label>';
        }
        return $body . '<button type="submit">上限設定を保存</button></form></fieldset>';
    }

    private static function stylesheet(): string
    {
        return <<<'CSS'
*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#203047;font:16px/1.6 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:28px 24px 60px}h1{font-size:26px;margin:0}h2{font-size:20px;margin:0 0 18px}a{color:#075bb6}.admin-back{margin:4px 0 18px}.admin-notice,.admin-warning{padding:12px 16px;border-radius:8px;background:#e9f1fb;font-size:14px}.admin-warning{background:#fff1cd;color:#63440a}.admin-tabs{display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #cad4e0;margin:24px 0}.admin-tabs a{padding:10px 16px;border-radius:8px 8px 0 0;text-decoration:none;color:#425268}.admin-tabs a[aria-selected=true]{background:#fff;color:#075bb6;border-bottom:3px solid #075bb6;font-weight:650}.admin-count{display:inline-block;margin-left:8px;background:#e4ebf4;color:#35485e;border-radius:12px;padding:0 8px;font-size:12px}.admin-panel{background:#fff;border:1px solid #d9e1eb;border-radius:12px;padding:24px;margin-bottom:20px}.admin-controls{display:flex;align-items:end;gap:16px;margin-top:20px}.admin-controls label:first-child{flex:1}.admin-controls input{width:100%}.admin-results,.admin-meta,.admin-footnote{font-size:14px;color:#52637a}.admin-record,.admin-create{border:1px solid #d7e0eb;border-radius:8px;margin:10px 0;background:#fff}.admin-create{background:#f7f9fc}.admin-record summary,.admin-create summary{cursor:pointer;padding:14px 16px}.admin-name{font-weight:650;overflow-wrap:anywhere}.admin-meta{display:block;padding-left:18px}.admin-badge{margin-left:12px;padding:2px 8px;border-radius:10px;background:#edf0f5;color:#536174;font-size:12px}.admin-badge.is-active{background:#e0f3e7;color:#21623a}.admin-editor{padding:0 18px 18px}fieldset{border:1px solid #d6dfe9;border-radius:8px;margin:16px 0;padding:16px;min-width:0}legend{font-weight:650;padding:0 6px}form{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:12px 0}label{display:flex;flex-direction:column;gap:5px;font-size:14px}input,select,button{font:inherit;border-radius:6px}input,select{border:1px solid #aebdce;padding:9px;min-width:0;max-width:100%;background:#fff;color:#203047}button{border:1px solid #075bb6;background:#075bb6;color:#fff;padding:9px 16px;cursor:pointer;align-self:end}button:disabled{opacity:.45;cursor:default}form[action$="/alias_remove"] button{background:#a92a34;border-color:#a92a34}form p{grid-column:1/-1;margin:0}.admin-pager{display:flex;justify-content:center;align-items:center;gap:18px;margin-top:20px}.admin-pager button{background:#fff;color:#075bb6}a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,button:focus-visible{outline:3px solid #60a5fa;outline-offset:3px}[hidden]{display:none!important}@media(max-width:640px){main{padding:18px 12px}h1{font-size:22px}.admin-panel{padding:16px}.admin-tabs a{padding:8px 10px}.admin-controls{align-items:stretch;flex-direction:column}form{grid-template-columns:1fr}.admin-name{display:inline}.admin-meta{padding-left:0}.admin-editor{padding:0 12px 12px}}
CSS;
    }

    public function save(Request $request): Response
    {
        $actor = $this->actor($request);
        if (!$request->isMethod('POST') || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
            || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN) { return ConsoleController::page('アクセス拒否', '', 403); }
        $token = $request->request->all()['_csrf_token'] ?? null;
        if (!is_string($token) || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_policy', $token))) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        if (!$actor) { return $this->factorOrDenial($request); }
        try {
            $input = $request->request->all();
            $returnTo = AdminInventoryFilter::returnTo($input['return_to'] ?? null);
            if (!is_string($input['user_id'] ?? null)) { throw new \DomainException('invalid_user_id'); }
            $this->store->setUserPolicy($actor, UserPolicyLimits::userId($input['user_id']), UserPolicyLimits::fromForm($input));
        } catch (\Throwable) { return ConsoleController::page('設定を保存できません', '<p>保存結果は未確認です。自動再試行は行いません。</p>', 400); }
        $request->getSession()->set('mail_admin_policy_saved', true);
        return new RedirectResponse($returnTo, 303, ['Cache-Control' => 'no-store']);
    }

    private function actor(Request $request): ?AdminUser
    {
        $user = $this->tokens->getToken()?->getUser();
        return $user instanceof AdminUser && AdminFactorGate::permits($user,
            $request->getSession()->get(AdminFactorGate::SESSION_KEY), time()) ? $user : null;
    }

    private function factorOrDenial(Request $request): Response
    {
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof AdminUser || !$user->active || !$user->systemAdmin) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        return ConsoleController::factorRequired($request, $this->csrf);
    }
}
