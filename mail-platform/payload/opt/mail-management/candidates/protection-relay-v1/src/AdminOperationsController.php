<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class AdminOperationsController
{
    public function __construct(private readonly TokenStorageInterface $tokens, private readonly CsrfTokenManagerInterface $csrf,
        private readonly AdminOperationsStore $store, private readonly RateLimiterFactory $limiter) {}

    public function apply(Request $request, string $action): Response
    {
        $actor = $this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser || !$actor->active || !$actor->systemAdmin || !$request->isMethod('POST')
            || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        $input = $request->request->all();
        if (!is_string($input['_csrf_token'] ?? null)
            || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_operation', $input['_csrf_token']))) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        if (strlen($request->getContent()) > 16384) { return ConsoleController::page('入力が大きすぎます', '', 413); }
        if (!AdminFactorGate::permits($actor, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time())) {
            return ConsoleController::factorRequired($request, $this->csrf);
        }
        if (!$this->limiter->create($actor->id . ':' . $request->getClientIp())->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です', '<p>操作は実行していません。</p>', 429);
        }
        try {
            $returnTo = AdminInventoryFilter::returnTo($input['return_to'] ?? null);
            $mutation = AdminMutation::fromForm($action, $input);
            $this->store->apply($actor, $mutation);
        } catch (\DomainException $e) {
            $message = match ($e->getMessage()) {
                'migration_protected' => 'POP移行保護中のアカウントまたはドメインは変更できません。',
                'last_administrator', 'last_usable_administrator' => '最後の有効な管理者を停止・降格できません。',
                'namespace_unavailable', 'admin_identity_unavailable' => '既存の名前・アドレスと競合しています。',
                'confirmation_required' => '対象の確認入力が一致しません。',
                'invalid_new_password' => 'パスワードは12〜1024バイトで、確認入力を一致させてください。制御文字は使用できません。',
                'owned_alias_binding' => '利用者所有エイリアスの配送先は変更できません。',
                'inactive_domain', 'inactive_destination', 'local_destination_required' => '有効なローカルドメイン・メールボックスが必要です。',
                default => '操作を完了できませんでした。結果は未確認です。自動再試行は行いません。',
            };
            return ConsoleController::page('操作を保存できません', '<p>' . $message . '</p><a href="/mail-admin/manage">管理設定に戻る</a>', 400);
        } catch (\Throwable) { return ConsoleController::page('操作を保存できません', '<p>結果は未確認です。自動再試行は行いません。</p>', 400); }
        $request->getSession()->set('mail_admin_operation_saved', true);
        return new RedirectResponse($returnTo, 303, ['Cache-Control' => 'no-store']);
    }
}
