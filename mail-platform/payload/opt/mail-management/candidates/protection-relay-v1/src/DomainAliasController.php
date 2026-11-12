<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{Request, Response, RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken, CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** Separate route: leave the installed quota controller and its filtering unchanged. */
final class DomainAliasController
{
    public function __construct(private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf, private readonly CutoverStore $store,
        private readonly RateLimiterFactory $limiter) {}

    public function show(Request $request): Response
    {
        $actor = $this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser || !$actor->active || !$actor->systemAdmin) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        if (!AdminFactorGate::permits($actor, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time())) {
            return ConsoleController::factorRequired($request, $this->csrf);
        }
        if (!in_array($request->getMethod(), ['GET', 'POST'], true)) {
            return ConsoleController::page('許可されない操作です', '', 405);
        }
        if (!$this->limiter->create($actor->id.':'.$request->getClientIp())->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です', '', 429);
        }
        try {
            $params = $request->query->all();
            $after = $params['after'] ?? '0';
            if (array_diff(array_keys($params), ['after']) || !is_string($after)) {
                throw new \DomainException('invalid_input');
            }
            if ($after !== '0') { UserPolicyLimits::userId($after); }
            if ($request->isMethod('POST')) {
                if (strlen($request->getContent()) > 4096 || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
                    || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN) {
                    return ConsoleController::page('アクセス拒否', '', 403);
                }
                $input = $request->request->all();
                $allowed = ['_csrf_token','operation','id','alias_domain','confirm_alias','target_name',
                    'enabled','expected_target_domain_id','expected_enabled'];
                if (array_diff(array_keys($input), $allowed)) { throw new \DomainException('invalid_input'); }
                foreach ($input as $value) {
                    if (!is_string($value) || strlen($value) > 512) { throw new \DomainException('invalid_input'); }
                }
                if (!isset($input['_csrf_token']) || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_domain-aliases', $input['_csrf_token']))) {
                    return ConsoleController::page('画面を更新してください', '', 403);
                }
                unset($input['_csrf_token']);
                $this->store->save($actor, 'domain-aliases', $input);
                $request->getSession()->set('cutover_saved_domain-aliases', true);
                return new RedirectResponse('/mail-admin/domain-aliases', 303, ['Cache-Control'=>'no-store']);
            }
            $data = $this->store->overview($actor, 'domain-aliases', $after);
            $token = $this->csrf->getToken('mail_admin_domain-aliases')->getValue();
            $body = '<p><a href="/mail-admin/">メール管理</a></p>'
                .'<p>別名ドメイン宛を登録済みの本ドメインへ対応付けます。新規登録は無効で作成します。対応先の変更は無効にしてから行ってください。DNS・配送切替えの設定は変更しません。</p>';
            if ($request->getSession()->remove('cutover_saved_domain-aliases') === true) {
                $body .= '<p role="status">ドメイン別名を保存しました。</p>';
            }
            $body .= CutoverController::aliasForm(null, $token);
            foreach ($data['rows'] as $row) { $body .= CutoverController::aliasForm($row, $token); }
            if (!$data['rows']) { $body .= '<p>該当する登録はありません。</p>'; }
            if ($data['next_after'] !== null) {
                $body .= '<p><a href="/mail-admin/domain-aliases?after='
                    .ConsoleController::escape((string)$data['next_after']).'">次の50件</a></p>';
            }
            return ConsoleController::page('ドメイン別名管理', $body);
        } catch (\Throwable $e) {
            if ($e instanceof CutoverFailure) { $failure = $e; }
            elseif (!$e instanceof \DomainException) { $failure = new CutoverFailure('alias_controller', $e, false); }
            if (isset($failure)) {
                error_log(json_encode(['component'=>'domain_alias_admin','failure'=>$failure->detail], JSON_THROW_ON_ERROR));
            }
            return ConsoleController::page('操作できません', '<p role="alert">'.CutoverController::reason($e).'</p>',
                $e instanceof \DomainException ? 409 : 503);
        }
    }
}
