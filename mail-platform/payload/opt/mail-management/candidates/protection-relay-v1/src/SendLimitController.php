<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{Request,Response,RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class SendLimitController
{
    public function __construct(private readonly TokenStorageInterface $tokens, private readonly CsrfTokenManagerInterface $csrf,
        private readonly SendLimitStore $store, private readonly RateLimiterFactory $limiter) {}

    public function show(Request $request): Response
    {
        $actor = $this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser || !$actor->active || !$actor->systemAdmin) { return ConsoleController::page('アクセス拒否', '', 403); }
        if (!AdminFactorGate::permits($actor, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time())) {
            return ConsoleController::factorRequired($request, $this->csrf);
        }
        if (!in_array($request->getMethod(), ['GET','POST'], true)) { return ConsoleController::page('許可されない操作です', '', 405); }
        if (!$this->limiter->create($actor->id . ':' . $request->getClientIp())->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です', '', 429);
        }
        if ($request->query->count()) { return ConsoleController::page('入力を確認してください', '', 400); }
        try {
            if ($request->isMethod('POST')) {
                if ($request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN) {
                    return ConsoleController::page('アクセス拒否', '', 403);
                }
                if (strlen($request->getContent()) > 4096) { return ConsoleController::page('入力が大きすぎます', '', 413); }
                $input = $request->request->all();
                if (!is_string($input['_csrf_token'] ?? null)
                    || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_send_limits', $input['_csrf_token']))) {
                    return ConsoleController::page('アクセス拒否', '', 403);
                }
                $this->store->save($actor, SendLimitChange::fromForm($input));
                $request->getSession()->set('mail_send_limits_saved', true);
                return new RedirectResponse('/mail-admin/send-limits', 303, ['Cache-Control'=>'no-store']);
            }
            $data = $this->store->overview($actor);
            $notice = $request->getSession()->remove('mail_send_limits_saved') === true
                ? '<p role="status">送信上限を保存しました。</p>' : '';
            return ConsoleController::page('本人単位の送信量制限', $notice . self::render($data, $this->csrf->getToken('mail_admin_send_limits')->getValue()));
        } catch (\DomainException $error) {
            $message = match ($error->getMessage()) {
                'revision_changed'=>'他の管理操作で更新されました。画面を再読込みして値を確認してください。',
                'confirmation_required'=>'対象区分の確認入力が一致しません。',
                'invalid_limits'=>'上限は1～1,000,000で指定してください。1時間の上限は1分以上、宛先数は回数以上にしてください。',
                'invalid_reason'=>'変更理由を200バイト以内で入力してください。',
                default=>'入力または管理権限を確認してください。',
            };
            return ConsoleController::page('送信上限を保存できません', '<p role="alert">' . $message . '</p>', 400);
        } catch (\Throwable $error) {
            if ($error instanceof SendLimitFailure) { error_log(json_encode(['component'=>'send_limits','failure'=>$error->detail], JSON_THROW_ON_ERROR)); }
            return ConsoleController::page('送信上限を確認できません', '<p role="alert">操作履歴と現在の設定を確認してください。</p>', 503);
        }
    }

    public static function render(array $data, string $token): string
    {
        $e = static fn(mixed $value): string => ConsoleController::escape((string)$value);
        $labels = ['minute_messages'=>'1分の送信試行回数', 'minute_recipients'=>'1分の宛先数',
            'hour_messages'=>'1時間の送信試行回数', 'hour_recipients'=>'1時間の宛先数'];
        $body = '<p>通常利用者はメールボックス単位、旧SMTPは認証ID単位で集計します。'
            . '上限を超えた送信は一時拒否451となり、送信アプリ側の再試行が必要です。'
            . '上限を下げると、直近の利用量が新しい上限を下回るまで送信を保留します。</p>'
            . '<p>回数は本文送信前の許可時に計上します。許可後に送信を中断した場合も計上が残ります。</p>';
        foreach ($data['profiles'] as $row) {
            $profile = $row['profile'];
            if (!isset(SendLimitChange::LABELS[$profile])) { throw new \DomainException('invalid_profile'); }
            $limits = SendLimitChange::limits($row);
            $revision = SendLimitChange::revision($row['revision']);
            $body .= '<fieldset><legend>' . SendLimitChange::LABELS[$profile] . '</legend>'
                . '<p>設定版 ' . $revision . '</p><form method="post" action="/mail-admin/send-limits">'
                . '<input type="hidden" name="_csrf_token" value="' . $e($token) . '">'
                . '<input type="hidden" name="profile" value="' . $profile . '">'
                . '<input type="hidden" name="revision" value="' . $revision . '">';
            foreach ($labels as $name=>$label) {
                $body .= '<label>' . $label . '<input type="number" name="' . $name . '" min="1" max="1000000" step="1" required value="' . $limits[$name] . '"></label>';
            }
            $body .= '<label>対象区分を確認入力（' . SendLimitChange::LABELS[$profile] . '）<input name="confirm_profile" required autocomplete="off"></label>'
                . '<label>変更理由<input name="reason" required maxlength="200"></label><button>上限を保存</button></form></fieldset>';
        }
        $body .= '<details><summary>直近50件の変更履歴</summary>';
        foreach ($data['history'] as $row) {
            $body .= '<section><h3>' . $e(SendLimitChange::LABELS[$row['profile']] ?? '区分不明') . ' 設定版 ' . $e($row['revision']) . '</h3>'
                . '<p>記録時刻 ' . $e($row['created_at']) . ' ／ 管理者ID ' . $e($row['admin_id']) . '</p><p>' . $e($row['reason']) . '</p><dl>';
            $before = SendLimitChange::limits(json_decode($row['before_json'], true, 8, JSON_THROW_ON_ERROR));
            $after = SendLimitChange::limits(json_decode($row['after_json'], true, 8, JSON_THROW_ON_ERROR));
            foreach ($labels as $name=>$label) { $body .= '<dt>' . $label . '</dt><dd>' . $before[$name] . ' → ' . $after[$name] . '</dd>'; }
            $body .= '</dl></section>';
        }
        return $body . '</details>';
    }
}
