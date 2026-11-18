<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{RedirectResponse,Request,Response};
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};

final class NotificationController
{
    private const PATH = '/mail-admin/notifications';
    private const SESSION = 'mail_notification_forms';
    private const CSRF = 'mail_notification_delivery';

    public function __construct(
        private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf,
        private readonly UpdateClient $broker,
        private readonly RateLimiterFactory $limiter,
    ) {}

    private static function verified(AdminUser $user, Request $request): bool
    {
        return AdminFactorGate::verified($user, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time());
    }

    public static function dashboard(Request $request, AdminUser $user, CsrfTokenManagerInterface $csrf): string
    {
        if (!$user->active || !$user->systemAdmin || !self::verified($user,$request)) {
            return '';
        }
        return self::controls($request,$user,$csrf,new UpdateClient(),true);
    }

    private static function controls(Request $request, AdminUser $user, CsrfTokenManagerInterface $csrf,
                                     UpdateClient $broker, bool $dashboard): string
    {
        try {
            $state = $broker->call(['operation'=>'notification_status']);
            if (!is_bool($state['enabled']??null) || !is_bool($state['configurable']??null)
                || !is_string($state['revision']??null) || !preg_match('/\A[a-f0-9]{64}\z/D',$state['revision'])) {
                throw new \RuntimeException('notification_status');
            }
        } catch (\Throwable) {
            return $dashboard ? '<p><a href="'.self::PATH.'">通知設定</a></p>'
                              : '<p role="alert">通知設定サービスに接続できません。</p>';
        }
        if (!$state['configurable']) {
            return $dashboard ? '<p><a href="'.self::PATH.'">通知設定</a></p>'
                              : '<p role="status">通知の再開にはサーバー側で通知先の設定が必要です。</p>';
        }
        $nonce = bin2hex(random_bytes(16));
        $pool = $request->getSession()->get(self::SESSION, []);
        $pool = is_array($pool) ? array_slice($pool, -7, null, true) : [];
        $pool[$nonce] = ['id'=>$user->id,'epoch'=>$user->epoch,'revision'=>$state['revision'],
                         'at'=>time(),'enabled'=>!$state['enabled'],'return_to'=>$dashboard?'/mail-admin/':self::PATH];
        $request->getSession()->set(self::SESSION, $pool);
        $token = ConsoleController::escape($csrf->getToken(self::CSRF)->getValue());
        $button = $state['enabled'] ? '内部障害通知を停止' : '内部障害通知を再開';
        $out = '<form method="post" action="'.self::PATH.'"><input type="hidden" name="_csrf_token" value="'.$token.'">'
             . '<input type="hidden" name="nonce" value="'.$nonce.'"><button type="submit">'.$button.'</button></form>';
        if ($dashboard) {
            return $out.'<p><a href="'.self::PATH.'">通知設定</a></p>';
        }
        $channels = [];
        foreach (['email'=>'メール','discord'=>'Discord'] as $key=>$label) {
            if (($state['channels'][$key]??false)===true) { $channels[] = $label; }
        }
        return '<p>通知経路：'.implode('・',$channels).'</p>'.$out
             . '<p>次の定期処理から反映されます。停止操作の時点で処理中の通知は完了することがあります。稼働監視は継続します。</p>';
    }

    private function page(string $body, int $status = 200): Response
    {
        $response = ConsoleController::page('通知設定',$body,$status);
        $response->headers->set('Cache-Control','no-store');
        return $response;
    }

    public function show(Request $request): Response
    {
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof AdminUser || !$user->active || !$user->systemAdmin) {
            return ConsoleController::page('アクセス拒否','',403);
        }
        if (!self::verified($user,$request)) { return ConsoleController::factorRequired($request,$this->csrf); }
        return $this->page(InternalAlertsStatus::read(time()).self::controls($request,$user,$this->csrf,$this->broker,false));
    }

    public function save(Request $request): Response
    {
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof AdminUser || !$user->active || !$user->systemAdmin) {
            return ConsoleController::page('アクセス拒否','',403);
        }
        if (!self::verified($user,$request)) { return ConsoleController::factorRequired($request,$this->csrf); }
        $input = $request->request->all();
        if (!$request->isMethod('POST') || !is_string($input['_csrf_token']??null)
            || !$this->csrf->isTokenValid(new CsrfToken(self::CSRF,$input['_csrf_token']))) {
            return $this->page('<p role="alert">操作を受け付けられません。</p>',403);
        }
        if (!$this->limiter->create((string)$user->id)->consume()->isAccepted()) {
            return $this->page('<p role="alert">時間をおいて画面を開き直してください。</p>',429);
        }
        $pool = $request->getSession()->get(self::SESSION, []);
        $nonce = $input['nonce']??null;
        $form = is_string($nonce) && is_array($pool) ? ($pool[$nonce]??null) : null;
        $now = time();
        if (!is_array($form) || $form['id']!==$user->id || $form['epoch']!==$user->epoch
            || $form['at']<$now-300 || $form['at']>$now) {
            return $this->page('<p role="alert">画面を開き直してください。</p>',409);
        }
        unset($pool[$nonce]);
        $request->getSession()->set(self::SESSION,$pool);
        try {
            $this->broker->call(['operation'=>'notification_delivery','enabled'=>$form['enabled'],
                                 'revision'=>$form['revision'],'actor'=>(string)$user->id,'request_id'=>$nonce]);
        } catch (\Throwable) {
            return $this->page('<p role="alert">設定変更の結果を確認できません。<a href="'.self::PATH.'">通知設定</a>を開き直して現在の状態を確認してください。</p>',503);
        }
        $response = new RedirectResponse($form['return_to'],303);
        $response->headers->set('Cache-Control','no-store');
        return $response;
    }
}
