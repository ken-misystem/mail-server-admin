<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{Request,Response,RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class DomainDeliveryController
{
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly DomainDeliveryStore $store,private readonly DomainDeliveryStatus $status,private readonly RateLimiterFactory $limiter) {}

    public function show(Request $request): Response
    {
        $actor=$this->tokens->getToken()?->getUser();
        if (!$actor instanceof AdminUser||!$actor->active||!$actor->systemAdmin) { return ConsoleController::page('アクセス拒否','',403); }
        if (!AdminFactorGate::permits($actor,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time())) {
            return ConsoleController::factorRequired($request,$this->csrf);
        }
        if (!in_array($request->getMethod(),['GET','POST'],true)) { return ConsoleController::page('許可されない操作です','',405); }
        if ($request->isMethod('POST')) {
            if (strlen($request->getContent())>4096||$request->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN
                ||$request->headers->get('Origin')!==AdminWebauthn::ORIGIN) { return ConsoleController::page('アクセス拒否','',403); }
            $input=$request->request->all();
            if (array_diff(array_keys($input),['_csrf_token','domain_id','revision','follow_mx','confirm'])
                ||!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_admin_domain_delivery',$input['_csrf_token']))
                ||!is_string($input['domain_id']??null)||!is_string($input['revision']??null)||!is_string($input['confirm']??null)
                ||!in_array($input['follow_mx']??'0',['0','1'],true)) { return ConsoleController::page('入力を確認してください','',400); }
            if (!$this->limiter->create($actor->id.':'.$request->getClientIp())->consume()->isAccepted()) {
                return ConsoleController::page('操作回数の上限です','',429);
            }
            try { $this->store->save($actor,$input['domain_id'],($input['follow_mx']??'0')==='1',$input['revision'],$input['confirm']); }
            catch (\Throwable $e) { return $this->failed($e); }
            $request->getSession()->set('mail_domain_delivery_saved',true);
            return new RedirectResponse('/mail-admin/domain-delivery',303,['Cache-Control'=>'no-store']);
        }
        if (!$this->limiter->create($actor->id.':'.$request->getClientIp())->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です','',429);
        }
        try { $data=$this->store->overview($actor); }
        catch (\Throwable $e) { return $this->failed($e); }
        $snapshot=$this->status->read();$escape=ConsoleController::escape(...);
        $body='<p><a href="/mail-admin/manage">管理設定</a> ／ <a href="/mail-admin/">メール管理</a></p>';
        if ($request->getSession()->remove('mail_domain_delivery_saved')===true) {
            $body.='<p role="status">希望設定を保存しました。実際の配送状態は下の「反映状態」で確認してください。</p>';
        }
        $body.='<p>移行中の同じドメイン宛メールを、公開MXに合わせて配送します。最優先MXがこのサーバーになれば内部配送します。</p>'
            .'<p>ドメイン全体と滞留メールの次回通常配送に作用します。DNSキャッシュ期間が過ぎ、配送を確認するまで旧サーバーを停止しないでください。</p>';
        if ($data['truncated']) { $body.='<p role="alert">先頭200ドメインのみ表示しています。</p>'; }
        foreach ($data['rows'] as $row) {
            $view=DomainDeliveryStatus::applied($row,$snapshot,time());
            $body.='<section><h2>'.$escape($row['name']).'</h2><p>反映状態：'.$escape($view['state']).' — '.$escape($view['reason']).'</p>';
            if ($view['checked_at']!==null) {
                $body.='<p>最終確認：'.$escape(gmdate('Y-m-d H:i:s',$view['checked_at']+9*3600)).' JST ／ 判定期限：'
                    .$escape(gmdate('Y-m-d H:i:s',$view['expires_at']+9*3600)).' JST</p>';
            }
            $disabled=(string)$row['active']!=='1'?' disabled':'';
            $body.='<form method="post" action="/mail-admin/domain-delivery"><input type="hidden" name="_csrf_token" value="'
                .$escape($this->csrf->getToken('mail_admin_domain_delivery')->getValue()).'">'
                .'<input type="hidden" name="domain_id" value="'.$escape((string)$row['id']).'">'
                .'<input type="hidden" name="revision" value="'.$escape((string)$row['revision']).'">'
                .'<label><input type="checkbox" name="follow_mx" value="1"'.((string)$row['follow_mx']==='1'?' checked':'').$disabled.'>'
                .'同じドメイン宛を公開MXの配送先へ送る（移行中）</label>'
                .'<p>チェックなし：このサーバー内へ配送。チェックあり：公開MXが旧サーバーなら旧側へ、切替え後にこのサーバーを指せば自動で内部へ配送します。DNS失敗・判定期限切れ・新旧MXの混在時は保留し、配送ループを防ぎます。</p>'
                .'<label>対象ドメイン名を確認入力<input name="confirm" autocomplete="off" required'.$disabled.'></label>'
                .'<button type="submit"'.$disabled.'>保存する</button></form></section>';
        }
        return ConsoleController::page('ドメインの配送切替',$body);
    }

    private function failed(\Throwable $e): Response
    {
        if ($e instanceof DomainDeliveryFailure) {
            error_log(json_encode(['component'=>'domain_delivery','failure'=>$e->detail],JSON_THROW_ON_ERROR));
        }
        $message=match($e->getMessage()) {
            'routing_version_changed'=>'他の操作で設定が更新されました。表示を更新してください。',
            'confirmation_required'=>'対象ドメイン名の確認入力が一致しません。',
            'inactive_domain'=>'有効なドメインだけ変更できます。',
            default=>'操作結果を確認できません。自動再試行は行いません。',
        };
        return ConsoleController::page('配送設定を処理できません','<p role="alert">'.$message.'</p>',503);
    }
}
