<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;
final class UpdateController
{
    private const SESSION='mail_update_forms';
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly UpdateClient $updates,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $request): ?AdminUser
    {
        $user=$this->tokens->getToken()?->getUser();
        return $user instanceof AdminUser && $user->systemAdmin && AdminFactorGate::verified($user,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time()) ? $user : null;
    }
    private function page(string $html,int $status=200): Response
    {
        $r=ConsoleController::page('ソフトウェア更新',$html,$status);$r->headers->set('Cache-Control','no-store');return $r;
    }
    public function show(Request $request): Response
    {
        $actor=$this->actor($request);if(!$actor){return ConsoleController::factorRequired($request,$this->csrf);}
        try{
            $s=$this->updates->call(['operation'=>'status']);
            if(!is_int($s['revision']??null)||!in_array($s['mode']??null,['manual','automatic'],true)){throw new \RuntimeException('update_status');}
            $e=static fn(mixed $v):string=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
            $nonce=bin2hex(random_bytes(16));$pool=$request->getSession()->get(self::SESSION,[]);$pool=is_array($pool)?array_slice($pool,-7,null,true):[];
            $pool[$nonce]=['id'=>$actor->id,'epoch'=>$actor->epoch,'revision'=>$s['revision'],'at'=>time()];$request->getSession()->set(self::SESSION,$pool);
            $html='<p>現在のバージョン：'.$e($s['installed_version']).'</p><p>新しいバージョン：'.$e($s['available_version']??'確認待ち').'</p>'
                .'<p>更新状態：'.$e($s['phase']).'</p><p>正式リリースの署名と内容を確認して更新します。メール・利用者設定は保持します。</p>'
                .'<p>更新方式と対象機能の停止影響を確認して適用してください。</p>'
                .'<form method="post"><input type="hidden" name="_csrf_token" value="'.$e($this->csrf->getToken('mail_updates')->getValue()).'">'
                .'<input type="hidden" name="nonce" value="'.$nonce.'"><label>更新方法<select name="mode">'
                .'<option value="manual"'.($s['mode']==='manual'?' selected':'').'>通知を確認して手動で更新</option>'
                .'<option value="automatic"'.($s['mode']==='automatic'?' selected':'').'>正式リリースを自動更新</option></select></label>'
                .'<button name="action" value="settings">更新方法を保存</button><button name="action" value="apply">今すぐ更新を予約</button></form>';
            $pending=$s['retirement_pending']??[];
            if (is_array($pending)&&$pending!==[]) {
                $html.='<p>新しい世代へ切替え済みです。既存接続の終了を待って旧世代を停止します。</p><ul>';
                foreach ($pending as $component) {
                    if (is_string($component)) $html.='<li>'.$e($component).'</li>';
                }
                $html.='</ul>';
            }
            $effect=$s['impact']??null;
            if(is_array($effect)&&is_string($effect['method']??null)&&is_string($effect['delivery']??null)){
                $html.='<p>更新方法：'.$e($effect['method']).'</p><p>'.$e($effect['delivery']).'</p>';
                if(is_array($effect['components']??null)){
                    foreach($effect['components'] as $component){if(is_string($component)){$html.='<p>対象機能：'.$e($component).'</p>';}}
                }
            }
            return $this->page($html);
        }catch(\Throwable){return $this->page('<p>更新サービスの状態を確認できません。設定は変更していません。</p>',503);}
    }
    public function save(Request $request): Response
    {
        $actor=$this->actor($request);if(!$actor){return ConsoleController::factorRequired($request,$this->csrf);}
        $in=$request->request->all();
        if(!$request->isMethod('POST')||!is_string($in['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_updates',$in['_csrf_token']))){return $this->page('',403);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return $this->page('',429);}
        $pool=$request->getSession()->get(self::SESSION,[]);$nonce=$in['nonce']??null;$old=is_string($nonce)&&is_array($pool)?($pool[$nonce]??null):null;
        if(!is_array($old)||$old['id']!==$actor->id||$old['epoch']!==$actor->epoch||$old['at']<time()-300||$old['at']>time()){return $this->page('<p>画面を取得し直してください。</p>',409);}
        unset($pool[$nonce]);$request->getSession()->set(self::SESSION,$pool);
        if(!in_array($in['action']??null,['settings','apply'],true)||!in_array($in['mode']??null,['manual','automatic'],true)){return $this->page('',400);}
        try{
            $this->updates->call(['operation'=>$in['action'],'mode'=>$in['mode'],'revision'=>$old['revision'],'actor'=>(string)$actor->id,'request_id'=>$nonce]);
            return $this->page('<p>受け付けました。更新画面で状態と結果を確認してください。</p>');
        }catch(\Throwable){return $this->page('<p>受付結果を確認できません。再実行する前に更新状態を確認してください。</p>',503);}
    }
}
