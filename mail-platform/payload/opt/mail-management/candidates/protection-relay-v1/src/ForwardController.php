<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** Domain-scoped configuration forms; file publication is never done in PHP-FPM. */
final class ForwardController
{
    private const SESSION='mail_forward_forms';
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly ForwardStore $store,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $r):?AdminUser
    {$actor=$this->tokens->getToken()?->getUser();return $actor instanceof AdminUser&&AdminFactorGate::verified($actor,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$actor:null;}
    private static function page(string $title,string $html,int $status=200):Response
    {return ConsoleController::page($title,'<p><a href="/mail-admin/scoped/forwards">転送一覧へ</a> · <a href="/mail-admin/scoped/mailboxes">利用者を検索</a></p>'.$html,$status,null,[]);}
    public function edit(Request $r,string $id):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}if(!$r->isMethod('GET')){return self::page('アクセス拒否','',403);}
        try{
            ScopedAdminQuery::id($id);$row=$this->store->lookup($actor,$id);if(!$row){return self::page('対象がありません','',404);}$e=ConsoleController::escape(...);
            $html='<p>対象：'.$e($row['email']).'</p><p>転送自体はローカル保存を取り消しません。個人の振分けルールはその後に適用します。変更は保存後に反映処理で確認されます。障害時は新しい転送だけを保留し、受信メールを削除しません。</p>';
            if(!$row['can_change']){return self::page('転送設定',$html.'<p>参照のみです。</p><ul>'.implode('',array_map(static fn($target)=>'<li>'.$e($target).'</li>',$row['destinations'])).'</ul>');}
            $pool=$r->getSession()->get(self::SESSION,[]);if(!is_array($pool)){$pool=[];}$pool=array_filter($pool,static fn($item)=>is_array($item)&&is_int($item['at']??null)&&$item['at']<=time()&&$item['at']>time()-300);while(count($pool)>=24){array_shift($pool);}
            $nonce=bin2hex(random_bytes(16));$pool[$nonce]=['actor'=>$actor->id,'epoch'=>$actor->epoch,'id'=>$id,'email'=>$row['email'],'revision'=>$row['revision'],'at'=>time()];$r->getSession()->set(self::SESSION,$pool);
            $html.='<form method="post" action="/mail-admin/forward/'.$e($id).'"><input type="hidden" name="_csrf_token" value="'.$e($this->csrf->getToken('mail_forward_change')->getValue()).'"><input type="hidden" name="nonce" value="'.$nonce.'"><label>転送状態<select name="enabled"><option value="0"'.(!$row['enabled']?' selected':'').'>無効</option><option value="1"'.($row['enabled']?' selected':'').'>有効</option></select></label><label>転送先（1行1件、最大10件）<textarea name="destinations" rows="10" maxlength="2560">'.$e(implode("\n",$row['destinations'])).'</textarea></label><label>対象アドレスを再入力<input name="confirm_target" autocomplete="off" required></label><p>保存すると障害集計の起点を更新します。保留の再開前に転送先の障害を解消してください。同じ宛先の通常送信失敗も集計対象になり、転送分だけの失敗とは区別できません。既存の配送待ちは自動再送しません。</p><button>転送設定を保存</button></form>';
            return self::page('転送設定',$html);
        }catch(\DomainException){return self::page('対象または権限を確認してください','',403);}catch(\Throwable){return self::page('転送設定を取得できません','',503);}
    }
    public function save(Request $r,string $id):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}$input=$r->request->all();
        if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_forward_change',$input['_csrf_token']))){return self::page('アクセス拒否','',403);}
        if(strlen($r->getContent())>8192){return self::page('入力が大きすぎます','',413);}if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return self::page('操作回数の上限です','',429);}
        $nonce=$input['nonce']??null;$pool=$r->getSession()->get(self::SESSION,[]);$prior=is_string($nonce)&&is_array($pool)?($pool[$nonce]??null):null;
        if(!is_array($prior)||$prior['id']!==$id||$prior['actor']!==$actor->id||$prior['epoch']!==$actor->epoch||!is_int($prior['at'])||$prior['at']>time()||$prior['at']<time()-300){return self::page('確認期限または対象を確認してください','<p>設定画面を取得し直してください。</p>',400);}
        unset($pool[$nonce]);$r->getSession()->set(self::SESSION,$pool);
        try{
            if(!is_string($input['enabled']??null)||!in_array($input['enabled'],['0','1'],true)||!is_string($input['destinations']??null)||strlen($input['destinations'])>2560||!is_string($input['confirm_target']??null)){throw new \DomainException('invalid_input');}
            AdminMailPolicy::confirmation($prior['email'],$input['confirm_target']);$raw=str_replace("\r\n","\n",$input['destinations']);$values=$raw===''?[]:explode("\n",trim($raw));$targets=ForwardPlan::targets($values);
            $out=$this->store->save($actor,$id,$prior['revision'],$targets,$input['enabled']==='1',$prior['email'],$nonce);
            if(($out['state']??null)!=='saved_pending_publication'||($out['user_id']??null)!==$id||($out['revision']??null)!==$prior['revision']+1){throw new \DomainException('result_unverified');}
            return self::page('転送設定の保存結果','<p>保存しました。反映処理による確認待ちです。</p>');
        }catch(\DomainException $error){return self::page('保存結果を確認してください','<p>再送せず、現在の設定と管理操作履歴を確認してください。</p>',$error->getMessage()==='result_unverified'?503:409);}catch(\Throwable){return self::page('保存結果が未確定です','<p>再送せず、現在の設定と管理操作履歴を確認してください。</p>',503);}
    }
}
