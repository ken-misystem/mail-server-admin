<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class DomainDelegationController
{
    public const LABELS=['mailbox.read'=>'利用者の参照','mailbox.create'=>'利用者の登録','mailbox.state'=>'利用者の有効・無効変更','mailbox.password'=>'利用者のパスワード変更','mailbox.quota'=>'利用者の容量上限変更','alias.read'=>'受信エイリアスの参照','alias.create'=>'受信エイリアスの登録','alias.change'=>'受信エイリアスの変更','forward.read'=>'転送の参照','forward.change'=>'転送の変更','usage.read'=>'本人別利用状況の参照','csv.preview'=>'CSVの事前確認','csv.apply'=>'CSVの選択行登録'];
    private const KEY='mail_domain_delegation_preview';
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly DomainDelegationStore $store,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $r):?AdminUser{$u=$this->tokens->getToken()?->getUser();return $u instanceof AdminUser&&AdminFactorGate::permits($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$u:null;}
    private static function id(mixed $v):bool{return is_string($v)&&preg_match('/^[1-9][0-9]{0,9}$/D',$v)===1;}
    public function show(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        $e=ConsoleController::escape(...);$html='<p>有効な一般管理者に、指定ドメインの操作だけを委任します。全体管理者への昇格ではありません。変更後、対象管理者は本人確認をやり直す必要があります。</p><form method="get"><label>管理者ID<input name="admin_id" required></label><label>ドメインID<input name="domain_id" required></label><button>現在の委任を確認</button></form><p><a href="/mail-admin/manage?section=admins">管理者を検索</a> ／ <a href="/mail-admin/manage?section=domains">ドメインを検索</a></p>';
        $v=$r->query->all();if(!$v){return ConsoleController::page('ドメイン別の管理委任',$html);}
        if(!self::id($v['admin_id']??null)||!self::id($v['domain_id']??null)){return ConsoleController::page('対象IDを確認してください',$html,400);}
        try{
            $data=$this->store->lookup($actor,$v['admin_id'],$v['domain_id']);
            if(($data['admin_id']??null)!==$v['admin_id']||($data['domain_id']??null)!==$v['domain_id']||!is_int($data['revision']??null)||$data['revision']<0||!is_array($data['capabilities']??null)||!is_string($data['admin_label']??null)||!is_string($data['domain_label']??null)){throw new \UnexpectedValueException('scope');}
            foreach($data['capabilities'] as $cap){if(!is_string($cap)||!isset(self::LABELS[$cap])){throw new \UnexpectedValueException('capability');}}
            $id=bin2hex(random_bytes(16));$r->getSession()->set(self::KEY,['request_id'=>$id,'actor'=>$actor->id,'epoch'=>$actor->epoch,'at'=>time(),'admin_id'=>$data['admin_id'],'domain_id'=>$data['domain_id'],'revision'=>$data['revision'],'admin_label'=>$data['admin_label'],'domain_label'=>$data['domain_label']]);
            $html.='<h2>'.$e($data['admin_label']).' ／ '.$e($data['domain_label']).'</h2><form method="post" action="/mail-admin/delegation/save"><input type="hidden" name="_csrf_token" value="'.$e($this->csrf->getToken('mail_domain_delegation')->getValue()).'"><input type="hidden" name="request_id" value="'.$id.'"><fieldset><legend>このドメインで許可する操作</legend>';
            foreach(self::LABELS as $cap=>$label){$html.='<label><input type="checkbox" name="capabilities[]" value="'.$cap.'"'.(in_array($cap,$data['capabilities'],true)?' checked':'').'>'.$label.'</label>';}
            $html.='</fieldset><p>全て外して保存すると、このドメインの委任を取り消します。</p><label>管理者のアドレスを再入力<input name="confirm_admin" required autocomplete="off"></label><label>ドメイン名を再入力<input name="confirm_domain" required autocomplete="off"></label><button>この委任だけを保存</button></form>';
            return ConsoleController::page('ドメイン別の管理委任',$html);
        }catch(\Throwable){return ConsoleController::page('委任情報を取得できません',$html,503);}
    }
    public function save(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}$v=$r->request->all();
        if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($v['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_domain_delegation',$v['_csrf_token']))){return ConsoleController::page('アクセス拒否','',403);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        $p=$r->getSession()->get(self::KEY);$caps=$v['capabilities']??[];
        if(!is_array($p)||$p['actor']!==$actor->id||$p['epoch']!==$actor->epoch||!is_int($p['at'])||$p['at']>time()||time()-$p['at']>300||($v['request_id']??null)!==$p['request_id']||($v['confirm_admin']??null)!==$p['admin_label']||($v['confirm_domain']??null)!==$p['domain_label']||!is_array($caps)||count($caps)>count(self::LABELS)){return ConsoleController::page('対象と確認期限を確認してください','',400);}
        foreach($caps as $cap){if(!is_string($cap)||!isset(self::LABELS[$cap])){return ConsoleController::page('操作範囲を確認してください','',400);}}
        if(count(array_unique($caps))!==count($caps)){return ConsoleController::page('操作範囲を確認してください','',400);}
        $request=['admin_id'=>$p['admin_id'],'domain_id'=>$p['domain_id'],'revision'=>$p['revision'],'capabilities'=>$caps,'request_id'=>$p['request_id']];$r->getSession()->remove(self::KEY);
        try{
            $out=$this->store->save($actor,$request);if(($out['state']??null)!=='applied'){throw new \DomainException('result_unverified');}
            return ConsoleController::page('管理委任の保存結果','<p>指定ドメインの委任を保存しました。対象管理者の本人確認は失効しています。</p><p><a href="/mail-admin/delegation">委任を再取得</a></p>');
        }catch(\DomainException $error){$unknown=$error->getMessage()==='result_unverified';return ConsoleController::page($unknown?'保存結果が未確定です':'委任を保存できません','<p>再送せず現在の委任と監査履歴を確認してください。</p>',$unknown?503:409);}
        catch(\Throwable){return ConsoleController::page('保存結果を確認できません','<p>再送せず現在の委任と監査履歴を確認してください。</p>',503);}
    }
}
