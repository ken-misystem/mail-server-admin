<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** Scoped write forms with live storage authority; no expansion of global APIs. */
final class ScopedOperationsController
{
    private const KEY='mail_scoped_operations';
    private const TITLES=['mailbox_create'=>'利用者を登録','mailbox_state'=>'利用者の有効・無効を変更','mailbox_password'=>'パスワードを変更',
        'mailbox_quota'=>'容量上限を変更','alias_create'=>'受信エイリアスを登録','alias_state'=>'受信エイリアスの有効・無効を変更','alias_destination'=>'受信エイリアスの配送先を変更'];
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly ScopedAdminReadStore $reads,private readonly ScopedWriteStore $writes,private readonly RateLimiterFactory $limiter){}
    private static function page(string $title,string $body,int $status=200):Response
    {return ConsoleController::page($title,'<p><a href="/mail-admin/scoped">委任された管理へ戻る</a></p>'.$body,$status,null,[]);}
    private function actor(Request $r):?AdminUser
    {$u=$this->tokens->getToken()?->getUser();return $u instanceof AdminUser&&AdminFactorGate::verified($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$u:null;}
    private function domains(AdminUser $actor):array
    {
        $rows=$this->reads->domains($actor);if(count($rows)>10000){throw new \DomainException('domain_inventory_bound');}$out=[];
        foreach($rows as $row){ScopedAdminQuery::id($row['id']);if(!is_array($row['capabilities'])||!is_string($row['name'])){throw new \DomainException('invalid_domain');}$out[$row['id']]=$row;}
        return $out;
    }
    private function permit(AdminUser $actor,array $domains,string $domain,string $cap):void
    {
        if(!isset($domains[$domain])||(!$actor->systemAdmin&&!in_array($cap,$domains[$domain]['capabilities'],true))){throw new \DomainException('domain_not_delegated');}
    }
    private function form(Request $r,AdminUser $actor,string $action,array $target):string
    {
        $e=ConsoleController::escape(...);$pool=$r->getSession()->get(self::KEY,[]);if(!is_array($pool)){$pool=[];}
        $pool=array_filter($pool,static fn($p):bool=>is_array($p)&&is_int($p['at']??null)&&time()-300<$p['at']&&$p['at']<=time());
        while(count($pool)>=24){array_shift($pool);}
        $nonce=bin2hex(random_bytes(16));$pool[$nonce]=['actor'=>$actor->id,'epoch'=>$actor->epoch,'at'=>time(),'action'=>$action,'target'=>$target];$r->getSession()->set(self::KEY,$pool);
        $html='<form method="post" action="/mail-admin/scoped/operation/'.$action.'"><fieldset><legend>'.self::TITLES[$action].'</legend><input type="hidden" name="_csrf_token" value="'.$e($this->csrf->getToken('mail_scoped_operation')->getValue()).'"><input type="hidden" name="nonce" value="'.$nonce.'">';
        if(str_ends_with($action,'_create')){$html.='<label>アドレスの@より前<input name="local_part" maxlength="64" required></label>';}
        if(in_array($action,['mailbox_create','mailbox_password'],true)){$html.='<label>新しいパスワード<input type="password" name="new_password" minlength="12" maxlength="1024" autocomplete="new-password" required></label><label>パスワードを再入力<input type="password" name="repeat_password" minlength="12" maxlength="1024" autocomplete="new-password" required></label>';}
        if(in_array($action,['alias_create','alias_destination'],true)){$html.='<label>配送先の利用者ID<input name="destination_id" inputmode="numeric" pattern="[1-9][0-9]*" required></label><p><a href="/mail-admin/scoped/mailboxes">利用者一覧で配送先を検索</a>。別ドメインへの配送先指定には両方のドメインの変更権限が必要です。</p>';}
        if(str_ends_with($action,'_state')){$html.='<label>変更後の状態<select name="enabled"><option value="0">無効</option><option value="1">有効</option></select></label>';}
        if($action==='mailbox_quota'){$html.='<label>変更後の上限<select name="mode"><option value="limited">上限を指定</option><option value="unlimited">無制限</option></select></label><label>上限（KiB）<input name="limit_kib" inputmode="numeric" pattern="[1-9][0-9]*"></label><label><input type="checkbox" name="confirm_unlimited" value="1">無制限への変更を確認しました</label><p>現在の上限：'.$e($target['quota_bytes']).'バイト。保存時に最新の使用量と実効性を再確認します。</p>';}
        $html.='<label>対象の'.(str_ends_with($action,'_create')?'ドメイン名':'アドレス').'を再入力<input name="confirm_target" autocomplete="off" required></label><button>'.self::TITLES[$action].'</button></fieldset></form>';
        return $html;
    }
    public function create(Request $r,string $kind):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        if(!$r->isMethod('GET')||!in_array($kind,['mailbox','alias'],true)){return self::page('アクセス拒否','',403);}
        try{
            $domain=ScopedAdminQuery::id($r->query->get('domain_id'));$domains=$this->domains($actor);$action=$kind.'_create';$this->permit($actor,$domains,$domain,ScopedMutation::OPERATIONS[$action]);
            if($domains[$domain]['active']!=='1'){throw new \DomainException('inactive_domain');}
            return self::page(self::TITLES[$action],'<p>対象ドメイン：'.ConsoleController::escape($domains[$domain]['name']).'。初期状態は無効です。</p>'.$this->form($r,$actor,$action,['domain_id'=>$domain,'label'=>$domains[$domain]['name']]));
        }catch(\DomainException){return self::page('対象または権限を確認してください','',403);}catch(\Throwable){return self::page('登録画面を取得できません','',503);}
    }
    public function edit(Request $r,string $kind,string $id):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        if(!$r->isMethod('GET')||!in_array($kind,['mailbox','alias'],true)){return self::page('アクセス拒否','',403);}
        try{
            ScopedAdminQuery::id($id);$row=$this->reads->record($actor,$kind==='mailbox'?'mailboxes':'aliases',$id);if($row===null){return self::page('対象がありません','',404);}
            $domains=$this->domains($actor);$domain=$row['domain_id'];$label=$row['email']??$row['source'];$html='<p>対象：'.ConsoleController::escape($label).'</p>';$forms=0;
            foreach($kind==='mailbox'?['mailbox_state','mailbox_password','mailbox_quota']:['alias_state','alias_destination'] as $action){
                try{$this->permit($actor,$domains,$domain,ScopedMutation::OPERATIONS[$action]);}catch(\DomainException){continue;}
                $html.=$this->form($r,$actor,$action,['id'=>$id,'domain_id'=>$domain,'label'=>$label,'quota_bytes'=>$row['quota_bytes']??'0']);++$forms;
            }
            return self::page('個別設定',$html.($forms?'':'<p>この対象の変更権限はありません。</p>'));
        }catch(\DomainException){return self::page('対象または権限を確認してください','',403);}catch(\Throwable){return self::page('個別設定を取得できません','',503);}
    }
    public function apply(Request $r,string $action):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        $input=$r->request->all();
        if(!$r->isMethod('POST')||!isset(ScopedMutation::OPERATIONS[$action])||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_scoped_operation',$input['_csrf_token']))){return self::page('アクセス拒否','',403);}
        if(strlen($r->getContent())>16384){return self::page('入力が大きすぎます','',413);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return self::page('操作回数の上限です','',429);}
        $pool=$r->getSession()->get(self::KEY,[]);$nonce=$input['nonce']??null;$p=is_string($nonce)&&is_array($pool)?($pool[$nonce]??null):null;
        if(!is_array($p)||$p['actor']!==$actor->id||$p['epoch']!==$actor->epoch||$p['action']!==$action||!is_int($p['at'])||$p['at']>time()||time()-$p['at']>300){return self::page('確認期限または対象を確認してください','<p>個別設定を取得し直してください。</p>',400);}
        unset($pool[$nonce]);$r->getSession()->set(self::KEY,$pool); // consume BEFORE hashing/DB, including uncertain outcomes
        try{
            $target=$p['target'];AdminMailPolicy::confirmation($target['label'],is_string($input['confirm_target']??null)?$input['confirm_target']:'');
            $input['domain_id']=$target['domain_id'];$input['id']=$target['id']??'0';$input['confirm_target']=$target['label'];$input['confirm']=$target['label'];$input['expected_bytes']=$target['quota_bytes']??'0';
            $mutation=ScopedMutation::fromForm($action,$input);unset($input);$out=$this->writes->apply($actor,$mutation,$nonce);
            if(($out['state']??null)!=='applied'||($out['action']??null)!==$action||!is_string($out['target_id']??null)){throw new \DomainException('result_unverified');}
            return self::page('個別操作の保存結果','<p>保存しました。対象ID：'.ConsoleController::escape($out['target_id']).'</p><p>容量上限の変更は、既存の容量収集処理で適用確認します。</p>');
        }catch(\DomainException $error){$unknown=$error->getMessage()==='result_unverified';return self::page($unknown?'保存結果が未確定です':'操作を保存できません','<p>再送せず、現在の対象と管理操作履歴を確認してください。</p>',$unknown?503:409);}
        catch(\Throwable){return self::page('保存結果を確認できません','<p>再送せず、現在の対象と管理操作履歴を確認してください。</p>',503);}
    }
}
