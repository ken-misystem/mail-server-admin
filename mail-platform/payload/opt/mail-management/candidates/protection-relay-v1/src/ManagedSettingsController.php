<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** Small typed forms; no raw JSON, commands, secrets, or global filter bypass. */
final class ManagedSettingsController
{
    private const SESSION='mail_feature_settings_forms';
    private const TITLES=['access'=>'許否リスト','spam'=>'迷惑メール判定設定'];
    private const REASONS=['abuse'=>'不正利用','malware'=>'危険な通信','operator'=>'管理者による判断','migration'=>'移行時の互換対応'];
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly ManagedSettingsStore $store,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $r):?AdminUser
    {$u=$this->tokens->getToken()?->getUser();return $u instanceof AdminUser&&$u->systemAdmin&&AdminFactorGate::verified($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$u:null;}
    private static function title(string $kind):string{return self::TITLES[$kind]??throw new \DomainException('invalid_setting_kind');}
    private static function number(mixed $value,int $max,bool $zero=true):int
    {if(!is_string($value)||!preg_match($zero?'/^(?:0|[1-9][0-9]{0,9})$/D':'/^[1-9][0-9]{0,9}$/D',$value)||(int)$value>$max){throw new \DomainException('invalid_number');}return (int)$value;}
    private function base(string $kind,string $html,int $status=200):Response{return ConsoleController::page(self::title($kind),$html,$status);}
    public function show(Request $r,string $kind):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}if(!$r->isMethod('GET')||!isset(self::TITLES[$kind])){return ConsoleController::page('アクセス拒否','',403);}
        try{
            $saved=$this->store->lookup($actor,$kind);$payload=ManagedSettings::validate($kind,$saved['payload']);$key=$kind==='access'?'rules':'profiles';$rows=$payload[$key];$page=self::number((string)$r->query->get('page','1'),10000,false);$size=(string)$r->query->get('size','25');if(!in_array($size,['25','50','100'],true)){throw new \DomainException('invalid_page');}
            $prefix=$r->query->get('q','');if(!is_string($prefix)||strlen($prefix)>254||preg_match('/[\x00-\x1f\x7f]/',$prefix)){throw new \DomainException('invalid_search');}
            $filtered=[];foreach($rows as $index=>$row){if($prefix===''||str_starts_with((string)($row['value']??$row['domain_id']),$prefix)){$filtered[$index]=$row;}}
            $visible=array_slice($filtered,($page-1)*(int)$size,(int)$size,true);$e=ConsoleController::escape(...);$pool=$r->getSession()->get(self::SESSION,[]);if(!is_array($pool)){$pool=[];}$pool=array_filter($pool,static fn($item)=>is_array($item)&&is_int($item['at']??null)&&$item['at']<=time()&&$item['at']>time()-300);while(count($pool)>=8){array_shift($pool);}
            $nonce=bin2hex(random_bytes(16));$pool[$nonce]=['actor'=>$actor->id,'epoch'=>$actor->epoch,'kind'=>$kind,'revision'=>$saved['revision'],'indices'=>array_keys($visible),'at'=>time()];$r->getSession()->set(self::SESSION,$pool);
            $hidden='<input type="hidden" name="_csrf_token" value="'.$e($this->csrf->getToken('mail_feature_settings')->getValue()).'"><input type="hidden" name="nonce" value="'.$nonce.'">';
            $html='<p>保存と反映は別に確認します。受信・認証・TLS・外部中継の既存制限は維持します。</p><p><a href="/mail-admin/manage?section=domains">対象ドメインを検索</a>。ドメインIDの0は全体です。</p>';
            if($kind==='access'){$html.='<p>「追加拒否の例外」は、この画面の追加拒否だけの例外です。認証なし中継、証明書省略、既存の迷惑メール判定の回避は許可しません。期限切れの規則は適用しません。</p>';}
            else{$html.='<p>通常受信のグレーリスト・迷惑メール表示・受信拒否の点数を順に指定します。既存の認証済み送信・POP取込み用の例外、迷惑メールフォルダー振分け・日報は維持します。1通に複数ドメインの宛先がある場合は、受信拒否点数が最も低い設定を使い、同点は迷惑メール表示・グレーリストの順で比較します。</p>';}
            $html.='<form method="get"><label>'.($kind==='access'?'値の前方一致':'ドメインIDの前方一致').'<input name="q" value="'.$e($prefix).'" maxlength="254"></label><label>表示件数<select name="size">';foreach(['25','50','100']as $value){$html.='<option'.($size===$value?' selected':'').'>'.$value.'</option>';}$html.='</select></label><button>検索</button></form><p>該当'.count($filtered).'件 ／ 設定世代'.$e((string)$saved['revision']).'</p>';
            foreach($visible as $index=>$row){$html.='<details><summary>'.$e((string)($row['value']??('ドメインID '.$row['domain_id']))).'</summary><dl>';
                $labels=$kind==='access'?['kind'=>'種類','scope'=>'適用箇所','value'=>'対象','effect'=>'動作','expires'=>'期限','domain_id'=>'対象ドメインID','reason'=>'理由']:['domain_id'=>'対象ドメインID','greylist'=>'グレーリスト','add_header'=>'迷惑メール表示','reject'=>'受信拒否'];
                foreach($labels as $field=>$label){$value=$row[$field];$value=match($field){'reason'=>self::REASONS[$value],'kind'=>['ip'=>'IP範囲','address'=>'メールアドレス','domain'=>'ドメイン'][$value],'scope'=>['client'=>'接続元IP','sender'=>'送信元','recipient'=>'宛先','spam'=>'追加の迷惑メール拒否'][$value],'effect'=>$value==='deny'?'拒否':'追加拒否の例外','expires'=>$value===0?'期限なし':gmdate('Y-m-d H:i:s',$value).' UTC',default=>(string)$value};$html.='<dt>'.$label.'</dt><dd>'.$e($value).'</dd>';}$html.='</dl>';
                if($kind==='access'||$row['domain_id']!==0){$confirm=$kind==='access'?$row['value']:(string)$row['domain_id'];$html.='<form method="post">'.$hidden.'<input type="hidden" name="action" value="remove"><input type="hidden" name="index" value="'.$index.'"><label>削除する対象を再入力<input name="confirm" required></label><p>確認値：'.$e($confirm).'</p><button>この設定を削除</button></form>';}$html.='</details>';}
            if($page>1){$html.='<a href="?'.$e(http_build_query(['q'=>$prefix,'size'=>$size,'page'=>$page-1])).'">前のページ</a> ';}if($page*(int)$size<count($filtered)){$html.='<a href="?'.$e(http_build_query(['q'=>$prefix,'size'=>$size,'page'=>$page+1])).'">次のページ</a>';}
            $html.='<h2>'.($kind==='access'?'規則を追加':'点数を設定').'</h2><form method="post">'.$hidden.'<input type="hidden" name="action" value="set">';
            if($kind==='access'){$html.='<label>種類<select name="type"><option value="ip">IP範囲（CIDR）</option><option value="address">メールアドレス</option><option value="domain">ドメイン</option></select></label><label>適用箇所<select name="scope"><option value="client">接続元IP</option><option value="sender">送信元</option><option value="recipient">宛先</option><option value="spam">追加の迷惑メール拒否</option></select></label><label>対象<input name="value" maxlength="254" required></label><label>動作<select name="effect"><option value="deny">拒否</option><option value="allow">追加拒否の例外</option></select></label><label>有効時間（0は期限なし）<input name="hours" type="number" min="0" max="8760" value="24" required></label><label>理由<select name="reason">';foreach(self::REASONS as $value=>$label){$html.='<option value="'.$value.'">'.$label.'</option>';}$html.='</select></label>';}
            else{foreach(['greylist'=>'グレーリスト','add_header'=>'迷惑メール表示','reject'=>'受信拒否']as $field=>$label){$html.='<label>'.$label.'の点数<input name="'.$field.'" type="number" min="0" max="100" step="0.1" required></label>';}}
            $html.='<label>対象ドメインID（0は全体）<input name="domain_id" inputmode="numeric" value="0" required></label><label>確認のため「保存」と入力<input name="confirm" required></label><button>設定を保存</button></form>';
            return $this->base($kind,$html);
        }catch(\DomainException){return $this->base($kind,'<p>入力条件または現在の設定を確認してください。</p>',400);}catch(\Throwable){return $this->base($kind,'<p>設定を取得できません。</p>',503);}
    }
    public function save(Request $r,string $kind):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}if(!isset(self::TITLES[$kind])){return ConsoleController::page('アクセス拒否','',403);}$input=$r->request->all();
        if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_feature_settings',$input['_csrf_token']))){return $this->base($kind,'',403);}
        if(strlen($r->getContent())>8192){return $this->base($kind,'<p>入力が大きすぎます。</p>',413);}if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return $this->base($kind,'<p>操作回数の上限です。</p>',429);}
        $nonce=$input['nonce']??null;$pool=$r->getSession()->get(self::SESSION,[]);$prior=is_string($nonce)&&is_array($pool)?($pool[$nonce]??null):null;
        if(!is_array($prior)||$prior['actor']!==$actor->id||$prior['epoch']!==$actor->epoch||$prior['kind']!==$kind||!is_int($prior['at'])||$prior['at']>time()||$prior['at']<time()-300){return $this->base($kind,'<p>確認期限または対象を確認し、画面を取得し直してください。</p>',400);}
        unset($pool[$nonce]);$r->getSession()->set(self::SESSION,$pool);
        try{
            $saved=$this->store->lookup($actor,$kind);if($saved['revision']!==$prior['revision']){throw new \DomainException('stale_revision');}$payload=$saved['payload'];$key=$kind==='access'?'rules':'profiles';
            if(($input['action']??null)==='remove'){$index=self::number($input['index']??null,10000);if(!in_array($index,$prior['indices'],true)||!isset($payload[$key][$index])){throw new \DomainException('unknown_row');}$row=$payload[$key][$index];$confirm=$kind==='access'?$row['value']:(string)$row['domain_id'];if(!is_string($input['confirm']??null)||!hash_equals($confirm,$input['confirm'])||($kind==='spam'&&$row['domain_id']===0)){throw new \DomainException('confirmation_required');}array_splice($payload[$key],$index,1);}
            elseif(($input['action']??null)==='set'){
                if(($input['confirm']??null)!=='保存'){throw new \DomainException('confirmation_required');}$domain=self::number($input['domain_id']??null,4294967295);
                if($kind==='access'){
                    $hours=self::number($input['hours']??null,8760);foreach(['type','scope','value','effect','reason']as $field){if(!is_string($input[$field]??null)){throw new \DomainException('invalid_input');}}
                    $payload['rules'][]=['kind'=>$input['type'],'scope'=>$input['scope'],'value'=>strtolower(trim($input['value'])),'effect'=>$input['effect'],'expires'=>$hours===0?0:time()+3600*$hours,'domain_id'=>$domain,'reason'=>$input['reason']];
                }else{$row=['domain_id'=>$domain];foreach(['greylist','add_header','reject']as $field){if(!is_string($input[$field]??null)||!preg_match('/^(?:0|[1-9][0-9]?|100)(?:\.[0-9])?$/D',$input[$field])){throw new \DomainException('invalid_score');}$row[$field]=(float)$input[$field];}$found=false;foreach($payload['profiles']as &$profile){if($profile['domain_id']===$domain){$profile=$row;$found=true;}}unset($profile);if(!$found){$payload['profiles'][]=$row;}}
            }else{throw new \DomainException('invalid_action');}
            $payload=ManagedSettings::validate($kind,$payload);$out=$this->store->save($actor,$kind,$prior['revision'],$payload,$nonce);if(($out['state']??null)!=='saved_pending_publication'||($out['kind']??null)!==$kind||($out['revision']??null)!==$prior['revision']+1){throw new \DomainException('result_unverified');}
            return $this->base($kind,'<p>保存しました。反映処理による確認待ちです。</p><p><a href="/mail-admin/feature-settings/'.$kind.'">設定に戻る</a></p>');
        }catch(\DomainException $error){return $this->base($kind,'<p>保存できません。再送せず、現在の設定と管理操作履歴を確認してください。</p>',$error->getMessage()==='result_unverified'?503:409);}catch(\Throwable){return $this->base($kind,'<p>保存結果が未確定です。再送せず、現在の設定と管理操作履歴を確認してください。</p>',503);}
    }
}
