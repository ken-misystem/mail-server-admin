<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response,JsonResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** Dedicated delegated views. Existing system-admin controllers/gates remain unchanged. */
final class ScopedAdminController
{
    public const LABELS=['mailboxes'=>'利用者','aliases'=>'受信エイリアス','forwards'=>'転送','usage'=>'メールボックス容量'];
    private const COLUMNS=['id'=>'ID','domain_id'=>'ドメインID','email'=>'メールアドレス','source'=>'送信元・転送元','destination'=>'配送先',
        'active'=>'状態','domain_name'=>'ドメイン','domain_active'=>'ドメインの状態','quota_bytes'=>'容量上限（バイト）'];
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly ScopedAdminReadStore $store,private readonly RateLimiterFactory $limiter) {}
    private function actor(Request $r):?AdminUser
    {
        $user=$this->tokens->getToken()?->getUser();
        return $user instanceof AdminUser&&AdminFactorGate::verified($user,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$user:null;
    }
    private static function page(string $title,string $body,int $status=200):Response
    {
        // Explicit empty groups; never display the system-wide menu in delegated views.
        return ConsoleController::page($title,'<nav aria-label="委任管理"><a href="/mail-admin/scoped">委任された管理</a> ／ <a href="/mail-admin/">本人確認・ログアウト</a></nav>'.$body,$status,null,[]);
    }
    private function entry(Request $r,bool $json):AdminUser|Response
    {
        $actor=$this->actor($r);
        if(!$actor){return $json?$this->json(['ok'=>false,'error'=>'not_authorized'],403):ConsoleController::factorRequired($r,$this->csrf);}
        if(!$r->isMethod('GET')){return $json?$this->json(['ok'=>false,'error'=>'method_not_allowed'],405):self::page('参照専用です','',405);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return $json?$this->json(['ok'=>false,'error'=>'too_many_attempts'],429):self::page('操作回数の上限です','',429);}
        return $actor;
    }
    private function json(array $body,int $status=200):JsonResponse
    {
        return new JsonResponse($body,$status,['Cache-Control'=>'no-store','X-Content-Type-Options'=>'nosniff','Referrer-Policy'=>'same-origin']);
    }
    /** A strict public projection also protects against a miswired/faulty storage adapter. */
    public static function row(string $section,array $row):array
    {
        ScopedAdminQuery::section($section);
        $fields=in_array($section,['mailboxes','usage'],true)?['id','domain_id','email','active','quota_bytes','domain_name','domain_active']:
            ['id','domain_id','source','destination','active','domain_name','domain_active'];
        if($section==='forwards'){$fields=array_values(array_diff($fields,['destination']));}
        $out=[];
        foreach($fields as $field){if(!is_string($row[$field]??null)||strlen($row[$field])>1024){throw new \UnexpectedValueException('invalid_public_row');}$out[$field]=$row[$field];}
        ScopedAdminQuery::id($out['id']);ScopedAdminQuery::id($out['domain_id']);
        foreach(['active','domain_active'] as $field){if(!in_array($out[$field],['0','1'],true)){throw new \UnexpectedValueException('invalid_public_state');}}
        if(isset($out['quota_bytes'])&&!preg_match('/^(?:0|[1-9][0-9]{0,19})$/D',$out['quota_bytes'])){throw new \UnexpectedValueException('invalid_public_quota');}
        if($section==='forwards'){$out['destinations']=ForwardPlan::targets($row['destinations']??[]);}
        if($section==='usage'){
            $out['usage']=null;$out['usage_reason']='quota_backend_unverified';
            $usage=$row['usage']??null;
            if(is_array($usage)&&is_int($usage['used_bytes_upper_bound']??null)&&$usage['used_bytes_upper_bound']>=0
                &&is_int($usage['observed_at']??null)&&$usage['observed_at']>time()-120&&$usage['observed_at']<=time()
                &&($usage['enforcement_verified']??null)===true){
                $out['usage']=['used_bytes_upper_bound'=>$usage['used_bytes_upper_bound'],'observed_at'=>$usage['observed_at'],'enforcement_verified'=>true];$out['usage_reason']=null;
            }elseif(in_array($row['usage_reason']??null,['quota_usage_stale','quota_binding_changed','quota_snapshot_invalid','quota_integer_range'],true)){$out['usage_reason']=$row['usage_reason'];}
        }
        return $out;
    }
    public function home(Request $r):Response
    {
        $actor=$this->entry($r,false);if($actor instanceof Response){return $actor;}$e=ConsoleController::escape(...);
        try{
            $domains=$this->store->domains($actor);if(count($domains)>10000){throw new \UnexpectedValueException('domain_bound');}
            $html='<p>操作を委任されたドメインだけを表示します。権限は各APIで再確認します。</p>';
            if(!$domains){$html.='<p>委任されているドメインはありません。</p>';}
            foreach($domains as $d){
                if(!is_array($d)||!is_string($d['id']??null)||!is_string($d['name']??null)||!is_array($d['capabilities']??null)){throw new \UnexpectedValueException('invalid_domain');}
                ScopedAdminQuery::id($d['id']);$html.='<section><h2>'.$e($d['name']).'</h2><ul>';
                foreach($d['capabilities'] as $cap){if(!is_string($cap)||!isset(DomainDelegationController::LABELS[$cap])){throw new \UnexpectedValueException('invalid_capability');}$html.='<li>'.$e(DomainDelegationController::LABELS[$cap]).'</li>';}
                $html.='</ul><p>';
                foreach(ScopedAdminQuery::SECTIONS as $section=>$cap){if(in_array($cap,$d['capabilities'],true)){$html.='<a href="/mail-admin/scoped/'.$section.'?domain_id='.$e($d['id']).'">'.$e(self::LABELS[$section]).'を表示</a> ';}}
                foreach(['mailbox'=>'mailbox.create','alias'=>'alias.create'] as $kind=>$required){if(in_array($required,$d['capabilities'],true)){$html.='<a href="/mail-admin/scoped/create/'.$kind.'?domain_id='.$e($d['id']).'">'.($kind==='mailbox'?'利用者登録':'受信エイリアス登録').'</a> ';}}
                if(in_array('csv.preview',$d['capabilities'],true)){$html.='<a href="/mail-admin/bulk">CSV一括登録</a>';}
                $html.='</p></section>';
            }
            return self::page('委任された管理',$html);
        }catch(\Throwable){return self::page('委任情報を取得できません','<p>再読み込みしても解消しない場合は全体管理者へ連絡してください。</p>',503);}
    }
    public function show(Request $r,string $section):Response
    {
        $actor=$this->entry($r,false);if($actor instanceof Response){return $actor;}
        try{ScopedAdminQuery::section($section);$filter=ScopedAdminQuery::filter($r->query->all());}
        catch(\DomainException){return self::page('検索条件を確認してください','',400);}
        try{
            $data=$this->store->listing($actor,$section,$filter);$rows=$this->listingRows($section,$data,(int)$filter['size']);$e=ConsoleController::escape(...);
            $html='<form method="get"><label>ドメインID（0は委任範囲全体）<input name="domain_id" value="'.$e($filter['domain_id']).'"></label><label>メールアドレスの前方一致<input name="prefix" maxlength="320" value="'.$e($filter['prefix']).'"></label><label>状態<select name="state">';
            foreach(['any'=>'全て','1'=>'有効','0'=>'無効'] as $value=>$label){$html.='<option value="'.$value.'"'.((string)$value===$filter['state']?' selected':'').'>'.$label.'</option>';}
            $html.='</select></label><label>表示件数<select name="size">';foreach(['25','50','100'] as $size){$html.='<option'.($size===$filter['size']?' selected':'').'>'.$size.'</option>';}
            $html.='</select></label><button>検索</button></form><p>権限のないドメインは件数・詳細とも表示しません。</p>';
            if(!$rows){$html.='<p>該当する項目はありません。</p>';}
            foreach($rows as $row){if($section==='forwards'){$html.='<p><a href="/mail-admin/forward/'.$e($row['id']).'">'.$e($row['source']).'の転送設定</a></p>';}$html.='<details><summary>'.$e($row['email']??$row['source']).'（'.($row['active']==='1'?'有効':'無効').'）</summary>'.($this->description($row).(in_array($section,['mailboxes','aliases'],true)?'<p><a href="/mail-admin/scoped/edit/'.($section==='mailboxes'?'mailbox':'alias').'/'.$e($row['id']).'">個別設定</a></p>':'')).'</details>';}
            if($data['next_after']!==null){$link='/mail-admin/scoped/'.$section.'?'.http_build_query(array_replace($filter,['after'=>$data['next_after']]),'','&',PHP_QUERY_RFC3986);$html.='<p><a rel="next" href="'.$e($link).'">次の'.$e($filter['size']).'件</a></p>';}
            $html.='<p><a href="/mail-admin/scoped/'.$section.'?'. $e(http_build_query(array_replace($filter,['after'=>'0']),'','&',PHP_QUERY_RFC3986)).'">先頭へ戻る</a></p>';
            return self::page('委任範囲：'.self::LABELS[$section],$html);
        }catch(\DomainException $error){return $this->htmlFailure($error);}
        catch(\Throwable){return self::page('一覧を取得できません','',503);}
    }
    private function description(array $row):string
    {
        $e=ConsoleController::escape(...);$html='<dl>';
        foreach(self::COLUMNS as $field=>$label){if(isset($row[$field])){$value=$row[$field];if(in_array($field,['active','domain_active'],true)){$value=$value==='1'?'有効':'無効';}if($field==='quota_bytes'&&$value==='0'){$value='無制限';}$html.='<dt>'.$label.'</dt><dd>'.$e($value).'</dd>';}}
        if(array_key_exists('usage',$row)){$html.='<dt>計測値</dt><dd>'.($row['usage']===null?'確認できません（未計測・期限切れ・設定差異）':$e((string)$row['usage']['used_bytes_upper_bound']).'バイト ／ '.$e(gmdate('Y-m-d H:i:s',$row['usage']['observed_at'])).' UTC').'</dd>';}
        if(isset($row['destinations'])){$html.='<dt>転送先</dt><dd>'.($row['destinations']?implode('<br>',array_map($e,$row['destinations'])):'未設定').'</dd>';}
        return $html.'</dl>';
    }
    private function listingRows(string $section,array $data,int $size):array
    {
        if(!is_array($data['rows']??null)||count($data['rows'])>$size||!array_key_exists('next_after',$data)){throw new \UnexpectedValueException('invalid_public_list');}
        if($data['next_after']!==null){ScopedAdminQuery::id($data['next_after']);if(!$data['rows']||$data['next_after']!==($data['rows'][count($data['rows'])-1]['id']??null)){throw new \UnexpectedValueException('invalid_public_cursor');}}
        return array_map(static fn(array $row):array=>self::row($section,$row),$data['rows']);
    }
    private function htmlFailure(\DomainException $error):Response
    {
        return $error->getMessage()==='admin_session_changed'?self::page('本人確認をやり直してください','',403):self::page('一覧を取得できません','',503);
    }
    public function api(Request $r,string $section,?string $id=null):Response
    {
        $actor=$this->entry($r,true);if($actor instanceof Response){return $actor;}
        try{ScopedAdminQuery::section($section);if($id!==null){ScopedAdminQuery::id($id);if($r->query->count()){throw new \DomainException('invalid_filter');}}else{$filter=ScopedAdminQuery::filter($r->query->all());}}
        catch(\DomainException){return $this->json(['ok'=>false,'error'=>'invalid_query'],400);}
        try{
            if($id!==null){$row=$this->store->record($actor,$section,$id);return $row===null?$this->json(['ok'=>false,'error'=>'not_found'],404):$this->json(['ok'=>true,'record'=>self::row($section,$row)]);}
            $data=$this->store->listing($actor,$section,$filter);$rows=$this->listingRows($section,$data,(int)$filter['size']);
            return $this->json(['ok'=>true,'rows'=>$rows,'next_after'=>$data['next_after'],'filter'=>$filter]);
        }catch(\Throwable $error){return $this->json(['ok'=>false,'error'=>$error instanceof \DomainException&&$error->getMessage()==='admin_session_changed'?'not_authorized':'storage_unavailable'],$error instanceof \DomainException&&$error->getMessage()==='admin_session_changed'?403:503);}
    }
}
