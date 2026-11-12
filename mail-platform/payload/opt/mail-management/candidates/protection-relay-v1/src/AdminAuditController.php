<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfTokenManagerInterface,CsrfToken};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class AdminAuditController
{
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly AdminAuditStore $store,private readonly RateLimiterFactory $limiter,private readonly ?\Closure $diagnostic=null) {}
    public function show(Request $request): Response
    {
        if(!in_array($request->getMethod(),['GET','POST'],true))return new Response('',405,['Allow'=>'GET, POST','Cache-Control'=>'no-store']);
        $actor=$this->tokens->getToken()?->getUser();
        if(!$actor instanceof AdminUser||!$actor->active||!$actor->systemAdmin||$request->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN)return ConsoleController::page('アクセス拒否','',403);
        if(!AdminFactorGate::permits($actor,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time()))return ConsoleController::factorRequired($request,$this->csrf);
        $query=new AdminAuditQuery();
        if($request->isMethod('POST')){
            $v=$request->request->all();
            if(strlen($request->getContent())>2048||$request->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($v['_token']??null)
                ||!$this->csrf->isTokenValid(new CsrfToken('mail_admin_audit',$v['_token'])))return ConsoleController::page('検索を確認できません','',403);
            try {$query=AdminAuditQuery::fromArray($v);}catch(\DomainException){return ConsoleController::page('検索条件が不正です','',400);}
        }
        if($request->query->count()>0)return ConsoleController::page('検索条件が不正です','<p>画面の検索フォームを使用してください。</p>',400);
        if(!$this->limiter->create($actor->id)->consume()->isAccepted())return ConsoleController::page('検索回数の上限です','<p>1分間に20回までです。</p>',429);
        $token=$this->csrf->getToken('mail_admin_audit')->getValue();
        try {$result=$this->store->search($actor,$query,time());}
        catch(\Throwable $e){
            // Record safe structural detail, never PDO message, trace arguments or DSN.
            $details=self::failure($e);
            try {if($this->diagnostic!==null)($this->diagnostic)($details);else error_log(json_encode($details,JSON_THROW_ON_ERROR));}catch(\Throwable){}
            return ConsoleController::page('管理操作履歴',self::nav().self::form($query,$token).'<p role="alert">履歴を取得できません。権限・スキーマ・接続障害を確認してください。履歴がないという意味ではありません。</p>',503);
        }
        return ConsoleController::page('管理操作履歴',self::nav().self::form($query,$token).self::render($result,$query,$token));
    }
    public static function failure(\Throwable $e): array
    {
        if($e instanceof AdminAuditReadFailure){
            $out=self::failure($e->getPrevious());$out['stage']=$e->stage;
            $out['cleanup_failure']=$e->cleanup!==null?self::failure($e->cleanup):null;return $out;
        }
        $names=[\PDOException::class=>'PDOException',\DomainException::class=>'DomainException',\TypeError::class=>'TypeError',\RuntimeException::class=>'RuntimeException'];
        $reason=$e instanceof \DomainException&&in_array($e->getMessage(),['audit_not_authorized','audit_transaction','audit_actor_query','audit_actor_changed','audit_rows_query','audit_row_bound','audit_row_shape','audit_close_failed','audit_unavailable'],true)?$e->getMessage():'unclassified_read_failure';
        $out=['component'=>'management_admin_audit','stage'=>'read','class'=>$names[get_class($e)]??'OtherThrowable','reason'=>$reason,
            'sqlstate'=>null,'native_code'=>null,'frames'=>[],'raw_error_output'=>false];
        if($e instanceof \PDOException){$info=$e->errorInfo;
            if(is_array($info)&&is_string($info[0]??null)&&preg_match('/^[A-Z0-9]{5}$/D',$info[0]))$out['sqlstate']=$info[0];
            if(is_array($info)&&is_int($info[1]??null)&&$info[1]>=0&&$info[1]<=99999)$out['native_code']=$info[1];
        }
        foreach(array_merge([['file'=>$e->getFile(),'line'=>$e->getLine()]],$e->getTrace())as$f){
            if(in_array(basename($f['file']??''),['AdminAuditController.php','PdoAdminAuditStore.php','AdminAuditQuery.php'],true)){
                $out['frames'][]=['source'=>basename($f['file']),'line'=>(int)($f['line']??0)];if(count($out['frames'])===6)break;
            }
        }
        return $out;
    }
    private static function e(mixed $v): string {return ConsoleController::escape((string)$v);}
    private static function nav(): string {return '<p><a href="/mail-admin/">メール管理</a> ／ <a href="/mail-admin/logs">各種ログ</a> ／ <a href="/mail-admin/operations-status">稼働状況</a></p>';}
    private static function form(AdminAuditQuery $q,string $token,?string $before=null): string
    {
        $body='<form method="post" action="/mail-admin/audit"><input type="hidden" name="_token" value="'.self::e($token).'">';
        if($before!==null){
            foreach(['hours'=>$q->hours,'action'=>$q->action,'type'=>$q->type,'actor'=>$q->actor,'target'=>$q->target,'before'=>$before]as$k=>$v)$body.='<input type="hidden" name="'.$k.'" value="'.self::e($v).'">';
            return $body.'<button type="submit">条件を保って、さらに前の記録を確認</button></form>';
        }
        foreach(['hours'=>['期間',[24=>'直近24時間',168=>'直近7日間',720=>'直近30日間'],(string)$q->hours],
            'action'=>['操作',[''=>'すべて']+AdminAuditQuery::ACTIONS,$q->action],'type'=>['対象区分',[''=>'すべて']+AdminAuditQuery::TYPES,$q->type]]as$name=>[$label,$options,$selected]){
            $body.='<label>'.$label.'<select name="'.$name.'">';foreach($options as$v=>$text)$body.='<option value="'.self::e($v).'"'.((string)$v===$selected?' selected':'').'>'.self::e($text).'</option>';$body.='</select></label>';
        }
        foreach(['actor'=>['実行管理者ID',$q->actor],'target'=>['対象ID',$q->target]]as$name=>[$label,$value])$body.='<label>'.$label.'<input name="'.$name.'" value="'.self::e($value).'" maxlength="20" inputmode="numeric" autocomplete="off"></label>';
        return $body.'<button type="submit">検索・更新</button></form><p>条件はURLに含めません。自動更新は行いません。管理画面から記録された完了操作だけを表示します。失敗・SSH・本人管理操作の網羅記録ではありません。</p>';
    }
    public static function render(array $r,AdminAuditQuery $q,string $token): string
    {
        $body='<p>今回確認した範囲：'.self::e($r['scanned']).'件 ／ 一致：'.count($r['rows']).'件。1回最大200件を調べ、最大50件を表示します。</p><table><thead><tr><th>記録ID</th><th>日時（JST）</th><th>実行管理者ID</th><th>操作</th><th>対象区分／ID</th></tr></thead><tbody>';
        foreach($r['rows']as$row){
            $date=(new \DateTimeImmutable('@'.$row['occurred_at']))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y-m-d H:i:s');
            $body.='<tr><td>'.self::e($row['id']).'</td><td>'.self::e($date).'</td><td>'.self::e($row['admin_id']??'未記録（削除済みを含む）').'</td><td>'.self::e(AdminAuditQuery::ACTIONS[$row['action']]??'未対応の操作').'</td><td>'.self::e(AdminAuditQuery::TYPES[$row['target_type']]??'未対応の区分').' ／ '.self::e($row['target_id']??'未記録').'</td></tr>';
        }
        if(!$r['rows'])$body.='<tr><td colspan="5">今回確認した範囲には一致する記録がありません。全期間の不存在を示すものではありません。</td></tr>';
        $body.='</tbody></table>';
        if($r['next_before']!==null)$body.='<p role="status">前の記録があります。検索条件が一致しない場合も、続きから確認できます。</p>'.self::form($q,$token,$r['next_before']);
        return $body;
    }
}
