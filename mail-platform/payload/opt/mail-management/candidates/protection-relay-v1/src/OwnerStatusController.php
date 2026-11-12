<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;
final class OwnerStatusController
{
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly OwnerStatusStore $store,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $r):?AdminUser{$u=$this->tokens->getToken()?->getUser();return $u instanceof AdminUser&&AdminFactorGate::permits($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$u:null;}
    public function show(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        $v=$r->query->all();$kind=$v['kind']??'mailbox';$q=$v['q']??'';$domain=$v['domain']??'';$page=$v['page']??'1';$size=$v['size']??'25';
        if(!is_string($kind)||!in_array($kind,['mailbox','legacy'],true)||!is_string($q)||strlen($q)>254||!is_string($domain)||strlen($domain)>253
            ||!is_string($page)||!preg_match('/^[1-9][0-9]{0,4}$/D',$page)||(int)$page>40000||!is_string($size)||!in_array($size,['25','50','100'],true)){return ConsoleController::page('検索条件を確認してください','',400);}
        try{
            $data=$this->store->browse(['kind'=>$kind,'q'=>$q,'domain'=>$domain,'page'=>(int)$page,'size'=>(int)$size]);
            if(!is_int($data['total']??null)||$data['total']<0||$data['total']>1000000||!is_array($data['rows']??null)||count($data['rows'])>(int)$size||!is_int($data['observed_at']??null)||abs(time()-$data['observed_at'])>120){throw new \UnexpectedValueException('owner_snapshot');}
            $e=ConsoleController::escape(...);$html='<p>DATA判定時に確保した受付予約数です。配送完了・到着数ではありません。停止・再開で既存の計上を消去しません。</p><form method="get"><label>区分<select name="kind">';
            foreach(['mailbox'=>'通常メールボックス','legacy'=>'旧SMTP認証ID'] as $key=>$label){$html.='<option value="'.$key.'"'.($kind===$key?' selected':'').'>'.$label.'</option>';}
            $html.='</select></label><label>アドレス・認証IDの前方一致<input name="q" value="'.$e($q).'"></label><label>ドメイン<input name="domain" value="'.$e($domain).'"></label><label>件数<select name="size">';
            foreach(['25','50','100'] as $n){$html.='<option'.($size===$n?' selected':'').'>'.$n.'</option>';}
            $html.='</select></label><button>検索</button></form><p>'.$data['total'].'件</p><p><a href="/mail-admin/send-limits">上限設定</a></p><table><tr><th>本人</th><th>1分：回数／宛先</th><th>1時間：回数／宛先</th><th>送信停止</th></tr>';
            foreach($data['rows'] as $row){
                if(!is_int($row['id']??null)||$row['id']<1||($row['kind']??null)!==$kind||!is_string($row['label']??null)||strlen($row['label'])>320||!is_array($row['usage']??null)||!is_array($row['stop']??null)){throw new \UnexpectedValueException('owner_row');}
                $usage=$row['usage'];foreach(['minute_messages','minute_recipients','hour_messages','hour_recipients'] as $key){if(!is_int($usage[$key]??null)||$usage[$key]<0){throw new \UnexpectedValueException('owner_usage');}}
                $stop=$row['stop'];if(!is_int($stop['until']??null)||!is_int($stop['revision']??null)||$stop['until']<0||$stop['revision']<0){throw new \UnexpectedValueException('owner_stop');}
                $html.='<tr><td>'.$e($row['label']).'</td><td>'.$usage['minute_messages'].'／'.$usage['minute_recipients'].'</td><td>'.$usage['hour_messages'].'／'.$usage['hour_recipients'].'</td><td>'.($stop['until']>time()?'停止中（'.gmdate('Y-m-d H:i:s',$stop['until']).' UTCまで）':'停止なし');
                $html.='<details><summary>期限付き停止・再開</summary><form method="post" action="/mail-admin/send-status/stop">';
                foreach(['_csrf_token'=>$this->csrf->getToken('mail_owner_stop')->getValue(),'kind'=>$kind,'owner_id'=>(string)$row['id'],'revision'=>(string)$stop['revision'],'request_id'=>bin2hex(random_bytes(16)),'issued_at'=>(string)$data['observed_at']] as $key=>$value){$html.='<input type="hidden" name="'.$key.'" value="'.$e($value).'">';}
                $html.='<label>停止期間<select name="seconds"><option value="3600">1時間</option><option value="900">15分</option><option value="14400">4時間</option><option value="86400">24時間</option><option value="0">停止を解除</option></select></label><label>対象名を再入力<input name="confirm" required autocomplete="off"></label><label>理由<select name="reason"><option value="account_compromise">不正利用の調査</option><option value="application_error">アプリの誤動作</option><option value="operator_review">管理者確認</option></select></label><button>この本人だけに適用</button></form></details></td></tr>';
            }
            $html.='</table>';foreach(['前へ'=>(int)$page-1,'次へ'=>(int)$page+1] as $label=>$n){if($n>0&&($n-1)*(int)$size<$data['total']){$html.='<a href="/mail-admin/send-status?'.$e(http_build_query(['kind'=>$kind,'q'=>$q,'domain'=>$domain,'page'=>$n,'size'=>$size])).'">'.$label.'</a> ';}}
            return ConsoleController::page('本人別送信状況・緊急停止',$html);
        }catch(\Throwable){return ConsoleController::page('送信状況を取得できません','<p>取得できない値を0件として表示しません。</p>',503);}
    }
    public function stop(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}$v=$r->request->all();
        if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($v['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_owner_stop',$v['_csrf_token']))){return ConsoleController::page('アクセス拒否','',403);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        foreach(['kind','owner_id','revision','request_id','issued_at','seconds','confirm','reason'] as $key){if(!is_string($v[$key]??null)||strlen($v[$key])>320){return ConsoleController::page('入力を確認してください','',400);}}
        if(!in_array($v['kind'],['mailbox','legacy'],true)||!preg_match('/^[1-9][0-9]{0,17}$/D',$v['owner_id'])||!preg_match('/^(0|[1-9][0-9]{0,14})$/D',$v['revision'])||!preg_match('/^[a-f0-9]{32}$/D',$v['request_id'])||!preg_match('/^[0-9]{10}$/D',$v['issued_at'])||!in_array($v['seconds'],['0','900','3600','14400','86400'],true)){return ConsoleController::page('入力を確認してください','',400);}
        $request=array_intersect_key($v,array_flip(['kind','request_id','confirm','reason']));foreach(['owner_id','revision','issued_at','seconds'] as $key){$request[$key]=(int)$v[$key];}$request['actor']=$actor->id;
        try{$result=$this->store->stop($request);$ok=($result['state']??null)==='applied';return ConsoleController::page('送信停止の操作結果','<p>'.($ok?'反映を確認しました。既存の計上は維持しています。':'結果が未確定です。自動で再操作せず、状態と履歴を確認してください。').'</p><p><a href="/mail-admin/send-status">送信状況を再取得</a></p>',$ok?200:409);}
        catch(\Throwable){return ConsoleController::page('操作結果を確認できません','<p>状態を確認してから対応してください。</p>',503);}
    }
}
