<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response,RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class QueueAdminController
{
    private const STATES = ['incoming'=>'受付処理中','active'=>'配送処理中','deferred'=>'配送待ち','hold'=>'保留','maildrop'=>'投稿待ち'];
    private const ACTIONS = ['hold'=>'保留する','release'=>'保留を解除','retry'=>'再試行を要求'];
    private const RESULTS = ['held'=>'保留を確認しました。','released'=>'保留解除を確認しました。','retry_requested'=>'再試行を要求しました。配送完了の確認ではありません。',
        'changed'=>'対象の状態が変わりました。一覧を読み直してください。','already_absent'=>'対象は既にキューにありません。',
        'native_failed'=>'操作が失敗しました。履歴を確認してください。','unknown'=>'結果を確認できません。再操作せず、履歴と現在の状態を確認してください。'];
    public function __construct(private readonly TokenStorageInterface $tokens, private readonly CsrfTokenManagerInterface $csrf,
        private readonly QueueAdminStore $store, private readonly RateLimiterFactory $limiter) {}
    private function actor(Request $r): ?AdminUser
    {
        $u = $this->tokens->getToken()?->getUser();
        return $u instanceof AdminUser && AdminFactorGate::permits($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time()) ? $u : null;
    }
    public function show(Request $r): Response
    {
        $actor=$this->actor($r); if (!$actor) { return ConsoleController::factorRequired($r,$this->csrf); }
        if (!$this->limiter->create($actor->id)->consume()->isAccepted()) { return ConsoleController::page('操作回数の上限です','',429); }
        $query=$r->query->all();$q=$query['q']??'';$state=$query['state']??'';$page=$query['page']??'1';$size=$query['size']??'25';
        if (!is_string($q)||strlen($q)>254||preg_match('/[\x00-\x1f\x7f]/',$q)||!is_string($state)||($state!==''&&!isset(self::STATES[$state]))
            ||!is_string($page)||!preg_match('/^[1-9][0-9]{0,2}$/D',$page)||(int)$page>800||!is_string($size)||!in_array($size,['25','50','100'],true)) {
            return ConsoleController::page('検索条件を確認してください','',400);
        }
        try {
            $data=$this->store->browse(['query'=>$q,'state'=>$state,'page'=>(int)$page,'size'=>(int)$size]);
            if (!is_int($data['total']??null)||$data['total']<0||$data['total']>20000||!is_array($data['rows']??null)||count($data['rows'])>(int)$size
                ||!is_int($data['observed_at']??null)||$data['observed_at']>time()+5||$data['observed_at']<time()-120) { throw new \UnexpectedValueException('queue_snapshot'); }
            $e=ConsoleController::escape(...);$csrf=$this->csrf->getToken('mail_queue_action')->getValue();
            $html='<p>メール本文は表示しません。対象1件だけを操作します。表示から2分を超える操作は受け付けません。</p><form method="get"><label>キューID・送信元・宛先<input name="q" value="'.$e($q).'" maxlength="254"></label><label>状態<select name="state"><option value="">すべて</option>';
            foreach(self::STATES as $key=>$label){$html.='<option value="'.$key.'"'.($key===$state?' selected':'').'>'.$label.'</option>';}
            $html.='</select></label><label>表示件数<select name="size">';foreach(['25','50','100'] as $n){$html.='<option'.($n===$size?' selected':'').'>'.$n.'</option>';}
            $html.='</select></label><button>検索</button></form><p>'.$data['total'].'件</p><table><thead><tr><th>ID・状態</th><th>経過時間</th><th>宛先・滞留理由</th><th>操作</th></tr></thead><tbody>';
            foreach($data['rows'] as $row){
                if (!is_string($row['id']??null)||!preg_match('/^[A-Za-z0-9]{5,52}$/D',$row['id'])||!isset(self::STATES[$row['state']??''])||!is_int($row['age']??null)||$row['age']<0
                    ||!is_array($row['recipients']??null)||count($row['recipients'])>1000||!is_string($row['token']??null)||!preg_match('/^[a-f0-9]{64}$/D',$row['token'])) {throw new \UnexpectedValueException('queue_row');}
                $html.='<tr><td>'.$e($row['id']).'<br>'.self::STATES[$row['state']].'</td><td>'.intdiv($row['age'],60).'分</td><td>';
                foreach($row['recipients'] as $target){if(!is_string($target['address']??null)||!is_string($target['reason']??null)){throw new \UnexpectedValueException('queue_recipient');}
                    $html.=$e($target['address']).'<br>'.$e($target['reason']).'<br>';}
                $html.='</td><td><details><summary>対象1件を操作</summary><form method="post" action="/mail-admin/queue/action">';
                foreach(['_csrf_token'=>$csrf,'id'=>$row['id'],'token'=>$row['token'],'request_id'=>bin2hex(random_bytes(16)),'issued_at'=>(string)$data['observed_at']] as $key=>$value){$html.='<input type="hidden" name="'.$key.'" value="'.$e($value).'">';}
                $available=match($row['state']){'hold'=>['release'],'deferred'=>['hold','retry'],'incoming','active'=>['hold'],default=>[]};
                $html.='<label>操作<select name="action">';foreach(self::ACTIONS as $key=>$label){if(!in_array($key,$available,true)){continue;}$html.='<option value="'.$key.'">'.$label.'</option>';}
                $html.='</select></label><label>キューIDを再入力<input name="confirm" required autocomplete="off"></label><label>理由<select name="reason"><option value="delivery_investigation">配送調査</option><option value="destination_fixed">宛先側の修正を確認</option><option value="operator_review">管理者確認済み</option></select></label><button>この1件に実行</button></form></details></td></tr>';
            }
            $html.='</tbody></table>';foreach(['前へ'=>(int)$page-1,'次へ'=>(int)$page+1] as $label=>$target){if($target>=1&&($target-1)*(int)$size<$data['total']){$html.='<a href="/mail-admin/queue?'.$e(http_build_query(['q'=>$q,'state'=>$state,'size'=>$size,'page'=>$target])).'">'.$label.'</a> ';}}
            return ConsoleController::page('配送待ちメール',$html);
        }catch(\Throwable){return ConsoleController::page('配送待ちを取得できません','<p>収集状態と管理サービスを確認してください。</p>',503);}
    }
    public function apply(Request $r): Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        $input=$r->request->all();if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN
            ||!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_queue_action',$input['_csrf_token']))){return ConsoleController::page('アクセス拒否','',403);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        foreach(['action','id','confirm','token','reason','request_id','issued_at'] as $key){if(!is_string($input[$key]??null)||strlen($input[$key])>128){return ConsoleController::page('入力を確認してください','',400);}}
        if(!preg_match('/^[0-9]{10}$/D',$input['issued_at'])||!isset(self::ACTIONS[$input['action']])){return ConsoleController::page('入力を確認してください','',400);}
        $request=array_intersect_key($input,array_flip(['action','id','confirm','token','reason','request_id']));$request['actor']=$actor->id;$request['issued_at']=(int)$input['issued_at'];
        try{$result=$this->store->apply($request);$message=self::RESULTS[$result['state']??'unknown']??self::RESULTS['unknown'];
            return ConsoleController::page('配送待ちの操作結果','<p>'.$message.'</p><p><a href="/mail-admin/queue">一覧を再取得</a></p>',in_array($result['state']??'', ['held','released','retry_requested','already_absent'],true)?200:409);
        }catch(\Throwable){return ConsoleController::page('操作結果を確認できません','<p>自動で再操作せず、現在の状態と履歴を確認してください。</p>',503);}
    }
}
