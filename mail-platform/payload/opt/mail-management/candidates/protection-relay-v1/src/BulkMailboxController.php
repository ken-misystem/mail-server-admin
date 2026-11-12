<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response,File\UploadedFile};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

/** No uploaded bytes, plaintext or password hashes are put into session/results/logs. */
final class BulkMailboxController
{
    private const KEY='mail_bulk_preview';
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly BulkMailboxStore $store,private readonly RateLimiterFactory $limiter){}
    private function actor(Request $r):?AdminUser{$u=$this->tokens->getToken()?->getUser();return $u instanceof AdminUser&&AdminFactorGate::verified($u,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())?$u:null;}
    private function form(string $action):string{return '<form method="post" enctype="multipart/form-data" action="'.$action.'"><input type="hidden" name="_csrf_token" value="'.ConsoleController::escape($this->csrf->getToken('mail_bulk')->getValue()).'"><label>CSVファイル（最大2MiB）<input type="file" name="csv" accept=".csv,text/csv" required></label>';}
    public function show(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        try{$domains=$this->store->domains($actor);$html='<p>見出しは domain_id,local_part,password,quota_bytes です。全行を事前確認し、選択した最大25件を同一取引で登録します。初期状態は無効です。</p><p>パスワードを含むCSVは、結果・セッションへ保存しません。適用時には同じファイルを再指定してください。</p><ul>';
            foreach($domains as $id=>$name){$html.='<li>'.ConsoleController::escape((string)$id).'：'.ConsoleController::escape($name).'</li>';}
            return ConsoleController::page('CSV一括登録',$html.'</ul>'.$this->form('/mail-admin/bulk/preview').'<button>全行を事前確認</button></form>');
        }catch(\Throwable){return ConsoleController::page('CSV登録を利用できません','',503);}
    }
    private function upload(Request $r):string
    {
        $file=$r->files->get('csv');if(!$file instanceof UploadedFile||!$file->isValid()||$file->getSize()===false||$file->getSize()>2*1024*1024){throw new \DomainException('upload');}
        $raw=file_get_contents($file->getPathname(),false,null,0,2*1024*1024+1);if($raw===false||strlen($raw)>2*1024*1024){throw new \DomainException('upload');}return $raw;
    }
    public function submit(Request $r):Response
    {
        $actor=$this->actor($r);if(!$actor){return ConsoleController::factorRequired($r,$this->csrf);}
        $v=$r->request->all();if(!$r->isMethod('POST')||$r->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN||$r->headers->get('Origin')!==AdminWebauthn::ORIGIN||!is_string($v['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_bulk',$v['_csrf_token']))){return ConsoleController::page('アクセス拒否','',403);}
        if(!$this->limiter->create($actor->id)->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        try{
            $csv=$this->upload($r);$plan=BulkMailboxPlan::parse($csv,$this->store->domains($actor));
            if($r->getPathInfo()==='/mail-admin/bulk/preview'){
                $key=random_bytes(32);$id=bin2hex(random_bytes(16));$receipt=['actor'=>$actor->id,'epoch'=>$actor->epoch,'at'=>time(),'request_id'=>$id,'key'=>base64_encode($key),'binding'=>hash_hmac('sha256',$csv,$key)];unset($key,$csv);
                $r->getSession()->set(self::KEY,$receipt);$html='<p>最大25行を選択し、確認済みの同じCSVを再指定してください。パスワードは表示しません。確認の有効期間は5分です。</p>'.$this->form('/mail-admin/bulk/apply').'<input type="hidden" name="request_id" value="'.$id.'"><table><tr><th>選択</th><th>行</th><th>アドレス</th><th>容量上限（bytes・0は無制限）</th></tr>';
                foreach($plan->preview() as $row){$html.='<tr><td><input type="checkbox" name="lines[]" value="'.$row['line'].'"></td><td>'.$row['line'].'</td><td>'.ConsoleController::escape($row['email']).'</td><td>'.$row['quota_bytes'].'</td></tr>';}
                return ConsoleController::page('CSV登録の事前確認',$html.'</table><button>選択した行を無効状態で登録</button></form>');
            }
            if($r->getPathInfo()!=='/mail-admin/bulk/apply'){return ConsoleController::page('アクセス拒否','',403);}
            $receipt=$r->getSession()->get(self::KEY);$lines=$v['lines']??null;
            if(!is_array($receipt)||$receipt['actor']!==$actor->id||$receipt['epoch']!==$actor->epoch||!is_int($receipt['at'])||$receipt['at']>time()||time()-$receipt['at']>300||($v['request_id']??null)!==$receipt['request_id']||!is_array($lines)||count($lines)<1||count($lines)>25){throw new \DomainException('preview');}
            $key=base64_decode($receipt['key'],true);if($key===false||!hash_equals($receipt['binding'],hash_hmac('sha256',$csv,$key))){throw new \DomainException('changed_upload');}unset($key,$csv);
            foreach($lines as &$line){if(!is_string($line)||!preg_match('/^[1-9][0-9]{0,6}$/D',$line)||(int)$line>2097153){throw new \DomainException('line');}$line=(int)$line;}unset($line);
            // Consume BEFORE a database call: uncertain commits cannot be replayed by a browser refresh.
            $r->getSession()->remove(self::KEY);$rows=$this->store->apply($actor,$plan,$lines,$receipt['request_id']);
            $html='<p>登録は無効状態です。既存の個別管理画面で確認してから有効化してください。</p><ul>';
            foreach($rows as $row){$html.='<li>行'.(int)$row['line'].'：登録ID '.ConsoleController::escape((string)$row['id']).'・無効</li>';}
            return ConsoleController::page('CSV登録の結果',$html.'</ul>');
        }catch(\DomainException $error){$unknown=$error->getMessage()==='result_unverified';return ConsoleController::page($unknown?'登録結果が未確定です':'CSV・権限・確認期限を確認してください',$unknown?'<p>再送せず管理履歴と利用者一覧で確認してください。</p>':'<p>CSVと事前確認をやり直してください。既存の登録を上書きしません。</p>',$unknown?503:400);}
        catch(\Throwable){return ConsoleController::page('CSV登録の結果を確認できません','<p>再送せず管理履歴と利用者一覧で確認してください。</p>',503);}
    }
}
