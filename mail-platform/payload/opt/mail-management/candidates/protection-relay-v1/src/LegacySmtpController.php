<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response,RedirectResponse};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class LegacySmtpController
{
    private readonly \Closure $logger;
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly LegacySmtpStore $store,private readonly RateLimiterFactory $limiter,?callable $logger=null)
    { $this->logger=$logger===null?static function(array $v):void{error_log(json_encode($v,JSON_THROW_ON_ERROR));}:\Closure::fromCallable($logger); }
    public function show(Request $request):Response
    {
        $actor=$this->tokens->getToken()?->getUser();
        if(!$actor instanceof AdminUser||!$actor->active||!$actor->systemAdmin){return ConsoleController::page('アクセス拒否','',403);}
        if(!AdminFactorGate::permits($actor,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time())){return ConsoleController::factorRequired($request,$this->csrf);}
        if(!in_array($request->getMethod(),['GET','POST'],true)){return ConsoleController::page('許可されない操作です','',405);}
        if(array_diff(array_keys($request->query->all()),['before'])){return ConsoleController::page('入力を確認してください','',400);}
        if(!$this->limiter->create($actor->id.':'.$request->getClientIp())->consume()->isAccepted()){return ConsoleController::page('操作回数の上限です','',429);}
        try{
            if($request->isMethod('POST')){
                if($request->query->count()||strlen($request->getContent())>8192||$request->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN
                    ||$request->headers->get('Origin')!==AdminWebauthn::ORIGIN){return ConsoleController::page('アクセス拒否','',403);}
                $input=$request->request->all();
                if(!is_string($input['_csrf_token']??null)||!$this->csrf->isTokenValid(new CsrfToken('mail_admin_legacy_smtp',$input['_csrf_token']))){return ConsoleController::page('アクセス拒否','',403);}
                $m=LegacySmtpMutation::fromForm($input);$this->store->save($actor,$m);
                $request->getSession()->set('mail_legacy_smtp_saved',true);
                return new RedirectResponse('/mail-admin/legacy-smtp',303,['Cache-Control'=>'no-store']);
            }
            $before=$request->query->all()['before']??null;
            if($before!==null){if(!is_string($before)){throw new \DomainException('invalid_input');}LegacySmtpMutation::number($before);}
            $data=$this->store->overview($actor,$before);$token=$this->csrf->getToken('mail_admin_legacy_smtp')->getValue();
            $saved=$request->getSession()->remove('mail_legacy_smtp_saved')===true;
            return ConsoleController::page('旧XMail互換 SMTP送信',($saved?'<p role="status">保存しました。新規IDは停止状態です。有効化してから使用してください。</p>':'').self::render($data,$token));
        }catch(\Throwable $e){
            if($e instanceof LegacySmtpFailure){($this->logger)(['component'=>'legacy_smtp','failure'=>$e->detail]);}
            $message=$e instanceof \DomainException?match($e->getMessage()){
                'invalid_new_password'=>'パスワードは12文字以上、確認欄と同一にしてください。制御文字は使用できません。',
                'invalid_login'=>'IDは英数字で始まる128文字以内の英数字・ドット・@・+・ハイフン・下線にしてください。',
                'duplicate_login'=>'同じIDが既に登録されています。',
                'inactive_owner'=>'旧方式で登録されたIDのメールボックスまたはドメインが停止中です。',
                'invalid_sender'=>'送信元アドレスを確認してください。半角英数字・ドット・下線・+・ハイフンのアドレスに対応します。表示名やワイルドカードは指定できません。',
                'confirmation_required'=>'対象IDの確認入力が一致しません。',
                'revision_changed'=>'他の操作で更新されました。一覧を更新してください。',
                default=>'入力または権限を確認してください。自動再試行は行いません。',
            }:'結果を確認できません。自動再試行せず、管理操作履歴を確認してください。';
            return ConsoleController::page('互換SMTPを処理できません','<p role="alert">'.$message.'</p>', $e instanceof \DomainException?400:503);
        }
    }
    public static function render(array $data,string $token):string
    {
        $e=ConsoleController::escape(...);
        $body='<h2>旧XMail互換 SMTP送信</h2><p role="note">この画面で有効化したIDだけ、端末証明書なしでSMTP送信を許可します。TLS暗号化は必須です。'
            .'通常の587番・IMAP・POP・Roundcubeの認証設定は変更しません。互換接続は465番のSSL/TLSです。</p>'
            .'<p>送信元メールボックスの作成は不要です。外部ドメインのアドレスも登録できます。SMTPの送信元（MAIL FROM）は、IDごとに管理者が登録した1アドレスに限定します。パスワードは保存後に表示できません。新規IDは停止状態で作成します。利用権限のあるアドレスを指定してください。外部ドメインのSPF・DKIM・DMARC対応は別途必要で、この登録だけでは完了しません。</p>';
        $hidden=static fn(string $name,string $value):string=>'<input type="hidden" name="'.$name.'" value="'.$e($value).'">';
        $start=static fn(string $action):string=>'<form method="post" action="/mail-admin/legacy-smtp">'.$hidden('_csrf_token',$token).$hidden('action',$action);
        $passwords=static fn(string $prefix):string=>'<label for="'.$prefix.'-password">パスワード（必須・12文字以上）</label><input id="'.$prefix.'-password" type="password" name="new_password" required minlength="12" maxlength="1024" autocomplete="new-password">'
            .'<label for="'.$prefix.'-repeat">パスワードの確認（必須）</label><input id="'.$prefix.'-repeat" type="password" name="repeat_password" required minlength="12" maxlength="1024" autocomplete="new-password">';
        $body.='<fieldset><legend>SMTP専用IDを登録</legend>'.$start('create')
            .'<label for="legacy-login">旧SMTP認証ID（必須）</label><input id="legacy-login" name="login_id" required maxlength="128" autocomplete="username">'
            .'<label for="legacy-sender">許可する送信元アドレス（必須・メールボックス不要）</label><input id="legacy-sender" type="email" name="sender_address" required maxlength="254" autocomplete="email">'
            .$passwords('legacy-new').'<button type="submit">停止状態で登録する</button></form></fieldset>';
        foreach($data['rows']as$row){
            $id=LegacySmtpMutation::number((string)$row['id']);$revision=LegacySmtpMutation::number((string)$row['revision']);
            $login=LegacySmtpMutation::login($row['login_id']);
            $target=$hidden('id',$id).$hidden('revision',$revision).'<label>対象IDを確認入力<input name="confirm_login" required maxlength="128" autocomplete="off"></label>';
            $body.='<fieldset><legend>'.$e($login).' — '.((string)$row['enabled']==='1'?'有効':'停止').'</legend><p>送信元：'.$e($row['sender_address']).'</p>'
                .$start('state').$target.'<label>状態<select name="enabled"><option value="0"'.((string)$row['enabled']==='0'?' selected':'').'>停止</option><option value="1"'.((string)$row['enabled']==='1'?' selected':'').'>有効</option></select></label><button type="submit">状態を保存</button></form>'
                .$start('password').$target.$passwords('legacy-'.$id).'<button type="submit">パスワードを再設定</button></form></fieldset>';
        }
        if(!$data['rows']){$body.='<p>互換SMTPの登録はありません。</p>';}
        if($data['next_before']!==null){$body.='<a href="?before='.$e(LegacySmtpMutation::number($data['next_before'])).'">次の50件</a>';}
        return $body;
    }
}
