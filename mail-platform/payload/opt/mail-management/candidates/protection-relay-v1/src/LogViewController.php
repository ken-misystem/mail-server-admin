<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfTokenManagerInterface,CsrfToken};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class LogViewController
{
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,
        private readonly LogViewStore $store,private readonly RateLimiterFactory $limiter) {}
    public function show(Request $request): Response
    {
        if(!in_array($request->getMethod(),['GET','POST'],true))return new Response('',405,['Allow'=>'GET, POST','Cache-Control'=>'no-store']);
        $actor=$this->tokens->getToken()?->getUser();
        if(!$actor instanceof AdminUser||!$actor->active||!$actor->systemAdmin||$request->getSchemeAndHttpHost()!==AdminWebauthn::ORIGIN)return ConsoleController::page('アクセス拒否','',403);
        if(!AdminFactorGate::permits($actor,$request->getSession()->get(AdminFactorGate::SESSION_KEY),time()))return ConsoleController::factorRequired($request,$this->csrf);
        $query=new LogViewQuery();
        if($request->isMethod('POST')){
            if(strlen($request->getContent())>2048||$request->headers->get('Origin')!==AdminWebauthn::ORIGIN
                ||!is_string($request->request->all()['_token']??null)
                ||!$this->csrf->isTokenValid(new CsrfToken('mail_admin_log_search',$request->request->get('_token'))))return ConsoleController::page('検索を確認できません','<p>画面を再読み込みしてください。</p>',403);
            try {$query=LogViewQuery::fromArray($request->request->all());}catch(\DomainException){return ConsoleController::page('検索条件が不正です','<p>期間・区分・検索語を確認してください。</p>',400);}
        } elseif($request->query->count()>0)return ConsoleController::page('検索条件が不正です','<p>画面の検索フォームを使用してください。</p>',400);
        if(!$this->limiter->create($actor->id)->consume()->isAccepted())return ConsoleController::page('検索回数の上限です','<p>1分間に20回までです。少し待ってから更新してください。</p>',429);
        $token=$this->csrf->getToken('mail_admin_log_search')->getValue();
        try {$result=$this->store->search($query,time());}
        catch(\Throwable $e){
            return ConsoleController::page('各種ログ',self::nav().self::form($query,$token).'<p role="alert">ログ表示用データを取得できません。未導入・更新中・収集障害を確認してください。ログがないという意味ではありません。</p>',503);
        }
        return ConsoleController::page('各種ログ',self::nav().self::form($query,$token).self::render($result,$query,$token),200,self::css());
    }
    private static function nav(): string {return '<p><a href="/mail-admin/">メール管理</a> ／ <a href="/mail-admin/operations-status">稼働状況</a> ／ <a href="/mail-admin/logs">最新のログ</a></p>';}
    private static function e(mixed $v): string {return ConsoleController::escape((string)$v);}
    private static function form(LogViewQuery $q,string $token,?int $before=null): string
    {
        $body='<form method="post" action="/mail-admin/logs" class="log-search"><input type="hidden" name="_token" value="'.self::e($token).'">';
        if($before!==null){
            foreach(['category'=>$q->category,'level'=>$q->level,'word'=>$q->word,'hours'=>$q->hours,'before'=>$before]as$k=>$v)$body.='<input type="hidden" name="'.$k.'" value="'.self::e($v).'">';
            return $body.'<button type="submit">条件を保って、さらに前の記録を表示</button></form>';
        }
        foreach(['category'=>['区分',[''=>'すべて']+LogViewQuery::CATEGORIES,$q->category],
            'level'=>['重要度',[''=>'すべて']+LogViewQuery::LEVELS,$q->level],
            'hours'=>['期間',[1=>'直近1時間',24=>'直近24時間',168=>'直近7日間'],(string)$q->hours]]as$name=>[$title,$options,$selected]){
            $body.='<label>'.$title.'<select name="'.$name.'">';foreach($options as$v=>$label)$body.='<option value="'.self::e($v).'"'.((string)$v===$selected?' selected':'').'>'.self::e($label).'</option>';
            $body.='</select></label>';
        }
        return $body.'<label>検索語（文字列の部分一致）<input name="word" value="'.self::e($q->word).'" maxlength="80" autocomplete="off" spellcheck="false" placeholder="メールアドレス・IP・キューID・失敗理由"></label><button type="submit">検索・更新</button></form><p class="log-meta">パスワード・トークンは入力しないでください。検索条件はURLへ含めません。自動更新は行いません。</p>';
    }
    public static function render(array $r,LogViewQuery $q,string $token): string
    {
        $body='<p class="log-meta">収集日時 '.self::date($r['generated']).' ／ 保存済み '.self::e($r['retained']).' 件。直近7日・最大20,000件。導入時は直近15分から収集します。</p>';
        if($r['stale'])$body.='<p role="alert">古い取得結果です。3分以上更新されていません。</p>';
        if(($r['collector']['status']??'failed')!=='ok'){
            $body.='<p role="alert">ログ収集に失敗しています。以下は保存済みの記録です。</p>';
            foreach($r['collector']['sources']??[]as$source)if(($source['status']??'failed')!=='ok')$body.='<p role="alert">'.self::e($source['source']??'').': '.self::e($source['class']??'').': '.self::e($source['reason']??'未取得').'</p>';
        }
        if($r['collector']['backlog']??false)$body.='<p role="status">収集途中の記録があり、未処理分を次回へ繰り越しています。最新まで揃っているという意味ではありません。</p>';
        $body.='<details><summary>収集範囲・表示上限</summary><p>SMTP受信／送信／配送、IMAP・POP接続、フィルター、外部POP定期取得、Web・PHP、Fail2ban、監視の対象journalを増分収集します。記録がないサービスもあります。</p>'
            .'<p>Roundcube専用ファイルは固定のerrors/errors.logを対象とし、不在や形式不明は収集障害として表示します。管理操作DB履歴は未収集です。空欄からエラーがないとは判定しないでください。本文・件名・認証情報・debugログを表示せず、保護したログだけを検索します。</p>'
            .'<p>1ページ100件、1検索32断片／2MiB／1秒まで。超過時は続きをページ送りできます。並び順は新しい収集順です。保管上限より前の記録は検索しません。SMTP受付記録は到着証明ではありません。</p></details>';
        $body.='<div class="log-table"><table><thead><tr><th>日時（JST）</th><th>区分／重要度</th><th>本人・相手／識別情報</th><th>処理結果・理由</th></tr></thead><tbody>';
        foreach($r['rows']as$row){
            $body.='<tr><td>'.self::date(intdiv($row['ts'],1000000)).'</td><td>'.self::e(LogViewQuery::CATEGORIES[$row['category']]).'<br><strong class="log-'.$row['level'].'">'.self::e(LogViewQuery::LEVELS[$row['level']]).'</strong><br>'.self::e($row['source']).'</td><td>';
            foreach(['sender'=>'差出人','recipient'=>'宛先','account'=>'本人','ip'=>'IP','queue'=>'キューID']as$k=>$label)if($row[$k]!=='')$body.=self::e($label).'：'.self::e($row[$k]).'<br>';
            $outcome=['accepted'=>'配送先SMTP／LMTPが受付','deferred'=>'一時保留・再配送待ち','failed'=>'処理失敗','rejected'=>'受付拒否','auth_failed'=>'認証失敗','event'=>'処理記録'][$row['outcome']]??'未分類';
            $body.='</td><td>'.self::e($outcome).'<pre>'.self::e($row['text']).'</pre></td></tr>';
        }
        if(!$r['rows'])$body.='<tr><td colspan="4">今回調べた保存範囲に一致する記録はありません。全期間・未収集元を含む不存在の証明ではありません。</td></tr>';
        $body.='</tbody></table></div>';
        if($r['scan_limited'])$body.='<p role="status">表示件数または検索負荷の上限で区切りました。条件を保った続きから検索できます。</p>';
        if($r['next_before']!==null)$body.=self::form($q,$token,$r['next_before']);
        return $body;
    }
    private static function date(int $stamp): string {return (new \DateTimeImmutable('@'.$stamp))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y-m-d H:i:s').' JST';}
    private static function css(): string {return '.log-search{display:flex;flex-wrap:wrap;gap:12px;align-items:end;max-width:none}.log-search label{flex:1;min-width:160px}.log-table{overflow:auto;margin-top:20px}.log-table td{vertical-align:top}.log-table pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:650px;margin:6px 0;font:inherit}.log-meta{color:#bac7cf}.log-error{color:#ffb2b2}.log-warning{color:#ffe28b}.log-info{color:#b2f4cf}details{margin:15px 0}';}
}
