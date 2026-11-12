<?php
declare(strict_types=1);
namespace MailServer\Management;
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
final class FeatureRuntimeController
{
    public const TITLES=['authentication'=>'認証失敗の推移','dns'=>'公開DNS・送信ドメイン','backup'=>'バックアップの記録','scanner'=>'危険添付・ウイルス検査','upstream'=>'上流SMTPの状態','forwarding'=>'転送・設定反映の状態'];
    public function __construct(private readonly TokenStorageInterface $tokens,private readonly CsrfTokenManagerInterface $csrf,private readonly FeatureObservations $observations){}
    private static function yes(bool $value):string{return $value?'あり':'なし';}
    public function show(Request $r,string $section):Response
    {
        $actor=$this->tokens->getToken()?->getUser();if(!$actor instanceof AdminUser||!$actor->systemAdmin||!AdminFactorGate::verified($actor,$r->getSession()->get(AdminFactorGate::SESSION_KEY),time())){return ConsoleController::factorRequired($r,$this->csrf);}
        if(!$r->isMethod('GET')||!isset(self::TITLES[$section])){return ConsoleController::page('アクセス拒否','',403);}$title=self::TITLES[$section];$e=ConsoleController::escape(...);
        try{
            $data=$this->observations->status(time());$html='<p>観測日時：'.$e(gmdate('Y-m-d H:i:s',$data['observed_at'])).' UTC</p>';
            if($section!=='dns'&&($data[$section]['state']??null)==='unavailable'){return ConsoleController::page($title,$html.'<p>この項目の状態を確認できません。</p>',503);}
            if($section==='authentication'){
                $item=$data['authentication'];$html.='<p>直近24時間の保持済み正規化ログだけの集計です。期間全体の網羅は確認していません。Fail2Banの起動後累計とは別の値です。</p>';
                if(!isset($item['totals'])){$html.='<p>集計を確認できません。</p>';}else{$names=['access'=>'メール認証','smtp_in'=>'SMTP受信','smtp_out'=>'SMTP送信','web'=>'Web画面','security'=>'セキュリティ','system'=>'システム'];$html.='<table><thead><tr><th>時刻（UTC）</th><th>分類</th><th>失敗件数</th></tr></thead><tbody>';foreach(array_reverse($item['totals'])as $row){$html.='<tr><td>'.$e(gmdate('m-d H:i',$row['at'])).'</td><td>'.$names[$row['category']].'</td><td>'.$row['count'].'</td></tr>';}$html.='</tbody></table><h2>接続元IPの上位100件</h2><table><thead><tr><th>IP</th><th>件数</th></tr></thead><tbody>';foreach($item['top_IPs']as $row){$html.='<tr><td>'.$e($row['ip']).'</td><td>'.$row['count'].'</td></tr>';}$html.='</tbody></table>';}
            }elseif($section==='dns'){
                $prefix=$r->query->get('q','');$host=$r->query->get('domain','');if(!is_string($prefix)||strlen($prefix)>253||!is_string($host)){throw new \DomainException('DNS_filter');}
                $matches=array_values(array_filter($data['domains'],static fn($value)=>str_starts_with($value,$prefix)));$html.='<p>公開DNSをHTTPS経由で参照します。ローカルhosts・AWS管理権限は使用せず、DNSは変更しません。</p><form method="get"><label>ドメインの前方一致<input name="q" value="'.$e($prefix).'" maxlength="253"></label><button>検索</button></form><p>該当'.count($matches).'件。先頭100件を表示します。</p><ul>';foreach(array_slice($matches,0,100)as $name){$html.='<li><a href="?'.$e(http_build_query(['q'=>$prefix,'domain'=>$name])).'">'.$e($name).'</a></li>';}$html.='</ul>';
                if($host!==''){$view=$this->observations->dns($host,time());$labels=['consistent'=>'公開resolver間で一致','resolver_disagreement'=>'公開resolver間に差異','unavailable'=>'取得できません','selector_unknown'=>'表示用セレクター未確認'];$html.='<h2>'.$e($host).'</h2><p>DNS観測日時：'.$e(gmdate('Y-m-d H:i:s',$view['observed_at'])).' UTC</p>';foreach($view['records']as $row){$html.='<section><h3>'.$row['type'].'：'.$labels[$row['state']].'</h3><pre>'.$e(implode("\n",$row['values'])).'</pre></section>';}}
            }elseif($section==='backup'){
                $item=$data['backup'];$html.='<p>設定・DB・資格情報・鍵・取得履歴等の暗号化退避の記録です。メール本文全体の退避と復元試験は未実施です。外部コピーの現在の可用性はサーバーから確認していません。</p>';
                if($item['state']==='ok'){$html.='<dl><dt>保存証拠の照合</dt><dd>一致</dd><dt>暗号化ファイルのサイズ</dt><dd>'.$item['bytes'].'バイト</dd><dt>SHA256</dt><dd>'.$e($item['sha256']).'</dd></dl>';}else{$html.='<p>照合可能な保存証拠を取得できません。</p>';}
            }elseif($section==='scanner'){
                $item=$data['scanner'];$html.='<dl>';foreach(['engine_present'=>'検査エンジン','configured'=>'ウイルス検査設定','daemon_running'=>'検査プロセス','detection_verified'=>'実検出の検証','attachment_rules_configured'=>'危険添付ルール']as $key=>$label){$html.='<dt>'.$label.'</dt><dd>'.self::yes($item[$key]).'</dd>';}$html.='</dl><p>未導入・未設定の検査を有効とは扱いません。旧XMailのscanner・DenyAttachment・RemoveAttachmentは空でした。エンジン導入や検査設定の変更は、この参照画面では実行しません。</p>';
            }elseif($section==='upstream'){
                $item=$data['upstream'];$html.='<dl><dt>配送方法</dt><dd>'.($item['direct_MX']?'宛先のMXへ直接配送':'上流SMTPの設定あり（実効性は別途確認）').'</dd><dt>上流SMTP設定</dt><dd>'.self::yes($item['relay_configured']).'</dd><dt>資格情報参照先の設定</dt><dd>'.self::yes($item['credentials_configured']).'</dd></dl><p>資格情報は表示しません。旧XMailの上流定義は0件で、現在のMX直接配送を既定として維持します。</p>';
            }else{
                $item=$data['forwarding'];$html.='<dl><dt>転送設定数</dt><dd>'.$item['configured'].'</dd><dt>転送のみ保留</dt><dd>'.$item['held'].'</dd><dt>生成した個人別ルール</dt><dd>'.$item['scripts'].'</dd></dl><p>保留は新しい転送にだけ適用します。保存済みメールや配送待ちを削除・自動再送しません。</p>';
                if($data['configuration']['state']==='unavailable'){$html.='<p>設定の反映世代を確認できません。</p>';}else{$html.='<table><thead><tr><th>設定</th><th>保存世代</th><th>検証・公開要求済み世代</th></tr></thead><tbody>';foreach(['access'=>'許否リスト','spam'=>'迷惑メール判定']as $key=>$label){$row=$data['configuration'][$key];$html.='<tr><td>'.$label.'</td><td>'.$row['desired_revision'].'</td><td>'.$row['applied_revision'].'</td></tr>';}$html.='</tbody></table><p>世代は設定の検証・公開処理の結果です。実メールでの判定・配送成功を示す値ではありません。</p>';}
            }
            return ConsoleController::page($title,$html);
        }catch(\DomainException){return ConsoleController::page($title,'<p>観測結果が未取得・期限切れ、または対象を確認できません。稼働状況と新しい収集結果を確認してください。</p>',503);}catch(\Throwable){return ConsoleController::page($title,'<p>観測結果を取得できません。</p>',503);}
    }
}
