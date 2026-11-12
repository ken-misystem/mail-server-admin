<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\{CsrfToken,CsrfTokenManagerInterface};
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class ProtectionController
{
    private const SESSION = 'mail_protection_forms';
    private const TITLES = ['scanner'=>'危険添付・ウイルス設定', 'upstream'=>'上流SMTP設定'];
    private const PHASES = [
        'applied'=>'反映済み', 'pending'=>'反映待ち', 'applying'=>'反映中',
        'failed'=>'反映失敗・元設定へ復旧済み', 'unknown'=>'要確認・自動反映停止',
    ];

    public function __construct(
        private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf,
        private readonly ProtectionStore $store,
        private readonly RateLimiterFactory $limiter,
    ) {}

    private function actor(Request $request): ?AdminUser
    {
        $user = $this->tokens->getToken()?->getUser();
        return $user instanceof AdminUser && $user->systemAdmin
            && AdminFactorGate::verified($user, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time()) ? $user : null;
    }

    private function page(string $kind, string $html, int $status=200): Response
    {
        $response = ConsoleController::page(self::TITLES[$kind] ?? '設定', $html, $status);
        $response->headers->set('Cache-Control', 'no-store');
        return $response;
    }

    private static function text(array $input, string $name): string
    {
        if (!is_string($input[$name] ?? null)) { throw new \DomainException('input_type'); }
        return $input[$name];
    }

    public function show(Request $request, string $kind): Response
    {
        $actor = $this->actor($request);
        if (!$actor) { return ConsoleController::factorRequired($request, $this->csrf); }
        if (!$request->isMethod('GET') || !isset(self::TITLES[$kind])) { return $this->page($kind, '', 403); }
        try {
            $saved = $this->store->read($actor, $kind);
            $payload = $saved['payload'];
            $escape = static fn(mixed $value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $nonce = bin2hex(random_bytes(16));
            $pool = $request->getSession()->get(self::SESSION, []);
            $pool = is_array($pool) ? array_slice($pool, -7, null, true) : [];
            $pool[$nonce] = ['actor'=>$actor->id, 'epoch'=>$actor->epoch, 'kind'=>$kind, 'revision'=>$saved['revision'], 'at'=>time()];
            $request->getSession()->set(self::SESSION, $pool);
            $html = '<p>保存世代 '.$escape($saved['revision']).' / 反映済み世代 '.$escape($saved['applied_revision'])
                .' / '.$escape(self::PHASES[$saved['phase']]).'</p><form method="post" autocomplete="off">'
                .'<input type="hidden" name="_csrf_token" value="'.$escape($this->csrf->getToken('mail_protection')->getValue()).'">'
                .'<input type="hidden" name="nonce" value="'.$nonce.'">';
            if ($kind === 'scanner') {
                $html .= '<label><input type="checkbox" name="antivirus" value="1"'.($payload['antivirus']?' checked':'').'>ウイルス検査を有効にする</label>'
                    .'<p>有効化には検査エンジンと最新の定義が必要です。検査障害時は一時拒否し、送信側の再試行を待ちます。</p>'
                    .'<label>対象拡張子（ドットを除き、1行に1件）<textarea name="extensions" maxlength="2304" rows="8">'
                    .$escape(implode("\n",$payload['extensions'])).'</textarea></label>'
                    .'<label>危険添付を検出した場合<select name="attachment_action"><option value="reject"'
                    .($payload['attachment_action']==='reject'?' selected':'').'>受信拒否</option><option value="tag"'
                    .($payload['attachment_action']==='tag'?' selected':'').'>迷惑メール扱い</option></select></label>'
                    .'<label><input type="checkbox" name="encrypted_archives" value="1"'.($payload['encrypted_archives']?' checked':'')
                    .'>暗号化アーカイブも対象にする</label>';
            } else {
                $html .= '<label>配送方法<select name="mode"><option value="direct"'.($payload['mode']==='direct'?' selected':'')
                    .'>宛先MXへ直接配送</option><option value="relay"'.($payload['mode']==='relay'?' selected':'')
                    .'>上流SMTPを使用</option></select></label>'
                    .'<label>上流SMTPホスト名<input name="host" maxlength="253" value="'.$escape($payload['host']).'"></label>'
                    .'<label>接続方式<select name="connection">';
                foreach (['587'=>'587 / STARTTLS','465'=>'465 / TLS','25'=>'25 / STARTTLS'] as $port=>$label) {
                    $html .= '<option value="'.$port.'"'.((int)$port===$payload['port']?' selected':'').'>'.$label.'</option>';
                }
                $html .= '</select></label><p>TLSと証明書のホスト名検証を必須にします。</p>'
                    .'<label><input type="checkbox" name="authentication" value="1"'.($payload['authentication']?' checked':'').'>SMTP認証を使用</label>'
                    .'<p>資格情報 '.($saved['credential_present']?'保存済み':'未登録').'</p>'
                    .'<label>資格情報の操作<select name="credential_action"><option value="keep">保持</option>'
                    .'<option value="replace">新しい値へ変更</option><option value="clear">削除</option></select></label>'
                    .'<label>新しい認証ID<input name="username" maxlength="256" autocomplete="off"></label>'
                    .'<label>新しいパスワード<input name="password" type="password" maxlength="512" autocomplete="new-password"></label>'
                    .'<p>認証IDとパスワードは空白を含まない半角印字文字で入力してください。接続先を変更する場合は資格情報も指定し直してください。</p>';
            }
            $html .= '<label>確認のため「保存」と入力<input name="confirm" required></label><button>設定を保存</button></form>';
            return $this->page($kind, $html);
        } catch (\Throwable) {
            return $this->page($kind, '<p>設定を取得できません。</p>', 503);
        }
    }

    public function save(Request $request, string $kind): Response
    {
        $actor = $this->actor($request);
        if (!$actor) { return ConsoleController::factorRequired($request, $this->csrf); }
        if (!isset(self::TITLES[$kind])) { return $this->page($kind, '', 403); }
        $input = $request->request->all();
        if (!$request->isMethod('POST') || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
            || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN
            || !is_string($input['_csrf_token'] ?? null)
            || !$this->csrf->isTokenValid(new CsrfToken('mail_protection', $input['_csrf_token']))) {
            return $this->page($kind, '', 403);
        }
        if (strlen($request->getContent()) > 8192) { return $this->page($kind, '', 413); }
        if (!$this->limiter->create($actor->id)->consume()->isAccepted()) { return $this->page($kind, '', 429); }
        $nonce = $input['nonce'] ?? null;
        $pool = $request->getSession()->get(self::SESSION, []);
        $prior = is_string($nonce) && is_array($pool) ? ($pool[$nonce] ?? null) : null;
        if (!is_array($prior) || $prior['actor'] !== $actor->id || $prior['epoch'] !== $actor->epoch
            || $prior['kind'] !== $kind || $prior['at'] < time()-300 || $prior['at'] > time()) {
            return $this->page($kind, '<p>確認期限を確認し、画面を取得し直してください。</p>', 409);
        }
        unset($pool[$nonce]);
        $request->getSession()->set(self::SESSION, $pool);
        try {
            if (($input['confirm'] ?? null) !== '保存') { throw new \DomainException('confirmation'); }
            foreach (['antivirus','encrypted_archives','authentication'] as $name) {
                if (isset($input[$name]) && $input[$name] !== '1') { throw new \DomainException('boolean'); }
            }
            $credential = ['action'=>'keep'];
            if ($kind === 'scanner') {
                $lines = trim(self::text($input,'extensions'));
                $payload = [
                    'antivirus'=>isset($input['antivirus']),
                    'extensions'=>$lines===''?[]:preg_split('/\r?\n/',strtolower($lines)),
                    'attachment_action'=>self::text($input,'attachment_action'),
                    'encrypted_archives'=>isset($input['encrypted_archives']),
                ];
            } else {
                $port = self::text($input,'connection');
                if (!in_array($port,['25','465','587'],true)) { throw new \DomainException('port'); }
                $payload = [
                    'mode'=>self::text($input,'mode'), 'host'=>strtolower(trim(self::text($input,'host'))),
                    'port'=>(int)$port, 'tls'=>$port==='465'?'implicit':'starttls', 'authentication'=>isset($input['authentication']),
                ];
                $credential = ['action'=>self::text($input,'credential_action')];
                if ($credential['action']==='replace') {
                    $credential['username']=self::text($input,'username');
                    $credential['password']=self::text($input,'password');
                }
            }
            $result = $this->store->save($actor,$kind,$prior['revision'],$payload,$credential,$nonce);
            if (!in_array($result['state']??null,['saved_pending_publication','already_recorded'],true)
                || ($result['kind']??null)!==$kind || ($result['revision']??null)!==$prior['revision']+1) {
                throw new \RuntimeException('save_unverified');
            }
            return $this->page($kind,'<p>保存しました。反映状態を設定画面で確認してください。</p>');
        } catch (\DomainException) {
            return $this->page($kind,'<p>入力と現在の設定を確認してください。</p>',409);
        } catch (\Throwable) {
            return $this->page($kind,'<p>保存結果を確認できません。現在の設定と履歴を確認してください。</p>',503);
        }
    }
}
