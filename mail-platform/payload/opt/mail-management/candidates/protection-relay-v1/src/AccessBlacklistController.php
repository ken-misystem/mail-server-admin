<?php
declare(strict_types=1);
namespace MailServer\Management;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;

final class AccessBlacklistController
{
    private const JAILS = ['dovecot' => 'IMAP・POP認証', 'postfix-sasl' => 'SMTP認証',
        'roundcube-auth' => 'Webメール認証', 'sshd' => 'SSH認証', 'recidive' => '繰り返し検出'];
    private const REASONS = ['legitimate_user' => '正当な利用者と確認',
        'configuration_fixed' => '接続設定の修正を確認', 'operator_review' => '管理者による確認済み'];
    private const STATES = ['released' => '解除要求後、Fail2Banの対象登録の消失を確認しました。',
        'already_absent' => '対象のブロック登録は既に解除されています。',
        'still_banned' => '現在もブロックされています。再検出と他の判定を確認してください。',
        'unknown' => '解除結果を確認できません。一覧と操作履歴で現在の状態を確認してください。'];

    public function __construct(private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf, private readonly AccessBlacklistStore $store,
        private readonly RateLimiterFactory $limiter) {}

    private function actor(Request $request): ?AdminUser
    {
        $user = $this->tokens->getToken()?->getUser();
        return $user instanceof AdminUser && AdminFactorGate::permits($user,
            $request->getSession()->get(AdminFactorGate::SESSION_KEY), time()) ? $user : null;
    }

    public function show(Request $request): Response
    {
        $actor = $this->actor($request);
        if (!$actor) { return ConsoleController::factorRequired($request, $this->csrf); }
        if (!$this->limiter->create($actor->id)->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です', '<p>しばらく待ってから開いてください。</p>', 429);
        }
        try {
            $data = $this->store->overview();
            $body = $this->render($data, $request);
        } catch (\Throwable) {
            return ConsoleController::page('不正アクセスの状態を取得できません',
                '<p>監視データの取得状態を確認してください。</p>', 503);
        }
        return ConsoleController::page('不正アクセス・自動ブロック', $body);
    }

    private function render(array $data, Request $request): string
    {
        $e = ConsoleController::escape(...);
        if (!is_int($data['observed_at'] ?? null) || $data['observed_at'] > time() + 5
            || $data['observed_at'] < time() - 60 || !is_array($data['jails'] ?? null)
            || !is_array($data['bans'] ?? null) || count($data['bans']) > 10000) {
            throw new \UnexpectedValueException('snapshot_unavailable');
        }
        $query = $request->query->all();
        $search = $query['ip'] ?? '';
        $jail = $query['jail'] ?? '';
        $size = $query['size'] ?? '25';
        $page = $query['page'] ?? '1';
        if (!is_string($search) || strlen($search) > 45 || !preg_match('/^[0-9a-fA-F:.]*$/D', $search)
            || !is_string($jail) || ($jail !== '' && !isset(self::JAILS[$jail]))
            || !in_array($size, ['25', '50', '100'], true)
            || !is_string($page) || !preg_match('/^[1-9][0-9]{0,5}$/D', $page)) {
            throw new \DomainException('query_shape');
        }
        $rows = array_values(array_filter($data['bans'], static fn(array $row): bool =>
            ($jail === '' || $row['jail'] === $jail) && ($search === '' || str_starts_with($row['ip'], strtolower($search)))));
        usort($rows, static fn(array $a, array $b): int => [$a['ip'], $a['jail']] <=> [$b['ip'], $b['jail']]);
        $pages = max(1, (int) ceil(count($rows) / (int) $size));
        $page = min((int) $page, $pages);
        $body = '<p><a href="/mail-admin/">メール管理に戻る</a></p>';
        $notice = $request->getSession()->remove('mail_access_result');
        if (is_string($notice) && isset(self::STATES[$notice])) { $body .= '<p role="status">' . self::STATES[$notice] . '</p>'; }
        $body .= '<p>取得時刻 ' . $e(gmdate('Y-m-d H:i:s', $data['observed_at'])) . ' UTC。30秒間キャッシュします。</p>'
            . '<p>検出数・ブロック累計はFail2Banの現在の稼働期間の値です。日時はサーバー時刻 '
            . $e((string) ($data['timezone'] ?? '')) . ' で表示します。</p>'
            . '<h2>監視と自動ブロック条件</h2><table><thead><tr><th>対象</th><th>状態</th><th>現在の検出</th>'
            . '<th>検出累計</th><th>ブロック中</th><th>ブロック累計</th><th>条件</th></tr></thead><tbody>';
        foreach ($data['jails'] as $row) {
            $body .= '<tr><td>' . $e(self::JAILS[$row['jail']] ?? $row['jail']) . '</td><td>' . ($row['active'] ? '監視中' : '停止') . '</td>';
            if (!$row['active']) { $body .= '<td colspan="5">監視対象の起動状態を確認してください。</td></tr>'; continue; }
            foreach (['failed_current', 'failed_total', 'banned_current', 'banned_total'] as $field) {
                $body .= '<td>' . $e((string) $row[$field]) . '</td>';
            }
            $body .= '<td>' . $e((string) $row['findtime']) . '秒で' . $e((string) $row['maxretry'])
                . '回、' . ($row['bantime'] === -1 ? '無期限' : $e((string) $row['bantime']) . '秒ブロック') . '</td></tr>';
        }
        $body .= '</tbody></table>';
        if (($data['unlisted_jails'] ?? 0) > 0) { $body .= '<p role="alert">この一覧の対象外の監視設定があります。</p>'; }
        $body .= '<h2>ブロック中のIP</h2><form method="get" action="/mail-admin/access-blacklist">'
            . '<label>IP前方一致<input name="ip" maxlength="45" value="' . $e($search) . '"></label>'
            . '<label>対象<select name="jail"><option value="">すべて</option>';
        foreach (self::JAILS as $key => $label) { $body .= '<option value="' . $key . '"' . ($jail === $key ? ' selected' : '') . '>' . $label . '</option>'; }
        $body .= '</select></label><label>表示件数<select name="size">';
        foreach (['25', '50', '100'] as $option) { $body .= '<option' . ($size === $option ? ' selected' : '') . '>' . $option . '</option>'; }
        $body .= '</select></label><button>検索</button></form><p>' . count($rows) . '件／' . $page . 'ページ目</p>';
        $csrf = $this->csrf->getToken('mail_access_release')->getValue();
        foreach (array_slice($rows, ($page - 1) * (int) $size, (int) $size) as $row) {
            $body .= '<details><summary>' . $e($row['ip']) . ' ／ ' . $e(self::JAILS[$row['jail']]) . '</summary>'
                . '<p>開始 ' . $e($row['started']) . ' ／ 解除予定 ' . ($row['duration'] === -1 ? '無期限' : $e($row['ends'])) . '</p>'
                . '<p>選択した対象のブロックを解除します。同じIPが複数の対象でブロックされている場合は、各行で確認してください。同じ失敗が続くと再度ブロックされます。</p>'
                . '<form method="post" action="/mail-admin/access-blacklist/release">';
            $fields = ['_csrf_token' => $csrf, 'jail' => $row['jail'], 'ip' => $row['ip'],
                'token' => $row['token'], 'request_id' => bin2hex(random_bytes(16))];
            foreach ($fields as $key => $value) { $body .= '<input type="hidden" name="' . $key . '" value="' . $e($value) . '">'; }
            $body .= '<label>確認のためIPを入力<input name="confirm_ip" required maxlength="45" autocomplete="off"></label>'
                . '<label>解除理由<select name="reason">';
            foreach (self::REASONS as $key => $label) { $body .= '<option value="' . $key . '">' . $label . '</option>'; }
            $body .= '</select></label><button>このブロックを解除</button></form></details>';
        }
        if (!$rows) { $body .= '<p>条件に一致するブロックはありません。</p>'; }
        foreach (['前へ' => $page - 1, '次へ' => $page + 1] as $label => $target) {
            if ($target >= 1 && $target <= $pages) {
                $url = '/mail-admin/access-blacklist?' . http_build_query(['ip' => $search, 'jail' => $jail, 'size' => $size, 'page' => $target]);
                $body .= '<a href="' . $e($url) . '">' . $label . '</a> ';
            }
        }
        $body .= '<h2>管理者による解除履歴（直近100件）</h2><ul>';
        foreach ($data['audit'] ?? [] as $row) {
            $body .= '<li>' . $e(gmdate('Y-m-d H:i:s', $row['at'])) . ' UTC ／ 管理者ID ' . $e($row['actor'])
                . ' ／ ' . $e($row['ip']) . ' ／ ' . $e(self::JAILS[$row['jail']] ?? $row['jail'])
                . ' ／ ' . $e(self::REASONS[$row['reason']] ?? '確認待ち') . ' ／ ' . $e(self::STATES[$row['state']] ?? self::STATES['unknown']) . '</li>';
        }
        return $body . '</ul>';
    }

    public function release(Request $request): Response
    {
        $actor = $this->actor($request);
        if (!$actor) { return ConsoleController::factorRequired($request, $this->csrf); }
        $input = $request->request->all();
        if (!$request->isMethod('POST') || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
            || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN
            || !is_string($input['_csrf_token'] ?? null)
            || !$this->csrf->isTokenValid(new CsrfToken('mail_access_release', $input['_csrf_token']))) {
            return ConsoleController::page('アクセス拒否', '', 403);
        }
        if (!$this->limiter->create($actor->id)->consume()->isAccepted()) {
            return ConsoleController::page('操作回数の上限です', '', 429);
        }
        try {
            foreach (['jail', 'ip', 'confirm_ip', 'token', 'reason', 'request_id'] as $key) {
                if (!is_string($input[$key] ?? null)) { throw new \DomainException('field_shape'); }
            }
            if (!isset(self::JAILS[$input['jail']], self::REASONS[$input['reason']])
                || !filter_var($input['ip'], FILTER_VALIDATE_IP) || $input['ip'] !== $input['confirm_ip']
                || !preg_match('/^[a-f0-9]{64}$/D', $input['token'])
                || !preg_match('/^[a-f0-9]{32}$/D', $input['request_id'])) { throw new \DomainException('confirmation_required'); }
            // Keep a form ID's original request timestamp on duplicate POST.
            $timestamps = $request->getSession()->get('mail_access_requests', []);
            $stamp = $timestamps[$input['request_id']] ?? null;
            if (!is_int($stamp)) {
                $stamp = time();
                $timestamps[$input['request_id']] = $stamp;
                $request->getSession()->set('mail_access_requests', array_slice($timestamps, -100, null, true));
            }
            $result = $this->store->release(['operation' => 'unban', 'id' => $input['request_id'],
                'actor' => $actor->id, 'jail' => $input['jail'], 'ip' => $input['ip'], 'token' => $input['token'],
                'reason' => $input['reason'], 'issued_at' => $stamp]);
            $state = $result['state'] ?? 'unknown';
            if (!isset(self::STATES[$state])) { $state = 'unknown'; }
        } catch (\Throwable) { $state = 'unknown'; }
        $request->getSession()->set('mail_access_result', $state);
        return new RedirectResponse('/mail-admin/access-blacklist', 303, ['Cache-Control' => 'no-store']);
    }
}
