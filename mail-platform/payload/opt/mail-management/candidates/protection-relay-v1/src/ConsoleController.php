<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

final class ConsoleController
{
    public function __construct(
        private readonly TokenStorageInterface $tokens,
        private readonly CsrfTokenManagerInterface $csrf,
        private readonly AdminPasskeyCeremony $passkeys,
        private readonly RateLimiterFactory $factorLimiter,
    ) {}

    public function login(Request $request): Response
    {
        $error = $request->getSession()->remove(SecurityRequestAttributes::AUTHENTICATION_ERROR);
        $message = $error ? '<p role="alert">ログインできませんでした。</p>' : '';
        $token = self::escape($this->csrf->getToken('mail_admin_login')->getValue());
        return self::page('メール管理者ログイン', $message . '
            <p>メールボックスとは独立した管理者IDでログインしてください。</p>
            <form method="post" action="/mail-admin/login">
            <input type="hidden" name="_csrf_token" value="' . $token . '">
            <label>管理者ID（メールアドレス）<input type="email" name="_username" maxlength="254" autocomplete="username" required></label>
            <label>管理者パスワード<input type="password" name="_password" autocomplete="current-password" required></label>
            <button type="submit">ログイン</button></form>');
    }

    public function home(Request $request): Response
    {
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof AdminUser || !$user->active) { return self::page('アクセス拒否', '', 403); }
        $logoutToken = self::escape($this->csrf->getToken('mail_admin_logout')->getValue());
        $verified = AdminFactorGate::verified($user, $request->getSession()->get(AdminFactorGate::SESSION_KEY), time());
        return self::page('メール管理', '<p>管理者ID: ' . self::escape($user->getUserIdentifier()) . '</p>
            <p role="status">' . ($verified ? 'パスキー本人確認済み。' : 'パスワード認証済み。管理操作にはパスキーによる本人確認が必要です。') . '</p>
            ' . self::passkeyPanel($this->csrf, !$verified) . '
            <p>管理メニューは関連する設定ごとに分類しています。配送先の切替えは「配送・SMTP送信」から開いてください。</p>
            <form method="post" action="/mail-admin/logout"><input type="hidden" name="_csrf_token" value="'
            . $logoutToken . '"><button type="submit">ログアウト</button></form>');
    }

    /** Authentication UI only: never retain or replay a rejected management POST. */
    public static function factorRequired(Request $request, CsrfTokenManagerInterface $csrf): Response
    {
        $notice = $request->isMethod('POST')
            ? '<p role="alert">操作は実行していません。本人確認後、管理設定で内容を確認して再度保存してください。</p>' : '';
        return self::page('パスキーによる本人確認', $notice . self::passkeyPanel($csrf, true)
            . '<p><a href="/mail-admin/">メール管理に戻る</a></p>', 403);
    }

    private static function passkeyPanel(CsrfTokenManagerInterface $csrf, bool $automatic): string
    {
        $token = self::escape($csrf->getToken('mail_admin_passkey')->getValue());
        return '<section id="admin-passkey" data-csrf="' . $token . '" data-auto-assert="'
            . ($automatic ? 'true' : 'false') . '">
            <h2>' . ($automatic ? 'パスキーによる本人確認' : 'パスキーの追加登録') . '</h2>
            <div id="admin-passkey-enrollment"' . ($automatic ? ' hidden' : '') . '>
            <label>登録名<input id="admin-passkey-label" maxlength="128" value="" autocomplete="off"></label>
            <button type="button" id="admin-passkey-register">パスキーを登録</button></div>
            <button type="button" id="admin-passkey-retry" hidden>認証を再試行</button>
            <p id="admin-passkey-result" role="status" aria-live="polite"></p>
            <noscript>管理操作にはJavaScriptを有効にしてパスキー認証を行う必要があります。</noscript></section>
            <script src="/mail-admin/passkey.js" defer></script>';
    }

    public function passkeyOptions(Request $request, string $kind): Response
    {
        return $this->factorRequest($request, function (AdminUser $user, array $body) use ($request, $kind): array {
            if (!is_string($body['label'] ?? '')) { throw new \DomainException('invalid_label'); }
            return ['publicKey' => $this->passkeys->start($user, $request->getSession(), $kind, $body['label'] ?? '')];
        });
    }

    public function passkeyFinish(Request $request, string $kind): Response
    {
        return $this->factorRequest($request, function (AdminUser $user, array $body) use ($request, $kind): array {
            if (!is_array($body['credential'] ?? null)) { throw new \DomainException('invalid_response'); }
            $this->passkeys->finish($user, $request->getSession(), $kind,
                json_encode($body['credential'], JSON_THROW_ON_ERROR));
            return ['completed' => true];
        });
    }

    public function passkeyScript(): Response
    {
        return new Response(file_get_contents(dirname(__DIR__) . '/public/passkey.js'), 200, [
            'Content-Type' => 'application/javascript; charset=UTF-8', 'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff']);
    }

    private function factorRequest(Request $request, callable $operation): Response
    {
        try {
            $user = $this->tokens->getToken()?->getUser();
            if (!$user instanceof AdminUser || !$user->active || !$request->isMethod('POST')
                || $request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
                || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN
                || !$this->csrf->isTokenValid(new CsrfToken('mail_admin_passkey', $request->headers->get('X-CSRF-Token', '')))) {
                return new JsonResponse(['ok' => false, 'error' => 'not_authorized'], 403, ['Cache-Control' => 'no-store']);
            }
            if (!$this->factorLimiter->create($user->id . ':' . $request->getClientIp())->consume()->isAccepted()) {
                return new JsonResponse(['ok' => false, 'error' => 'too_many_attempts'], 429, ['Cache-Control' => 'no-store']);
            }
            $input = $request->getContent();
            if (strlen($input) > 131072 || $request->getContentTypeFormat() !== 'json') { throw new \DomainException('invalid_response'); }
            $body = json_decode($input, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($body)) { throw new \DomainException('invalid_response'); }
            return new JsonResponse(['ok' => true] + $operation($user, $body), 200, ['Cache-Control' => 'no-store']);
        } catch (\DomainException $e) {
            // Only fixed local codes; never upstream response or DB errors.
            $code = in_array($e->getMessage(), ['invalid_label', 'recent_passkey_required', 'recent_password_login_required',
                'challenge_expired_or_used', 'no_enabled_passkey', 'passkey_storage_unavailable', 'admin_session_changed',
                'passkey_validation_failed', 'registration_not_allowed', 'duplicate_credential', 'result_unverified'], true)
                ? $e->getMessage() : 'passkey_failed';
            return new JsonResponse(['ok' => false, 'error' => $code], 400, ['Cache-Control' => 'no-store']);
        } catch (\Throwable) {
            return new JsonResponse(['ok' => false, 'error' => 'passkey_failed'], 400, ['Cache-Control' => 'no-store']);
        }
    }

    public function manage(Request $request): Response
    {
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof AdminUser || !AdminFactorGate::permits($user,
            $request->getSession()->get(AdminFactorGate::SESSION_KEY), time())) {
            return self::page('本人確認が必要です', '<p>管理操作は許可されていません。</p>', 403);
        }
        // No mutating routes, DB policy writes or service operations in this checkpoint.
        return self::page('管理機能は未有効です', '<p>本番の管理操作はまだ配置されていません。</p>', 503);
    }

    public static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function page(string $title, string $content, int $status = 200, ?string $stylesheet = null): Response
    {
        // Only caller-supplied static UI CSS, with a response-specific CSP nonce.
        $stylesheet = ($stylesheet ?? '') . "\n" . self::darkStylesheet() . "\n" . self::feedbackStylesheet() . "\n" . AdminNavigation::stylesheet();
        $nonce = base64_encode(random_bytes(18));
        $style = '<style nonce="' . self::escape($nonce) . '">' . $stylesheet . '</style>';
        $stylePolicy = "style-src 'nonce-" . $nonce . "'; ";
        // Mark only a leading message paragraph, never a form/control or rejected POST data.
        if ($status >= 400) { $content = preg_replace('/\A\s*<p>/', '<p role="alert">', $content, 1) ?? $content; }
        $headingRole = $status >= 400 && !str_contains($content, 'role="alert"') ? ' role="alert"' : '';
        $navigation = !in_array($title, ['メール管理者ログイン','アクセス拒否'], true);
        $opening = $navigation ? '<div class="admin-shell">'.AdminNavigation::render($title) : '';
        $closing = $navigation ? '</div>' : '';
        return new Response('<!doctype html><html lang="ja"><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . self::escape($title) . '</title>' . $style . $opening . '<main><h1' . $headingRole . '>' . self::escape($title)
            . '</h1>' . $content . '</main>' . $closing . '</html>', $status, [
                'Content-Type' => 'text/html; charset=UTF-8', 'Cache-Control' => 'no-store',
                'Content-Security-Policy' => "default-src 'none'; " . $stylePolicy . "script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
                'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'same-origin',
            ]);
    }

    private static function darkStylesheet(): string
    {
        return <<<'CSS'
html{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#20292e;color:#e6edf0;font:16px/1.6 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:28px 24px 60px}h1{font-size:26px;margin:0 0 18px}h2{font-size:20px}main a{color:#78d4fa}main label{display:flex;flex-direction:column;gap:5px}main input,main select,main textarea,main button{font:inherit;border-radius:6px}main input,main select,main textarea{background:#1e272c;color:#e6edf0;border:1px solid #73858f;padding:9px;min-width:0;max-width:100%;accent-color:#58c4ef}main input::placeholder,main textarea::placeholder{color:#bac7cf;opacity:1}main button{background:#096b8c;border:1px solid #48b5dc;color:#fff;padding:9px 16px;cursor:pointer}main button:disabled{opacity:.65;cursor:default}main>form{display:grid;gap:16px;max-width:560px;margin:20px 0}#admin-passkey{background:#2d373c;border:1px solid #52636b;border-radius:10px;padding:20px;margin:20px 0}#admin-passkey label{max-width:560px;margin-bottom:14px}#admin-passkey h2{margin:0 0 16px}.admin-panel,.admin-record{background:#2d373c;border-color:#52636b}.admin-create{background:#253036;border-color:#52636b}.admin-editor fieldset,main fieldset{border:1px solid #52636b;border-radius:8px}.admin-notice{background:#253e4b;color:#d3e9f4}.admin-tabs{border-color:#52636b}.admin-tabs a{color:#d3dfe7}.admin-tabs a:hover{background:#33454e}.admin-tabs a[aria-selected=true]{background:#2d373c;color:#78d4fa;border-bottom-color:#78d4fa}.admin-count{background:#41545f;color:#eef5f8}.admin-results,.admin-meta,.admin-footnote{color:#bac7cf}.admin-badge{background:#41505b;color:#d3dfe7}.admin-badge.is-active{background:#143d2c;color:#b2f4cf}.admin-pager button{background:#2d373c;color:#78d4fa;border-color:#73858f}form[action$="/alias_remove"] button{background:#852e39;border-color:#d98089;color:#fff}main table{border-collapse:collapse;width:100%;background:#2d373c}main th,main td{border:1px solid #52636b;padding:10px;text-align:left}main th{background:#253e4b}main a:focus-visible,main summary:focus-visible,main input:focus-visible,main select:focus-visible,main textarea:focus-visible,main button:focus-visible{outline:3px solid #78d4fa;outline-offset:3px}[hidden]{display:none!important}@media(max-width:640px){main{padding:18px 12px}h1{font-size:22px}#admin-passkey{padding:16px}}
CSS;
    }

    private static function feedbackStylesheet(): string
    {
        return <<<'CSS'
main [role=status]:not(:empty),main [role=alert]:not(:empty){box-sizing:border-box;background:#fff1a8!important;color:#1f2937!important;border:1px solid #b88700;border-left:6px solid #b88700;border-radius:.35rem;padding:.75rem 1rem;margin:.75rem 0;line-height:1.5;font-weight:600;overflow-wrap:anywhere}
main [role=status] a,main [role=alert] a{color:#4a3300!important;text-decoration:underline}
#admin-passkey-result:empty{display:none}
CSS;
    }
}
