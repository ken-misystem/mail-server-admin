<?php
declare(strict_types=1);

use MISystem\RoundcubeCompat\AccountDirectory;
use MISystem\RoundcubeCompat\LoginView;

require_once dirname(__DIR__) . '/mi_system_compat/AccountDirectory.php';
require_once dirname(__DIR__) . '/mi_system_compat/LoginView.php';

class account_recovery extends rcube_plugin
{
    public $task = '.*';
    public $noajax = true;
    private const SHOW = 'plugin.account-recovery';
    private const SAVE = 'plugin.account-recovery-save';
    private array $settings;
    private AccountDirectory $directory;

    public function init(): void
    {
        $settings = AccountDirectory::settings();
        if ($settings === null) {
            return;
        }
        $this->settings = $settings;
        $this->directory = new AccountDirectory($settings);
        $roundcube = rcmail::get_instance();
        $this->add_texts('localization/');
        $this->add_hook('ready', [$this, 'reminder']);
        if (array_key_exists('_recovery_verify', $_GET)) {
            $this->confirmLink($_GET['_recovery_verify']);
        }
        if ($roundcube->task === 'settings') {
            $this->add_hook('settings_actions', [$this, 'menu']);
            $this->register_action(self::SHOW, [$this, 'page']);
            $this->register_action(self::SAVE, [$this, 'save']);
        } elseif ($roundcube->task === 'login') {
            $this->add_hook('loginform_content', [$this, 'resultNotice']);
        }
    }

    public function menu(array $options): array
    {
        $options['actions'][] = ['action' => self::SHOW, 'class' => 'account-recovery',
            'label' => 'accountrecovery', 'domain' => 'account_recovery'];
        return $options;
    }

    public function page(): void
    {
        $this->register_handler('plugin.body', [$this, 'body']);
        $output = rcmail::get_instance()->output;
        $output->set_pagetitle('アカウント復旧');
        $output->send('plugin');
    }

    public function body(): string
    {
        $rc = rcmail::get_instance();
        $mailbox = LoginView::mailbox($rc);
        if (empty($_SESSION['user_id']) || $mailbox === '') {
            return '';
        }
        try {
            $row = $this->directory->recovery($mailbox);
        } catch (Throwable) {
            return LoginView::notice('復旧用メールアドレスの状態を取得できません。', 'error');
        }
        $body = '';
        if (isset($_GET['_recovery_verified'])) {
            [$message, $status] = $this->result();
            $body .= LoginView::notice($message, $status);
        }
        $body .= html::tag('p', [], '登録済みの復旧先 ' . rcube::Q($row['recovery_email'] ?? '未登録'));
        if (!empty($row['verified_at'])) {
            $body .= html::tag('p', [], '確認日時 ' . rcube::Q($row['verified_at']));
        }
        if (!empty($row['pending_email'])) {
            $body .= html::tag('p', [], '確認待ち ' . rcube::Q($row['pending_email']));
        }
        $fields = html::tag('input', ['type' => 'hidden', 'name' => '_token',
            'value' => $rc->get_request_token()]);
        $fields .= html::tag('label', ['for' => 'recovery_email'], '復旧用メールアドレス');
        $fields .= html::tag('input', ['type' => 'email', 'name' => '_recovery_email',
            'id' => 'recovery_email', 'autocomplete' => 'email', 'required' => true,
            'placeholder' => 'name@example.com',
            'value' => ($row['pending_email'] ?? '') ?: ($row['recovery_email'] ?? '')]);
        $fields .= html::tag('button', ['type' => 'submit', 'class' => 'button mainaction'], '確認メールを送る');
        return $body . html::tag('form', ['method' => 'post',
            'action' => $rc->url(['_task' => 'settings', '_action' => self::SAVE])], $fields);
    }

    public function save(): void
    {
        $rc = rcmail::get_instance();
        $mailbox = LoginView::mailbox($rc);
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || empty($_SESSION['user_id']) || $mailbox === '') {
            http_response_code(403);
            return;
        }
        $rc->request_security_check(rcube_utils::INPUT_POST);
        $address = strtolower(trim((string) rcube_utils::get_input_string('_recovery_email', rcube_utils::INPUT_POST)));
        $domains = $this->settings['local_domains'] ?? [
            'mi-sys.jp', 'yukido.co.jp', 'mi-system.jp', 'archive.jpn.com', 'hello.jpn.com', 'srs.mi-sys.jp',
        ];
        if (!AccountDirectory::externalAddress($address, $domains)) {
            $rc->output->command('display_message', '有効な外部メールアドレスを入力してください。', 'error');
            $this->page();
            return;
        }
        $ok = false;
        try {
            $token = AccountDirectory::token();
            $hash = hash('sha256', $token);
            $link = $this->base() . '/?_recovery_verify=' . rawurlencode($token);
            $this->directory->start($mailbox, $address, $hash,
                max(300, (int) ($this->settings['verify_token_lifetime'] ?? 3600)));
            try {
                $ok = $this->deliver($address, $link);
            } finally {
                if (!$ok) {
                    $this->directory->cancel($mailbox, $hash);
                }
            }
        } catch (Throwable) {
            rcube::write_log('account_recovery', 'verification request failed');
        }
        $rc->output->command('display_message',
            $ok ? '確認メールを送信しました。' : '確認メールを送信できませんでした。',
            $ok ? 'confirmation' : 'error');
        $this->page();
    }

    private function base(): string
    {
        $base = rtrim((string) ($this->settings['base_url'] ?? ''), '/');
        $parts = parse_url($base);
        if (($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || array_intersect(['user', 'pass', 'query', 'fragment'], array_keys($parts))
            || !filter_var($base, FILTER_VALIDATE_URL)) {
            throw new RuntimeException('recovery_base_url');
        }
        return $base;
    }

    protected function deliver(string $recipient, string $link): bool
    {
        $from = (string) ($this->settings['mail_from'] ?? '');
        if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        $body = "復旧用メールアドレスの登録を確認します。\n\n" . $link
            . "\n\n心当たりがない場合は、このメールを破棄してください。\n";
        $smtp = new rcube_smtp();
        if (!$smtp->connect('127.0.0.1', '25', '', '')) {
            return false;
        }
        try {
            return (bool) $smtp->send_mail($from, $recipient, [
                'From' => $from, 'To' => $recipient, 'Date' => date(DATE_RFC2822),
                'Message-ID' => '<' . bin2hex(random_bytes(16)) . '@' . substr(strrchr($from, '@'), 1) . '>',
                'Subject' => '=?UTF-8?B?' . base64_encode('復旧用メールアドレスの確認') . '?=',
                'MIME-Version' => '1.0', 'Content-Type' => 'text/plain; charset=UTF-8',
                'Content-Transfer-Encoding' => 'base64', 'Auto-Submitted' => 'auto-generated',
                'X-Auto-Response-Suppress' => 'All',
            ], chunk_split(base64_encode($body), 76, "\r\n"));
        } finally {
            $smtp->disconnect();
        }
    }

    private function confirmLink(mixed $input): never
    {
        $base = $this->base();
        $confirmed = false;
        try {
            if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && is_string($input)) {
                $confirmed = $this->directory->confirm(trim($input));
            }
        } catch (Throwable) {
            rcube::write_log('account_recovery', 'verification failed');
        }
        $query = !empty($_SESSION['user_id']) ? ['_task' => 'settings', '_action' => self::SHOW] : [];
        $query['_recovery_verified'] = $confirmed ? '1' : '0';
        header('Referrer-Policy: no-referrer');
        LoginView::redirect($base . '/?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986));
    }

    public function reminder(array $state): array
    {
        $rc = rcmail::get_instance();
        if (empty($_SESSION['user_id']) || !empty($_SESSION['account_recovery_caution_checked'])) {
            return $state;
        }
        $mailbox = LoginView::mailbox($rc);
        if ($mailbox === '') {
            return $state;
        }
        $_SESSION['account_recovery_caution_checked'] = true;
        try {
            $row = $this->directory->recovery($mailbox);
            if (empty($row['recovery_email']) || empty($row['verified_at'])) {
                $rc->output->command('display_message',
                    '復旧用メールアドレスが未登録または未確認です。設定 → アカウント復旧から登録・確認してください。',
                    'warning');
            }
        } catch (Throwable) {
            rcube::write_log('account_recovery', 'recovery lookup failed');
        }
        return $state;
    }

    private function result(): array
    {
        return ($_GET['_recovery_verified'] ?? '') === '1'
            ? ['復旧用メールアドレスを確認しました。', 'success']
            : ['確認URLが無効、または有効期限切れです。', 'error'];
    }

    public function resultNotice(array $form): array
    {
        if (isset($_GET['_recovery_verified'])) {
            [$message, $status] = $this->result();
            $form['content'] = LoginView::notice($message, $status) . ($form['content'] ?? '');
        }
        return $form;
    }
}
