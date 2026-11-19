<?php
declare(strict_types=1);

use MISystem\RoundcubeCompat\AccountDirectory;
use MISystem\RoundcubeCompat\LoginView;

require_once dirname(__DIR__) . '/mi_system_compat/AccountDirectory.php';
require_once dirname(__DIR__) . '/mi_system_compat/LoginView.php';

class session_epoch_guard extends rcube_plugin
{
    public $task = '.*';
    private const SESSION_KEY = 'mail_auth_epoch';
    private AccountDirectory $directory;

    public function init(): void
    {
        $settings = AccountDirectory::settings();
        if ($settings === null) {
            return;
        }
        $this->directory = new AccountDirectory($settings);
        $this->add_hook('login_after', [$this, 'remember']);
        $this->add_hook('ready', [$this, 'check']);
        $this->add_hook('loginform_content', [$this, 'notice']);
    }

    protected function lookup(): ?string
    {
        $mailbox = LoginView::mailbox(rcmail::get_instance());
        if ($mailbox === '') {
            return null;
        }
        try {
            return $this->directory->epoch($mailbox);
        } catch (Throwable) {
            rcube::write_log('session_epoch_guard', 'auth_epoch lookup failed');
            return null;
        }
    }

    public function remember(array $state): array
    {
        $epoch = $this->lookup();
        if ($epoch !== null) {
            $_SESSION[self::SESSION_KEY] = $epoch;
        }
        return $state;
    }

    public function check(array $state): array
    {
        $client = rcmail::get_instance();
        if (empty($_SESSION['user_id']) || $client->task === 'logout') {
            return $state;
        }
        $current = $this->lookup();
        if ($current === null) {
            return $state;
        }
        $before = $_SESSION[self::SESSION_KEY] ?? null;
        if ($before === null) {
            $_SESSION[self::SESSION_KEY] = $current;
        } elseif ((string) $before !== $current) {
            $this->revoke($client);
        }
        return $state;
    }

    protected function revoke(object $client): void
    {
        $client->logout_actions();
        $client->kill_session();
        LoginView::redirect('./?_session_revoked=1');
    }

    public function notice(array $form): array
    {
        if (isset($_GET['_session_revoked']) && is_array($form['inputs'] ?? null)) {
            $form['inputs'] = ['mail_auth_session_revoked' => [
                'content' => LoginView::notice('パスワードが変更されたため、再ログインしてください。'),
            ]] + $form['inputs'];
        }
        return $form;
    }
}
