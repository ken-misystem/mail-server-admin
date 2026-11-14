<?php

class session_epoch_guard extends rcube_plugin
{
    public $task = '.*';

    private $rc;
    private $cfg;

    public function init()
    {
        $this->rc = rcmail::get_instance();

        $file = '/etc/roundcube/account_recovery.inc.php';

        if (!is_readable($file)) {
            return;
        }

        $this->cfg = require $file;

        $this->add_hook('login_after', [$this, 'login_after']);
        $this->add_hook('ready',       [$this, 'ready']);
        $this->add_hook('loginform_content', [$this, 'login_message']);
    }

    private function epoch(string $email): ?int
    {
        try {
            $pdo = new PDO(
                $this->cfg['db_dsn'],
                $this->cfg['db_user'],
                $this->cfg['db_pass'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );

            $st = $pdo->prepare(
                'SELECT auth_epoch
                   FROM virtual_users
                  WHERE email = ?
                    AND active = 1
                  LIMIT 1'
            );

            $st->execute([strtolower($email)]);

            $value = $st->fetchColumn();

            return $value === false ? null : (int) $value;
        }
        catch (Throwable $e) {
            rcube::write_log(
                'session_epoch_guard',
                'auth_epoch lookup failed'
            );

            // DB障害だけで全員をログアウトさせない
            return null;
        }
    }

    public function login_after($args)
    {
        $email = $this->rc->get_user_name();

        if ($email !== null && $email !== '') {
            $epoch = $this->epoch($email);

            if ($epoch !== null) {
                $_SESSION['mail_auth_epoch'] = $epoch;
            }
        }

        return $args;
    }

    public function ready($args)
    {
        if (empty($_SESSION['user_id'])
            || $this->rc->task === 'logout') {
            return $args;
        }

        $email = $this->rc->get_user_name();

        if (!$email) {
            return $args;
        }

        $current = $this->epoch($email);

        if ($current === null) {
            return $args;
        }

        // プラグイン導入前の既存セッションは現在値で初期化
        if (!isset($_SESSION['mail_auth_epoch'])) {
            $_SESSION['mail_auth_epoch'] = $current;
            return $args;
        }

        if ((int) $_SESSION['mail_auth_epoch'] !== $current) {
            $this->rc->logout_actions();
            $this->rc->kill_session();

            header(
                'Location: ./?_session_revoked=1',
                true,
                303
            );
            exit;
        }

        return $args;
    }

    public function login_message($args)
    {
        if (!isset($_GET['_session_revoked']) || !isset($args['inputs']) || !is_array($args['inputs'])) {
            return $args;
        }

        $notice = html::div(
                [
                    'style' =>
                        'margin-bottom:1rem;'
                        . 'padding:.75rem;'
                        . 'border:1px solid currentColor;',
                ],
                'パスワードが変更されたため、再ログインしてください。'
            );
        $args['inputs'] = ['mail_auth_session_revoked' => ['content' => $notice]] + $args['inputs'];

        return $args;
    }
}
