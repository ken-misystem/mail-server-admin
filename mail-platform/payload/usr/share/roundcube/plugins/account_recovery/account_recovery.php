<?php

class account_recovery extends rcube_plugin
{
    public $task = '.*';
    public $noajax = true;

    private $rc;
    private $cfg;

    public function init()
    {
        $this->rc = rcmail::get_instance();

        $cfgfile = '/etc/roundcube/account_recovery.inc.php';

        if (!is_readable($cfgfile)) {
            return;
        }

        $this->cfg = require $cfgfile;

        $this->add_texts('localization/');

        $this->add_hook(
            'ready',
            [$this, 'recovery_caution']
        );

        // Verification links must work regardless of the current
        // Roundcube task. An authenticated user normally lands in
        // task=mail, not task=login.
        if (isset($_GET['_recovery_verify'])) {
            $token = trim((string) $_GET['_recovery_verify']);
            $result = $this->verify($token);

            $base = rtrim($this->cfg['base_url'], '/');

            $logged_in =
                isset($this->rc->user)
                && $this->rc->user
                && !empty($this->rc->user->ID);

            if ($logged_in) {
                $dest =
                    $base
                    . '/?_task=settings'
                    . '&_action=plugin.account-recovery'
                    . '&_recovery_verified='
                    . ($result ? '1' : '0');
            } else {
                $dest =
                    $base
                    . '/?_recovery_verified='
                    . ($result ? '1' : '0');
            }

            header('Location: ' . $dest, true, 303);
            exit;
        }

        if ($this->rc->task === 'settings') {
            $this->add_hook(
                'settings_actions',
                [$this, 'settings_actions']
            );

            $this->register_action(
                'plugin.account-recovery',
                [$this, 'page']
            );

            $this->register_action(
                'plugin.account-recovery-save',
                [$this, 'save']
            );
        }

        if ($this->rc->task === 'login') {
            $this->add_hook(
                'loginform_content',
                [$this, 'loginform_content']
            );
        }
    }

    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.account-recovery',
            'class'  => 'account-recovery',
            'label'  => 'accountrecovery',
            'domain' => 'account_recovery',
        ];

        return $args;
    }

    private function db()
    {
        return new PDO(
            $this->cfg['db_dsn'],
            $this->cfg['db_user'],
            $this->cfg['db_pass'],
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );
    }

    private function username()
    {
        return strtolower(
            trim((string) $this->rc->get_user_name())
        );
    }

    private function row()
    {
        $pdo = $this->db();

        $st = $pdo->prepare(
            'SELECT recovery_email,
                    verified_at,
                    pending_email,
                    verify_expires_at
               FROM account_recovery
              WHERE email = ?'
        );

        $st->execute([$this->username()]);

        return $st->fetch() ?: [];
    }

    public function page()
    {
        $this->register_handler(
            'plugin.body',
            [$this, 'body']
        );

        $this->rc->output->set_pagetitle(
            'アカウント復旧'
        );

        $this->rc->output->send('plugin');
    }

    public function body()
    {
        $row = $this->row();

        $current = $row['recovery_email'] ?? '';
        $pending = $row['pending_email'] ?? '';

        $value = $pending ?: $current;

        $table = new html_table([
            'cols'  => 2,
            'class' => 'propform',
        ]);

        $field = new html_inputfield([
            'name'         => '_recovery_email',
            'id'           => 'recovery_email',
            'size'         => 50,
            'autocomplete' => 'email',
            'placeholder'  => 'name@example.com',
        ]);

        $table->add(
            'title',
            html::label(
                ['for' => 'recovery_email'],
                '復旧用メールアドレス：'
            )
        );

        $table->add(
            '',
            $field->show($value)
        );

        $table->add(
            'title',
            '確認状態：'
        );

        if ($current) {
            $status =
                '確認済み：' . rcube::Q($current);
        } elseif ($pending) {
            $status =
                '確認待ち：' . rcube::Q($pending);
        } else {
            $status = '未登録';
        }

        $table->add('', $status);

        $hidden = new html_hiddenfield([
            'name'  => '_token',
            'value' => $this->rc->get_request_token(),
        ]);

        $button = html::tag(
            'button',
            [
                'type'  => 'submit',
                'class' => 'button mainaction',
            ],
            '確認メールを送信'
        );

        $note = html::p(
            ['class' => 'hint'],
            'Gmail、Outlook、プロバイダー等、'
            . 'このメールサーバーとは別のアドレスを指定してください。'
        );

        $form = html::tag(
            'form',
            [
                'method' => 'post',
                'action' => $this->rc->url([
                    'task'   => 'settings',
                    'action' =>
                        'plugin.account-recovery-save',
                ]),
            ],
            $hidden->show()
            . $table->show()
            . $note
            . html::p(null, $button)
        );

        return html::div(
            ['class' => 'box formcontent'],
            html::div(
                ['class' => 'boxtitle'],
                'アカウント復旧'
            )
            . html::div(
                ['class' => 'boxcontent'],
                $form
            )
        );
    }

    public function save()
    {
        $email = strtolower(
            trim(
                rcube_utils::get_input_string(
                    '_recovery_email',
                    rcube_utils::INPUT_POST
                )
            )
        );

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->rc->output->command(
                'display_message',
                '有効なメールアドレスを入力してください。',
                'error'
            );

            return $this->page();
        }

        $domain = strtolower(
            substr(strrchr($email, '@'), 1)
        );

        $local_domains = [
            'mi-sys.jp',
            'yukido.co.jp',
            'mi-system.jp',
            'archive.jpn.com',
            'hello.jpn.com',
            'srs.mi-sys.jp',
        ];

        if (in_array($domain, $local_domains, true)) {
            $this->rc->output->command(
                'display_message',
                '復旧用メールには外部のメールアドレスを指定してください。',
                'error'
            );

            return $this->page();
        }

        $token = rtrim(
            strtr(
                base64_encode(random_bytes(32)),
                '+/',
                '-_'
            ),
            '='
        );

        $hash = hash('sha256', $token);
        $ttl  = max(
            300,
            (int) $this->cfg['verify_token_lifetime']
        );

        $pdo = $this->db();

        $sql = "
            INSERT INTO account_recovery
                (
                    email,
                    pending_email,
                    verify_token_hash,
                    verify_expires_at
                )
            VALUES
                (
                    ?,
                    ?,
                    ?,
                    DATE_ADD(NOW(), INTERVAL {$ttl} SECOND)
                )
            ON DUPLICATE KEY UPDATE
                pending_email = VALUES(pending_email),
                verify_token_hash = VALUES(verify_token_hash),
                verify_expires_at = VALUES(verify_expires_at)
        ";

        $st = $pdo->prepare($sql);
        $st->execute([
            $this->username(),
            $email,
            $hash,
        ]);

        $url =
            rtrim($this->cfg['base_url'], '/')
            . '/?_recovery_verify='
            . rawurlencode($token);

        if (!$this->send_verification_mail(
            $email,
            $this->username(),
            $url
        )) {
            $st = $pdo->prepare(
                'UPDATE account_recovery
                    SET pending_email = NULL,
                        verify_token_hash = NULL,
                        verify_expires_at = NULL
                  WHERE email = ?
                    AND verify_token_hash = ?'
            );

            $st->execute([
                $this->username(),
                $hash,
            ]);

            $this->rc->output->command(
                'display_message',
                '確認メールを送信できませんでした。',
                'error'
            );

            return $this->page();
        }

        $this->rc->output->command(
            'display_message',
            '確認メールを送信しました。',
            'confirmation'
        );

        return $this->page();
    }

    private function send_verification_mail(
        $to,
        $account,
        $url
    ) {
        $from = $this->cfg['mail_from'];

        $subject_text =
            '復旧用メールアドレスの確認';

        $subject =
            '=?UTF-8?B?'
            . base64_encode($subject_text)
            . '?=';

        $text =
            "メールアカウント {$account} の\n"
            . "復旧用メールアドレスとして登録するための確認です。\n\n"
            . "次のURLを開いて確認してください。\n\n"
            . "{$url}\n\n"
            . "この操作に心当たりがない場合は、"
            . "このメールを無視してください。\n";

        $body = chunk_split(
            base64_encode($text),
            76,
            "\r\n"
        );

        $headers = [
            'Date' => date(DATE_RFC2822),
            'From' => $from,
            'To' => $to,
            'Subject' => $subject,
            'Message-ID' =>
                '<'
                . bin2hex(random_bytes(12))
                . '@mi-sys.jp>',
            'MIME-Version' => '1.0',
            'Content-Type' =>
                'text/plain; charset=UTF-8',
            'Content-Transfer-Encoding' =>
                'base64',
            'Auto-Submitted' =>
                'auto-generated',
            'X-Auto-Response-Suppress' =>
                'All',
        ];

        $smtp = new rcube_smtp();

        if (!$smtp->connect(
            '127.0.0.1',
            '25',
            '',
            ''
        )) {
            rcube::write_log(
                'account_recovery',
                'SMTP connect failed'
            );

            return false;
        }

        $ok = $smtp->send_mail(
            $from,
            $to,
            $headers,
            $body
        );

        if (!$ok) {
            rcube::write_log(
                'account_recovery',
                'verification mail send failed'
            );
        }

        $smtp->disconnect();

        return $ok;
    }

    public function startup($args)
    {
        $token = isset($_GET['_recovery_verify'])
            ? trim((string) $_GET['_recovery_verify'])
            : '';

        if ($token === '') {
            return $args;
        }

        $result = $this->verify($token);

        $base = rtrim(
            $this->cfg['base_url'],
            '/'
        );

        header(
            'Location: '
            . $base
            . '/?_recovery_verified='
            . ($result ? '1' : '0'),
            true,
            303
        );

        exit;
    }

    private function verify($token)
    {
        if (!preg_match(
            '/^[A-Za-z0-9_-]{40,60}$/',
            $token
        )) {
            return false;
        }

        $hash = hash('sha256', $token);
        $pdo  = $this->db();

        $pdo->beginTransaction();

        try {
            $st = $pdo->prepare(
                'SELECT email, pending_email
                   FROM account_recovery
                  WHERE verify_token_hash = ?
                    AND verify_expires_at > NOW()
                    AND pending_email IS NOT NULL
                  FOR UPDATE'
            );

            $st->execute([$hash]);
            $row = $st->fetch();

            if (!$row) {
                $pdo->rollBack();
                return false;
            }

            $st = $pdo->prepare(
                'UPDATE account_recovery
                    SET recovery_email = pending_email,
                        verified_at = NOW(),
                        pending_email = NULL,
                        verify_token_hash = NULL,
                        verify_expires_at = NULL
                  WHERE email = ?
                    AND verify_token_hash = ?'
            );

            $st->execute([
                $row['email'],
                $hash,
            ]);

            $pdo->commit();

            return $st->rowCount() === 1;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            rcube::write_log(
                'account_recovery',
                'verification failed'
            );

            return false;
        }
    }


    public function recovery_caution($args)
    {
        // Show at most once per authenticated Roundcube session.
        if (empty($_SESSION['user_id'])
            || !empty($_SESSION['account_recovery_caution_checked'])) {
            return $args;
        }

        $_SESSION['account_recovery_caution_checked'] = true;

        try {
            $email = $this->username();

            if ($email === '') {
                return $args;
            }

            $pdo = $this->db();

            $st = $pdo->prepare(
                'SELECT 1
                   FROM account_recovery
                  WHERE email = ?
                    AND recovery_email IS NOT NULL
                    AND verified_at IS NOT NULL
                  LIMIT 1'
            );

            $st->execute([$email]);

            if (!$st->fetchColumn()) {
                $this->rc->output->command(
                    'display_message',
                    '復旧用メールアドレスが未登録または未確認です。'
                    . '設定 → アカウント復旧 から登録・確認してください。',
                    'warning'
                );
            }
        }
        catch (Throwable $e) {
            rcube::write_log(
                'account_recovery',
                'recovery caution lookup failed'
            );
        }

        return $args;
    }

    public function loginform_content($args)
    {
        if (!isset($_GET['_recovery_verified'])) {
            return $args;
        }

        if ($_GET['_recovery_verified'] === '1') {
            $msg =
                '復旧用メールアドレスを確認しました。';
            $class = 'success';
        } else {
            $msg =
                '確認URLが無効、または有効期限切れです。';
            $class = 'error';
        }

        $args['content'] =
            html::div(
                [
                    'style' =>
                        'margin-bottom:1rem;'
                        . 'padding:.75rem;'
                        . 'border:1px solid currentColor;',
                    'class' => 'ui-feedback-result ' . $class,
                ],
                rcube::Q($msg)
            )
            . $args['content'];

        return $args;
    }
}
