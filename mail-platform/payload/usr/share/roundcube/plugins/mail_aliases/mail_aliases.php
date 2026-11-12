<?php

declare(strict_types=1);
use MailServer\AliasUi\RequestPolicy;
use MailServer\Management\AliasRepository;

/** Candidate only. Existing Roundcube login/CSRF and unchanged alias transactions are reused. */
final class mail_aliases extends rcube_plugin
{
    public $task = 'settings';
    private rcmail $rc;

    public function init(): void
    {
        require_once __DIR__ . '/src/RequestPolicy.php';
        $this->rc = rcmail::get_instance();
        $this->load_config();
        $this->add_texts('localization/', true);
        $this->add_hook('settings_actions', [$this, 'settingsActions']);
        $this->register_action('plugin.mail_aliases', [$this, 'show']);
        $this->register_action('plugin.mail_aliases-rpc', [$this, 'rpc']);
        $this->include_script('mail_aliases.js');
        $this->include_stylesheet('mail_aliases.css');
    }

    public function settingsActions(array $args): array
    {
        try { $this->actor(); }
        catch (Throwable) { return $args; }
        $args['actions'][] = ['action' => 'plugin.mail_aliases', 'class' => 'mail-aliases',
            'label' => 'aliases', 'domain' => 'mail_aliases'];
        return $args;
    }

    public function show(): void
    {
        try { $this->actor(); }
        catch (Throwable) { $this->json(403, ['ok' => false, 'error_code' => 'not_authorized']); }
        $this->rc->output->set_pagetitle($this->gettext('aliases'));
        $this->rc->output->send('mail_aliases.aliases');
    }

    public function rpc(): never
    {
        try {
            $actor = $this->actor();
            if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { throw new DomainException('invalid_request'); }
            // Same existing Roundcube header/token and native security check as local_auth.
            $header = rcube_utils::request_header('X-Roundcube-Request');
            if (!is_string($header) || !hash_equals($this->rc->get_request_token(), $header)) {
                throw new DomainException('not_authorized');
            }
            $this->rc->request_security_check(rcube_utils::INPUT_POST);
            $body = file_get_contents('php://input', false, null, 0, 8193);
            if (!is_string($body) || strlen($body) > 8192) { throw new DomainException('invalid_request'); }
            $input = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($input)) { throw new DomainException('invalid_request'); }
            $command = RequestPolicy::command($input);
            $repository = $this->repository();
            switch ($command['kind']) {
                case 'list': $this->json(200, ['ok' => true, 'aliases' => $repository->listOwned($actor),
                    'preferences' => $repository->addressPreferences($actor),
                    'usage' => $repository->aliasUsage($actor)]);
                case 'preferences': $repository->saveAddressPreferences($actor, $command['ignore_dots'], $command['allow_plus']); break;
                case 'create': $repository->create($actor, $command['local_part']); break;
                case 'state': $repository->setEnabled($actor, $command['id'], $command['enabled']); break;
                case 'remove': $repository->remove($actor, $command['id']); break;
            }
            $this->json(200, ['ok' => true]);
        } catch (Throwable $error) {
            $code = $error instanceof DomainException ? $error->getMessage() : 'unavailable';
            if (!in_array($code, ['not_authorized', 'invalid_request', 'alias_limit', 'invalid_alias',
                'alias_unavailable', 'read_unavailable', 'result_unverified', 'alias_binding', 'schema_not_ready'], true)) {
                $code = 'unavailable';
            }
            $this->json(400, ['ok' => false, 'error_code' => $code]);
        }
    }

    private function actor(): string
    {
        $pilots = $this->rc->config->get('mail_aliases_pilot_users', []);
        return RequestPolicy::actor($this->rc->config->get('mail_aliases_enabled', false) === true,
            is_array($pilots) ? $pilots : [], $_SESSION['user_id'] ?? null,
            $_SESSION['username'] ?? null, $this->rc->get_user_name());
    }

    private function repository(): AliasRepository
    {
        require_once __DIR__ . '/core/AliasPolicy.php';
        require_once __DIR__ . '/core/AliasRepository.php';
        // Dedicated least-privilege principal/config must be provisioned separately, never reuse admin credentials.
        $path = '/etc/roundcube/mail-aliases.php';
        $info = lstat($path);
        if (!is_file($path) || is_link($path) || !$info || $info['uid'] !== 0 || $info['gid'] !== 33
            || ($info['mode'] & 0777) !== 0640) { throw new DomainException('unavailable'); }
        $config = require $path;
        if (!is_array($config) || ($config['user'] ?? null) !== 'mail_alias_ui'
            || !is_string($config['password'] ?? null) || !is_string($config['dsn'] ?? null)
            || !preg_match('~^mysql:unix_socket=/[A-Za-z0-9/._-]+;dbname=mail_management;charset=utf8mb4$~D', $config['dsn'])) {
            throw new DomainException('unavailable');
        }
        return new AliasRepository(new PDO($config['dsn'], $config['user'], $config['password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]));
    }

    private function json(int $status, array $data): never
    {
        while (ob_get_level() > 0) { ob_end_clean(); }
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($data, JSON_THROW_ON_ERROR);
        exit;
    }
}
