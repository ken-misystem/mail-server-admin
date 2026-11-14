<?php
declare(strict_types=1);
/** MI-SYSTEM mail settings. SPDX-License-Identifier: MIT */
use MiSystem\MailSettings\{AccountLock, NetSieveConnection, Script, Service};

final class mail_settings extends rcube_plugin
{
    public $task = 'settings';
    private rcmail $rc;

    public function init(): void
    {
        foreach (['Script', 'Document', 'Service', 'AccountLock'] as $name) require_once __DIR__ . '/src/' . $name . '.php';
        $this->rc = rcmail::get_instance();
        $this->load_config();
        if ($this->rc->config->get('mail_settings_enabled', false) !== true) return;
        $this->add_texts('localization/');
        $this->add_hook('settings_actions', [$this, 'menu']);
        $this->register_action('plugin.mail_settings', [$this, 'show']);
        $this->register_action('plugin.mail_settings-rpc', [$this, 'rpc']);
        $this->include_script('mail_settings.js');
        $this->include_script('document_editor.js');
        $this->include_stylesheet('mail_settings.css');
    }

    public function menu(array $args): array
    {
        try { $this->owner(); }
        catch (Throwable) { return $args; }
        $args['actions'][] = ['action' => 'plugin.mail_settings', 'class' => 'filter',
            'label' => 'mailsettings', 'domain' => 'mail_settings'];
        return $args;
    }

    private function owner(): string
    {
        $plugins = $this->rc->config->get('plugins', []);
        if (!is_array($plugins) || in_array('managesieve', $plugins, true)
            || !in_array('session_epoch_guard', $plugins, true) || !in_array('local_auth_gate', $plugins, true)
            || $this->rc->config->get('mail_settings_enabled', false) !== true
            || $this->rc->session->check_auth() !== true) throw new DomainException('not_authorized');
        $gate = $this->rc->plugins->get_plugin('local_auth_gate');
        $route = ['task' => 'settings', 'action' => 'plugin.mail_settings'];
        if (!$gate instanceof local_auth_gate || $gate->startup($route) !== $route) throw new DomainException('not_authorized');
        $id = $this->rc->get_user_id();
        if (!is_int($id) || $id <= 0 || (string) ($_SESSION['user_id'] ?? '') !== (string) $id
            || !is_string($_SESSION['username'] ?? null)
            || strtolower($_SESSION['username']) !== strtolower($this->rc->get_user_name())) throw new DomainException('not_authorized');
        require_once dirname(__DIR__) . '/local_auth/AccountIdentity.php';
        try {
            return \MailServer\RoundcubePasskeyGeneral\AccountIdentity::requireOwner($this->rc->get_dbh(), $id, $this->rc->get_user_name());
        } catch (Throwable) { throw new DomainException('not_authorized'); }
    }

    public function show(): void
    {
        try { $this->owner(); }
        catch (Throwable) { $this->json(403, ['ok' => false, 'error_code' => 'not_authorized']); }
        $this->rc->output->set_pagetitle('転送・フィルター・休暇応答');
        $this->rc->output->send('mail_settings.settings');
    }

    public function rpc(): never
    {
        try {
            $owner = $this->owner();
            $header = rcube_utils::request_header('X-Roundcube-Request');
            $token = $this->rc->get_request_token();
            if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !is_string($header) || !is_string($token)
                || strlen($token) < 16 || !hash_equals($token, $header)) throw new DomainException('not_authorized');
            $this->rc->request_security_check(rcube_utils::INPUT_POST);
            $raw = file_get_contents('php://input', false, null, 0, 1048577);
            if (!is_string($raw) || strlen($raw) > 1048576) throw new DomainException('invalid_settings');
            $input = json_decode($raw, true, 256, JSON_THROW_ON_ERROR);
            if (!is_array($input) || !is_string($input['operation'] ?? null)
                || array_diff(array_keys($input), ['operation', 'revision', 'model', 'base_source', 'version', 'document', 'source',
                    'script_name', 'script_sha256', 'new_name'])) throw new DomainException('invalid_settings');
            if ($input['operation'] === 'parse_source' && is_string($input['source'] ?? null)) {
                $this->json(200, ['ok' => true, 'document' => \MiSystem\MailSettings\Document::parse($input['source'])]);
            }
            $lock = new AccountLock('/var/lib/roundcube/mail-settings-locks', $owner);
            require_once 'Net/Sieve.php';
            require_once __DIR__ . '/src/NetSieveConnection.php';
            $peer = $this->rc->config->get('mail_settings_sieve_peer_name');
            if (!is_string($peer) || !is_string($_SESSION['password'] ?? null)) throw new DomainException('not_authorized');
            $password = $this->rc->decrypt($_SESSION['password']);
            $connection = new NetSieveConnection($owner, $password, $peer);
            unset($password);
            $service = new Service($connection);
            $inspected = null;
            if ($input['operation'] === 'load') {
                $snapshot = $service->snapshot();
            } elseif ($input['operation'] === 'inspect_set' && is_string($input['script_name'] ?? null)) {
                $snapshot = $service->snapshot();
                $inspected = $service->inspectSet($input['script_name']);
            } else {
                if (!is_string($input['revision'] ?? null) || !preg_match('/\A[a-f0-9]{64}\z/D', $input['revision'])) throw new DomainException('invalid_settings');
                if ($input['operation'] === 'save' && is_array($input['model'] ?? null)
                    && (!isset($input['base_source']) || is_string($input['base_source']))) {
                    $snapshot = $service->save($input['revision'], $input['model'], $input['base_source'] ?? null);
                } elseif ($input['operation'] === 'save_document' && is_array($input['document'] ?? null)) {
                    $snapshot = $service->saveDocument($input['revision'], $input['document']);
                } elseif ($input['operation'] === 'save_base_document' && is_array($input['document'] ?? null)) {
                    $snapshot = $service->saveBaseDocument($input['revision'], $input['document']);
                } elseif ($input['operation'] === 'restore' && is_string($input['version'] ?? null)) {
                    $snapshot = $service->restore($input['revision'], $input['version']);
                } elseif ($input['operation'] === 'copy_set' && is_string($input['new_name'] ?? null) && is_array($input['document'] ?? null)) {
                    $snapshot = $service->copySet($input['revision'], $input['new_name'], $input['document']);
                } elseif (in_array($input['operation'], ['activate_set', 'delete_set', 'rename_set'], true)
                    && is_string($input['script_name'] ?? null) && is_string($input['script_sha256'] ?? null)) {
                    if ($input['operation'] === 'activate_set') $snapshot = $service->activateSet($input['revision'], $input['script_name'], $input['script_sha256']);
                    elseif ($input['operation'] === 'delete_set') $snapshot = $service->deleteSet($input['revision'], $input['script_name'], $input['script_sha256']);
                    elseif (is_string($input['new_name'] ?? null)) $snapshot = $service->renameSet($input['revision'], $input['script_name'], $input['script_sha256'], $input['new_name']);
                    else throw new DomainException('invalid_settings');
                } else { throw new DomainException('invalid_settings'); }
            }
            $versions = $service->versions();
            unset($service, $connection, $lock);
            $this->json(200, ['ok' => true, 'snapshot' => $snapshot, 'versions' => $versions, 'inspected' => $inspected]);
        } catch (Throwable $error) {
            $allowed = ['not_authorized', 'invalid_settings', 'invalid_address', 'invalid_script', 'invalid_version',
                'managed_script_changed', 'base_script_changed', 'settings_conflict', 'settings_busy', 'script_limit',
                'script_too_large', 'save_unverified', 'result_unverified', 'lock_unavailable', 'snapshot_collision', 'script_referenced'];
            $code = $error instanceof DomainException && in_array($error->getMessage(), $allowed, true) ? $error->getMessage() : 'unavailable';
            $this->json(400, ['ok' => false, 'error_code' => $code]);
        }
    }

    private function json(int $status, array $payload): never
    {
        while (ob_get_level() > 0) ob_end_clean();
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($payload, JSON_THROW_ON_ERROR);
        exit;
    }
}
