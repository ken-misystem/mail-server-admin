<?php

declare(strict_types=1);

use MailServer\RoundcubeAuth\AssertionChallengeStore;
use MailServer\RoundcubeAuth\AssertionService;
use MailServer\RoundcubeAuth\RegistrationConfig;
use MailServer\RoundcubeAuth\RegistrationException;
use MailServer\RoundcubeAuth\RoundcubeCredentialRepository;
use MailServer\RoundcubeAuth\WebauthnLibAssertionValidator;
use MailServer\RoundcubeAuth\WebauthnLibRegistrationValidator;
use MailServer\RoundcubeAuthGate\GateSession;
use MailServer\RoundcubeAuthGate\WebmailSessionCredential;
use MailServer\RoundcubeAuthManagement\ManagementException;
use MailServer\RoundcubeAuthManagement\MailAuthRecoveryAddressRepository;
use MailServer\RoundcubeAuthManagement\MailAuthSessionEpochInvalidator;
use MailServer\RoundcubeAuthManagement\MfaRequirement;
use MailServer\RoundcubeAuthManagement\PhpRecoveryCodeHasher;
use MailServer\RoundcubeAuthManagement\RecentFactorSession;
use MailServer\RoundcubeAuthManagement\RecoveryCodeService;
use MailServer\RoundcubeAuthManagement\RoundcubeMfaPolicyRepository;
use MailServer\RoundcubeAuthManagement\RoundcubeRecoveryCodeRepository;
use MailServer\RoundcubeAuthManagement\RoundcubeSecurityEventNotifier;
use MailServer\RoundcubeAuthManagement\SecurityEventNotifier;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoveryCompletionService;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoveryException;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoveryRegistrationChallengeStore;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoverySession;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoveryTokenClaim;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoveryTokenClaimService;
use MailServer\RoundcubeEmergencyRecovery\LoopbackEmergencyRecoverySecurityNotifier;
use MailServer\RoundcubeEmergencyRecovery\MailAuthEmergencyRecoveryEpochInvalidator;
use MailServer\RoundcubeEmergencyRecovery\NetSmtpLoopbackMailTransport;
use MailServer\RoundcubeEmergencyRecovery\PhpEmergencyRecoveryTokenHasher;
use MailServer\RoundcubeEmergencyRecovery\RestrictedRecoveryGateService;
use MailServer\RoundcubeEmergencyRecovery\RoundcubeAuthenticatedSessionDestroyer;
use MailServer\RoundcubeEmergencyRecovery\RoundcubeEmergencyRecoveryCompletionRepository;
use MailServer\RoundcubeEmergencyRecovery\RoundcubeEmergencyRecoveryTokenRepository;
use MailServer\RoundcubeEmergencyRecovery\RoundcubeEmergencyRecoveryWebauthnSource;
use MailServer\RoundcubeEmergencyRecovery\UpstreamEmergencyRecoveryRegistrationCeremony;

/** Phase D4 combined recovery gate candidate; not approved for deployment. */
class local_auth_gate extends rcube_plugin
{
    public $task = '.*';

    private const GATE_TASK = 'mail';
    private const ACTION_GATE = 'plugin.local_auth_gate';
    private const ACTION_OPTIONS = 'plugin.local_auth_gate-assert-options';
    private const ACTION_FINISH = 'plugin.local_auth_gate-assert-finish';
    private const ACTION_RECOVERY = 'plugin.local_auth_gate-recovery-finish';
    private const ACTION_EMERGENCY_CLAIM = 'plugin.local_auth_gate-emergency-claim';
    private const ACTION_EMERGENCY_GATE = 'plugin.local_auth_gate-emergency';
    private const ACTION_EMERGENCY_OPTIONS = 'plugin.local_auth_gate-emergency-options';
    private const ACTION_EMERGENCY_FINISH = 'plugin.local_auth_gate-emergency-finish';
    private const LOCAL_AUTH_SOURCE = '/usr/share/roundcube/plugins/.passkey-management-v2-mobile-fixed/local_auth/src';
    private const EMERGENCY_SOURCE = __DIR__ . '/src/emergency';
    private const LOCAL_AUTH_AUTOLOAD = '/opt/roundcube-auth/vendor/autoload.php';
    private const NET_SMTP_SOURCE = '/usr/share/php/Net/SMTP.php';
    private const GUEST_OPTIONS = 'plugin.local_auth_gate-login-options';
    private const GUEST_FINISH = 'plugin.local_auth_gate-login-finish';
    private const GUEST_STATE = 'local_auth_gate_guest_v1';
    private const WEBMAIL_SESSION = 'local_auth_gate_webmail_v1';
    private ?int $verifiedLoginOwner = null;

    protected rcmail $rc;

    public function init(): void
    {
        require_once __DIR__ . '/src/GateSession.php';
        require_once self::LOCAL_AUTH_SOURCE . '/RegistrationException.php';
        require_once self::LOCAL_AUTH_SOURCE . '/RegistrationConfig.php';
        require_once self::LOCAL_AUTH_SOURCE . '/ManagementException.php';
        require_once self::LOCAL_AUTH_SOURCE . '/MfaRequirement.php';
        require_once __DIR__ . '/../local_auth/AccountIdentity.php';
        require_once __DIR__ . '/../local_auth/OwnerMfaPolicyRepository.php';

        $this->rc = rcmail::get_instance();
        $this->add_texts('localization/', true);
        $this->add_hook('login_after', [$this, 'loginAfter']);
        $this->add_hook('startup', [$this, 'startup']);
        require_once __DIR__ . '/src/WebmailSessionCredential.php';
        if (WebmailSessionCredential::configured()) {
            $this->add_hook('loginform_content', [$this, 'loginPasskeyButton']);
            $this->add_hook('session_destroy', [$this, 'revokeWebmailCredential']);
            $this->add_hook('ready', [$this, 'checkWebmailSession']);
        }
        $this->register_action(self::ACTION_GATE, [$this, 'showGate']);
        $this->register_action(self::ACTION_OPTIONS, [$this, 'beginAssertion']);
        $this->register_action(self::ACTION_FINISH, [$this, 'finishAssertion']);
        $this->register_action(self::ACTION_RECOVERY, [$this, 'finishRecoveryCode']);
        $this->register_action(self::ACTION_EMERGENCY_CLAIM, [$this, 'claimEmergencyToken']);
        $this->register_action(self::ACTION_EMERGENCY_GATE, [$this, 'showEmergencyGate']);
        $this->register_action(self::ACTION_EMERGENCY_OPTIONS, [$this, 'beginEmergencyRegistration']);
        $this->register_action(self::ACTION_EMERGENCY_FINISH, [$this, 'finishEmergencyRegistration']);
    }

    /** @param array<string, mixed> $args
     *  @return array<string, mixed>
     */
    public function loginAfter(array $args): array
    {
        $owner = $this->currentUserId();
        if ($owner <= 0) return $args;
        if ($this->verifiedLoginOwner === $owner) { return $args; }
        try {
            $this->requireOwnerAccount();
            if (!$this->mfaRequirement($owner)->required) return $args;
        } catch (Throwable $error) {
            // Unknown identity/policy must not silently turn a required Gate off.
        }
        $this->gateSession()->markPending($owner);
        return ['_task'=>self::GATE_TASK, '_action'=>self::ACTION_GATE];
    }

    /** @param array<string, mixed> $args
     *  @return array<string, mixed>
     */
    public function startup(array $args): array
    {
        $task = is_string($args['task'] ?? null) ? $args['task'] : '';
        $action = is_string($args['action'] ?? null) ? $args['action'] : '';
        if ($task === 'login' && in_array($action, [self::GUEST_OPTIONS, self::GUEST_FINISH], true)) {
            $this->guestPasskey($action);
        }
        if ($this->emergencySession()->hasState()) {
            if ($this->isAllowedEmergencyRoute($task, $action)) {
                return $args;
            }
            $args['task'] = self::GATE_TASK;
            $args['action'] = self::ACTION_EMERGENCY_GATE;
            return $args;
        }

        $userId = $this->currentUserId();
        $state = $this->gateSession();
        if ($userId <= 0 || !$state->hasState()) {
            return $args;
        }

        if ($this->isAllowedPendingRoute($task, $action)) {
            return $args;
        }
        $args['task'] = self::GATE_TASK;
        $args['action'] = self::ACTION_GATE;
        return $args;
    }

    public function loginPasskeyButton(array $form): array
    {
        $this->include_script('guest_passkey.js');
        $button = ['outterclass' => 'guest-passkey',
            'content' => '<button type="button" id="webmail-passkey-login" class="button">パスキーでログイン</button>'
                . '<button type="button" id="webmail-passkey-account-login" class="button">メールアドレスを指定してパスキーでログイン</button>'
                . '<p id="webmail-passkey-login-result" role="status" aria-live="polite"></p>'];
        $form['buttons'] = ['guest_passkey' => $button] + ($form['buttons'] ?? []);
        return $form;
    }

    private function guestPasskey(string $action): never
    {
        try {
            if (!WebmailSessionCredential::configured() || !empty($_SESSION['user_id']) || empty($_SESSION['temp'])
                || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
                || ($_SERVER['HTTP_ORIGIN'] ?? '') !== 'https://' . \MailServer\RoundcubePasskeyGeneral\AccountIdentity::MAIL_HOST
                || ($_SERVER['HTTP_X_ROUNDCUBE_REQUEST'] ?? '') !== $this->rc->get_request_token()
                || strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '', 2)[0])) !== 'application/json') {
                $this->respondGuest(['ok' => false], 403);
            }
            $this->limitGuestRequests();
            $raw = file_get_contents('php://input', false, null, 0, 131073);
            if (!is_string($raw) || strlen($raw) > 131072) { throw new \DomainException('guest_request'); }
            $body = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($body)) { throw new \DomainException('guest_request'); }
            $this->loadAssertionDependencies();
            if ($action === self::GUEST_OPTIONS) {
                $this->respondGuest(['ok' => true] + $this->startGuestAssertion($body), 200);
            }
            $this->finishGuestAssertion($body);
        } catch (Throwable) {
            $this->respondGuest(['ok' => false], 400);
        }
    }

    private function startGuestAssertion(array $body): array
    {
        unset($_SESSION[self::GUEST_STATE]);
        if (!array_key_exists('email', $body)) {
            $ceremony = bin2hex(random_bytes(32));
            $options = WebauthnLibAssertionValidator::create()->createOptions(random_bytes(32), []);
            WebmailSessionCredential::registerChallenge($ceremony);
            $_SESSION[self::GUEST_STATE] = ['ceremony' => $ceremony, 'discoverable_options' => $options];
            return ['ceremony_id' => $ceremony, 'publicKey' => json_decode($options, true, 32, JSON_THROW_ON_ERROR)];
        }
        $email = \MailServer\RoundcubePasskeyGeneral\AccountIdentity::canonical(
            is_string($body['email'] ?? null) ? trim($body['email']) : '');
        $repository = new RoundcubeCredentialRepository($this->rc->get_dbh());
        $db = $this->rc->get_dbh();
        $users = $db->table_name('users', true);
        $result = $db->query("SELECT user_id FROM {$users} WHERE BINARY username=BINARY ? AND mail_host=? LIMIT 2",
            $email, \MailServer\RoundcubePasskeyGeneral\AccountIdentity::MAIL_HOST);
        $row = $db->fetch_assoc($result);
        $owner = is_array($row) && !$db->fetch_assoc($result) ? (int) $row['user_id'] : 0;
        $pending = $owner > 0 ? $repository->enabledCredentialDescriptors($owner) : [];
        $epoch = $pending ? $this->webmailEpoch($email) : null;
        if ($epoch === null) {
            $synthetic = WebauthnLibAssertionValidator::create()->createOptions(
                random_bytes(32), [['id' => random_bytes(32), 'transports' => []]]);
            return ['ceremony_id' => bin2hex(random_bytes(16)),
                'publicKey' => json_decode($synthetic, true, 32, JSON_THROW_ON_ERROR)];
        }
        $options = $this->assertionService()->begin($owner);
        WebmailSessionCredential::registerChallenge($options['ceremony_id']);
        $_SESSION[self::GUEST_STATE] = ['id' => $owner, 'email' => $email, 'epoch' => $epoch,
            'ceremony' => $options['ceremony_id']];
        return $options;
    }

    private function finishGuestAssertion(array $body): never
    {
        $pending = $_SESSION[self::GUEST_STATE] ?? null;
        unset($_SESSION[self::GUEST_STATE]);
        if (!is_array($pending) || !WebmailSessionCredential::consumeChallenge($pending['ceremony'])
            || ($body['ceremony_id'] ?? null) !== $pending['ceremony']
            || !is_array($body['credential'] ?? null)) { throw new \DomainException('guest_state'); }
        $credential = $body['credential'];
        $response = json_encode($credential, JSON_THROW_ON_ERROR);
        $discovery = $pending['discoverable_options'] ?? null;
        if (is_string($discovery)) {
            [$owner, $mailbox, $handle] = $this->discoverGuestOwner($credential);
        } else {
            $owner = $pending['id'];
            $mailbox = $pending['email'];
        }
        $email = \MailServer\RoundcubePasskeyGeneral\AccountIdentity::requireOwner(
            $this->rc->get_dbh(), $owner, $mailbox);
        $epoch = $this->webmailEpoch($email);
        if ($epoch === null || ($discovery === null && $epoch !== $pending['epoch'])) {
            throw new \DomainException('mailbox_epoch_changed');
        }
        if (is_string($discovery)) {
            // The database challenge is already consumed. Reuse the same verifier
            // and locked credential update with request-local state.
            $state = [];
            $challenge = new AssertionChallengeStore($state);
            $ceremony = $challenge->issue($owner, $handle, $discovery);
            $this->assertionService($challenge)->finish($owner, $ceremony, $response);
        } else {
            $this->assertionService()->finish($owner, $body['ceremony_id'], $response);
        }
        [$selector, $secret] = WebmailSessionCredential::issue($email, $epoch);
        try {
            $this->rc->kill_session();
            if (!$this->rc->login($email, $secret, null, true) || $this->currentUserId() !== $owner
                || $this->webmailEpoch($email) !== $epoch) {
                throw new \DomainException('webmail_login_failed');
            }
            $this->rc->session->remove('temp');
            $this->rc->session->regenerate_id(false);
            $this->rc->session->set_auth_cookie();
            $_SESSION[self::WEBMAIL_SESSION] = ['email' => $email, 'epoch' => $epoch, 'selector' => $selector,
                'expires' => time() + WebmailSessionCredential::TTL];
            $this->loadManagementDependencies();
            $this->recentFactor()->mark($owner, 'passkey', time());
            $this->verifiedLoginOwner = $owner;
            $this->rc->plugins->exec_hook('login_after', ['_task' => 'mail']);
            $this->rc->log_login();
        } catch (Throwable $error) {
            $this->rc->kill_session();
            WebmailSessionCredential::revoke($selector);
            throw $error;
        }
        $this->respondGuest(['ok' => true, 'redirect' => $this->rc->url(['_task' => 'mail'])], 200);
    }

    private function discoverGuestOwner(array $credential): array
    {
        $response = $credential['response'] ?? null;
        $handle = self::decodeGuestIdentity(is_array($response) ? ($response['userHandle'] ?? null) : null, 32);
        $id = self::decodeGuestIdentity($credential['rawId'] ?? null, RegistrationConfig::MAX_CREDENTIAL_ID_BYTES);
        if (strlen($handle) !== 32) { throw new \DomainException('invalid_passkey_handle'); }

        $db = $this->rc->get_dbh();
        $users = $db->table_name('users', true);
        $handles = $db->table_name('auth_webauthn_users', true);
        $keys = $db->table_name('auth_webauthn_credentials', true);
        $db->set_debug(false);
        $db->set_option('ignore_errors', true);
        $db->set_option('ignore_key_errors', true);
        $result = $db->query("SELECT u.user_id, u.username FROM {$users} u
            JOIN {$handles} h ON h.user_id=u.user_id
            JOIN {$keys} c ON c.user_id=h.user_id AND c.user_handle=h.user_handle
            WHERE h.user_handle=UNHEX(?) AND c.credential_id=UNHEX(?) AND c.enabled=1 AND u.mail_host=?
            LIMIT 1", bin2hex($handle), bin2hex($id), \MailServer\RoundcubePasskeyGeneral\AccountIdentity::MAIL_HOST);
        $row = $result === false || $db->is_error($result) ? null : $db->fetch_assoc($result);
        if (!is_array($row) || (int) $row['user_id'] <= 0 || !is_string($row['username'])) {
            throw new \DomainException('unrecognized_passkey');
        }
        return [(int) $row['user_id'], $row['username'], $handle];
    }

    private static function decodeGuestIdentity(mixed $encoded, int $max): string
    {
        if (!is_string($encoded) || strlen($encoded) > (int) ceil($max * 4 / 3)
            || preg_match('/\A[A-Za-z0-9_-]+\z/D', $encoded) !== 1) {
            throw new \DomainException('invalid_passkey_identity');
        }
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($decoded === false || $decoded === '' || strlen($decoded) > $max
            || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $encoded) {
            throw new \DomainException('invalid_passkey_identity');
        }
        return $decoded;
    }

    private function webmailEpoch(string $email): ?string
    {
        require_once dirname(__DIR__) . '/mi_system_compat/AccountDirectory.php';
        $settings = \MISystem\RoundcubeCompat\AccountDirectory::settings();
        return $settings === null ? null : (new \MISystem\RoundcubeCompat\AccountDirectory($settings))->epoch($email);
    }

    public function revokeWebmailCredential(array $args): array
    {
        $selector = $_SESSION[self::WEBMAIL_SESSION]['selector'] ?? null;
        if (is_string($selector)) {
            try { WebmailSessionCredential::revoke($selector); }
            catch (Throwable) { rcube::write_log('local_auth_gate', 'Webmail credential revocation unavailable'); }
        }
        return $args;
    }

    public function checkWebmailSession(array $args): array
    {
        $state = $_SESSION[self::WEBMAIL_SESSION] ?? null;
        if (!is_array($state) || $this->rc->task === 'logout') { return $args; }
        try {
            $unchanged = time() < $state['expires'] && $this->webmailEpoch($state['email']) === $state['epoch'];
        } catch (Throwable) { $unchanged = false; }
        if ($unchanged) { return $args; }
        $this->rc->kill_session();
        header('Location: ./?_session_revoked=1', true, 303);
        exit;
    }

    private function limitGuestRequests(): void
    {
        $address = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP);
        if ($address === false) { throw new \DomainException('guest_address'); }
        $key = hash_hmac('sha256', $address, $this->rc->config->get('des_key'));
        $file = $this->rc->config->get('temp_dir') . '/passkey-login-' . substr($key, 0, 2);
        $handle = fopen($file, 'c+');
        if ($handle === false) { throw new \RuntimeException('guest_limiter'); }
        try {
            if (!flock($handle, LOCK_EX)) { throw new \RuntimeException('guest_limiter'); }
            $raw = stream_get_contents($handle, 16385);
            if ($raw === false || strlen($raw) > 16384) { throw new \RuntimeException('guest_limiter'); }
            $claims = $raw === '' ? [] : json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
            $window = intdiv(time(), 60);
            $claims = array_filter($claims, static fn (array $claim): bool => $claim[0] === $window);
            $attempts = $claims[$key][1] ?? 0;
            if ($attempts >= 10 || (count($claims) >= 128 && $attempts === 0)) {
                $this->respondGuest(['ok' => false], 429);
            }
            $claims[$key] = [$window, $attempts + 1];
            $encoded = json_encode($claims, JSON_THROW_ON_ERROR);
            if (!rewind($handle) || !ftruncate($handle, 0) || fwrite($handle, $encoded) !== strlen($encoded)) {
                throw new \RuntimeException('guest_limiter');
            }
        } finally { fclose($handle); }
    }

    private function respondGuest(array $body, int $status): never
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($body, JSON_THROW_ON_ERROR);
        exit;
    }

    public function showGate(): void
    {
        $userId = $this->requireAuthenticatedUser();
        $pending = $this->gateSession()->status($userId) === GateSession::STATUS_PENDING;
        $requirement = new MfaRequirement(true, false, false);
        if ($pending) {
            try {
                $requirement = $this->mfaRequirement($userId);
            } catch (Throwable $e) {
                // Keep both methods unavailable when policy state is unknown.
            }
        }

        $this->rc->output->set_env('local_auth_gate_ready', $pending);
        $this->rc->output->set_env('local_auth_gate_passkey', $requirement->passkeyAvailable);
        $this->rc->output->set_env('local_auth_gate_recovery', $requirement->recoveryCodeAvailable);
        $this->rc->output->set_env('local_auth_gate_emergency', $pending);
        $this->rc->output->set_pagetitle($this->gettext('pagetitle'));
        $this->include_stylesheet('local_auth_gate.css');
        $this->include_script('local_auth_gate.js');
        if (!$pending) {
            $this->rc->output->show_message('local_auth_gate.invalidstate', 'error');
        } elseif (!$requirement->passkeyAvailable && !$requirement->recoveryCodeAvailable) {
            $this->rc->output->show_message('local_auth_gate.nofactor', 'error');
        }
        $this->rc->output->send('local_auth_gate.gate');
    }

    public function claimEmergencyToken(): never
    {
        try {
            $userId = $this->requirePendingUser();
            $this->requireOwnerAccount();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $redirect = $this->completeEmergencyClaimPayload($userId, $body);
            $this->json(200, ['ok' => true, 'redirect' => $redirect]);
        } catch (EmergencyRecoveryException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (RegistrationException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    public function showEmergencyGate(): void
    {
        try {
            $this->requireRestrictedEmergencyUser();
            $this->rc->output->set_env('local_auth_emergency_ready', true);
        } catch (EmergencyRecoveryException $e) {
            $this->rc->output->set_env('local_auth_emergency_ready', false);
            $this->rc->output->show_message('local_auth_gate.emergencyinvalidstate', 'error');
        }

        $this->rc->output->set_pagetitle($this->gettext('emergencypagetitle'));
        $this->include_stylesheet('local_auth_gate.css');
        $this->include_script('local_auth_gate.js');
        $this->rc->output->send('local_auth_gate.emergency');
    }

    public function beginEmergencyRegistration(): never
    {
        try {
            [$userId, $account] = $this->requireRestrictedEmergencyUser();
            $this->requireCsrf();
            $result = $this->emergencyGateService()->begin($userId, $account);
            $this->json(200, ['ok' => true] + $result);
        } catch (EmergencyRecoveryException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    public function finishEmergencyRegistration(): never
    {
        try {
            [$userId, $account] = $this->requireRestrictedEmergencyUser();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $result = $this->emergencyGateService()->finish(
                $userId,
                $account,
                (string) ($body['ceremony_id'] ?? ''),
                json_encode($body['credential'] ?? null, JSON_THROW_ON_ERROR),
                (string) ($body['label'] ?? ''),
            );
            $this->json(200, [
                'ok' => true,
                'fresh_login_required' => true,
                'session_destroyed' => $result->sessionDestroyed,
                'notification_sent' => $result->notificationSent,
            ]);
        } catch (EmergencyRecoveryException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    public function beginAssertion(): never
    {
        try {
            $userId = $this->requirePendingUser();
            $this->requireCsrf();
            if (!$this->mfaRequirement($userId)->passkeyAvailable) {
                throw new RegistrationException('Passkey is unavailable.', diagnosticCode: 'credential');
            }
            $result = $this->assertionService()->begin($userId);
            $this->json(200, ['ok' => true] + $result);
        } catch (RegistrationException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    public function finishAssertion(): never
    {
        try {
            $userId = $this->requirePendingUser();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $redirect = $this->completeAssertionPayload($userId, $body);
            $this->json(200, ['ok' => true, 'redirect' => $redirect]);
        } catch (RegistrationException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    public function finishRecoveryCode(): never
    {
        try {
            $userId = $this->requirePendingUser();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $redirect = $this->completeRecoveryPayload($userId, $body);
            $notified = $this->notifySecurityEvent(SecurityEventNotifier::RECOVERY_CODE_USED);
            $this->json(200, [
                'ok' => true,
                'redirect' => $redirect,
                'notification_sent' => $notified,
            ]);
        } catch (ManagementException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (RegistrationException $e) {
            $this->gateFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->gateFailure('internal');
        }
    }

    /** @param array<string, mixed> $body */
    protected function completeAssertionPayload(int $userId, array $body): string
    {
        $now = time();
        $this->requirePendingAt($userId, $now);
        $this->assertionService()->finish(
            $userId,
            (string) ($body['ceremony_id'] ?? ''),
            json_encode($body['credential'] ?? null, JSON_THROW_ON_ERROR),
        );
        $this->recentFactor()->mark($userId, 'passkey', $now);
        return $this->completeGate($userId, $now, ['_task' => 'mail']);
    }

    /** @param array<string, mixed> $body */
    protected function completeRecoveryPayload(int $userId, array $body): string
    {
        $now = time();
        $this->requirePendingAt($userId, $now);
        $code = $body['recovery_code'] ?? null;
        if (!is_string($code) || strlen($code) > 128
            || !$this->recoveryCodeService()->consume($userId, trim($code), $now)
        ) {
            throw new ManagementException('Recovery Code verification failed.', 'authentication');
        }
        return $this->completeGate(
            $userId,
            $now,
            ['_task' => 'settings', '_action' => 'plugin.local_auth'],
        );
    }

    /** @param array<string, mixed> $body */
    protected function completeEmergencyClaimPayload(int $userId, array $body): string
    {
        $now = time();
        $this->requirePendingAt($userId, $now);
        $account = $this->requireOwnerAccount();
        $presented = $body['emergency_token'] ?? null;
        if (!is_string($presented) || strlen($presented) > 128) {
            // A bounded invalid value still reaches the claim service so the
            // fixed pilot's rate-limit state records the failed attempt.
            $presented = '';
        }
        if (!$this->emergencyClaimService()->claim(
            $userId,
            $account,
            $presented,
            $this->emergencySession(),
            $now,
        )) {
            throw new EmergencyRecoveryException('Recovery token verification failed.', 'authentication');
        }

        // Keep both states until rotation succeeds. If rotation fails after the
        // database claim, the claimed token is deliberately not reusable.
        $this->rotateAuthenticatedSession();
        if (!$this->gateSession()->clearPending($userId, $now)) {
            throw new EmergencyRecoveryException('Recovery transition failed.', 'state');
        }
        return $this->rc->url([
            '_task' => self::GATE_TASK,
            '_action' => self::ACTION_EMERGENCY_GATE,
        ]);
    }

    /** @param array<string, string> $redirect */
    private function completeGate(int $userId, int $now, array $redirect): string
    {
        // Keep pending until session rotation and the new auth cookie succeed.
        $this->rotateAuthenticatedSession();
        if (!$this->gateSession()->clearPending($userId, $now)) {
            throw new RegistrationException(
                'Second-factor state could not be completed.',
                diagnosticCode: 'state',
            );
        }
        return $this->rc->url($redirect);
    }

    private function requirePendingAt(int $userId, int $now): void
    {
        if ($this->gateSession()->status($userId, $now) !== GateSession::STATUS_PENDING) {
            throw new RegistrationException(
                'Second-factor state is unavailable.',
                diagnosticCode: 'state',
            );
        }
    }

    /** @return array<string, mixed> */
    private function readJsonBody(): array
    {
        $input = file_get_contents('php://input');
        if (!is_string($input) || strlen($input) > RegistrationConfig::MAX_REQUEST_BYTES) {
            throw new RegistrationException('Request body is unavailable.', diagnosticCode: 'request');
        }
        try {
            $body = json_decode($input, true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new RegistrationException('Request body is invalid.', 0, $e, 'request');
        }
        if (!is_array($body)) {
            throw new RegistrationException('Request body is invalid.', diagnosticCode: 'request');
        }
        return $body;
    }

    protected function mfaRequirement(int $userId): MfaRequirement
    {
        $this->loadManagementDependencies();
        return (new \MailServer\RoundcubePasskeyGeneral\OwnerMfaPolicyRepository($this->rc->get_dbh()))->requirement($userId);
    }

    private function assertionService(?AssertionChallengeStore $challenge = null): AssertionService
    {
        $this->loadAssertionDependencies();
        return new AssertionService(
            new RoundcubeCredentialRepository($this->rc->get_dbh()),
            WebauthnLibAssertionValidator::create(),
            $challenge ?? new AssertionChallengeStore($_SESSION),
        );
    }

    private function recoveryCodeService(): RecoveryCodeService
    {
        $this->loadManagementDependencies();
        return new RecoveryCodeService(
            new RoundcubeRecoveryCodeRepository($this->rc->get_dbh()),
            new PhpRecoveryCodeHasher(),
            $this->recentFactor(),
        );
    }

    protected function emergencyClaimService(): EmergencyRecoveryTokenClaim
    {
        $this->loadEmergencyClaimDependencies();
        return new EmergencyRecoveryTokenClaimService(
            new RoundcubeEmergencyRecoveryTokenRepository($this->rc->get_dbh()),
            new PhpEmergencyRecoveryTokenHasher(),
        );
    }

    protected function emergencyGateService(): RestrictedRecoveryGateService
    {
        $this->loadEmergencyDependencies();
        if (!is_file(self::NET_SMTP_SOURCE)
            || is_link(self::NET_SMTP_SOURCE)
            || !is_readable(self::NET_SMTP_SOURCE)
        ) {
            throw new EmergencyRecoveryException('Recovery notification is unavailable.', 'setup');
        }
        require_once self::NET_SMTP_SOURCE;
        if (!class_exists('Net_SMTP', false)) {
            throw new EmergencyRecoveryException('Recovery notification is unavailable.', 'setup');
        }

        $session = $this->emergencySession();
        $credentials = new RoundcubeEmergencyRecoveryWebauthnSource($this->rc->get_dbh());
        $ceremony = new UpstreamEmergencyRecoveryRegistrationCeremony(
            $credentials,
            WebauthnLibRegistrationValidator::create(),
            new EmergencyRecoveryRegistrationChallengeStore($_SESSION),
        );
        $completion = new EmergencyRecoveryCompletionService(
            new RoundcubeEmergencyRecoveryCompletionRepository($this->rc->get_dbh()),
            new MailAuthEmergencyRecoveryEpochInvalidator(new MailAuthSessionEpochInvalidator()),
            $session,
            new RoundcubeAuthenticatedSessionDestroyer($this->rc),
            new LoopbackEmergencyRecoverySecurityNotifier(
                new MailAuthRecoveryAddressRepository(),
                new NetSmtpLoopbackMailTransport($this->requireOwnerAccount()),
            ),
        );
        return new RestrictedRecoveryGateService($session, $ceremony, $completion);
    }

    private function recentFactor(): RecentFactorSession
    {
        require_once self::LOCAL_AUTH_SOURCE . '/RecentFactorSession.php';
        return new RecentFactorSession($_SESSION);
    }

    private function loadRepositoryDependencies(): void
    {
        foreach ([
            'StoredCredential.php',
            'ValidatedAssertion.php',
            'ValidatedCredential.php',
            'AssertionCredentialRepository.php',
            'CredentialRepository.php',
            'RoundcubeCredentialRepository.php',
        ] as $file) {
            require_once self::LOCAL_AUTH_SOURCE . '/' . $file;
        }
    }

    private function loadAssertionDependencies(): void
    {
        if (!is_readable(self::LOCAL_AUTH_AUTOLOAD)) {
            throw new RegistrationException(
                'Isolated WebAuthn dependencies are unavailable.',
                diagnosticCode: 'setup',
            );
        }
        require_once self::LOCAL_AUTH_AUTOLOAD;
        $this->loadRepositoryDependencies();
        foreach ([
            'AssertionValidator.php',
            'AssertionChallengeStore.php',
            'AssertionService.php',
            'WebauthnLibAssertionValidator.php',
        ] as $file) {
            require_once self::LOCAL_AUTH_SOURCE . '/' . $file;
        }
    }

    private function loadManagementDependencies(): void
    {
        foreach ([
            'ManagementException.php',
            'RecentFactorSession.php',
            'RecoveryCodeHasher.php',
            'PhpRecoveryCodeHasher.php',
            'StoredRecoveryCode.php',
            'RecoveryCodeRepository.php',
            'RecoveryCodeService.php',
            'RoundcubeRecoveryCodeRepository.php',
            'MfaRequirement.php',
            'MfaPolicyRepository.php',
            'RoundcubeMfaPolicyRepository.php',
            'SessionEpochInvalidator.php',
            'MailAuthSessionEpochInvalidator.php',
            'RecoveryAddressRepository.php',
            'MailAuthRecoveryAddressRepository.php',
            'SecurityEventNotifier.php',
            'RoundcubeSecurityEventNotifier.php',
        ] as $file) {
            require_once self::LOCAL_AUTH_SOURCE . '/' . $file;
        }
    }

    private function loadEmergencySessionDependencies(): void
    {
        if (class_exists(EmergencyRecoverySession::class, false)) {
            return;
        }
        foreach (['EmergencyRecoveryException.php', 'EmergencyRecoverySessionState.php', 'EmergencyRecoverySession.php'] as $file) {
            require_once self::EMERGENCY_SOURCE . '/' . $file;
        }
    }

    private function loadEmergencyClaimDependencies(): void
    {
        $this->loadEmergencySessionDependencies();
        foreach ([
            'StoredEmergencyRecoveryToken.php',
            'EmergencyRecoveryTokenRepository.php',
            'EmergencyRecoveryTokenHasher.php',
            'EmergencyRecoveryTokenDelivery.php',
            'NewEmergencyRecoveryToken.php',
            'EmergencyRecoveryTokenService.php',
            'EmergencyRecoveryTokenClaim.php',
            'EmergencyRecoveryTokenClaimService.php',
            'PhpEmergencyRecoveryTokenHasher.php',
            'RoundcubeEmergencyRecoveryTokenRepository.php',
        ] as $file) {
            require_once self::EMERGENCY_SOURCE . '/' . $file;
        }
    }

    private function loadEmergencyDependencies(): void
    {
        $this->loadEmergencyClaimDependencies();
        $this->loadManagementDependencies();
        $this->loadRegistrationDependencies();
        foreach ([
            'EmergencyRecoveryCredential.php',
            'EmergencyRecoveryRegistrationCeremony.php',
            'EmergencyRecoveryWebauthnSource.php',
            'RoundcubeEmergencyRecoveryWebauthnSource.php',
            'EmergencyRecoveryRegistrationChallengeStore.php',
            'UpstreamEmergencyRecoveryRegistrationCeremony.php',
            'EmergencyRecoveryCompletionRepository.php',
            'RoundcubeEmergencyRecoveryCompletionRepository.php',
            'EmergencyRecoveryEpochInvalidator.php',
            'MailAuthEmergencyRecoveryEpochInvalidator.php',
            'EmergencyRecoveryAuthenticatedSessionDestroyer.php',
            'RoundcubeAuthenticatedSessionDestroyer.php',
            'EmergencyRecoveryMailTransport.php',
            'NetSmtpLoopbackMailTransport.php',
            'EmergencyRecoverySecurityNotifier.php',
            'LoopbackEmergencyRecoverySecurityNotifier.php',
            'EmergencyRecoveryCompletionResult.php',
            'EmergencyRecoveryCompletionService.php',
            'RestrictedRecoveryGateService.php',
        ] as $file) {
            require_once self::EMERGENCY_SOURCE . '/' . $file;
        }
    }

    private function loadRegistrationDependencies(): void
    {
        if (!is_readable(self::LOCAL_AUTH_AUTOLOAD)) {
            throw new EmergencyRecoveryException('WebAuthn dependencies are unavailable.', 'setup');
        }
        require_once self::LOCAL_AUTH_AUTOLOAD;
        foreach (['ValidatedCredential.php', 'RegistrationValidator.php', 'WebauthnLibRegistrationValidator.php'] as $file) {
            require_once self::LOCAL_AUTH_SOURCE . '/' . $file;
        }
    }

    private function notifySecurityEvent(string $event): bool
    {
        $this->loadManagementDependencies();
        return (new RoundcubeSecurityEventNotifier(
            $this->rc,
            new MailAuthRecoveryAddressRepository(),
        ))->notify((string) $this->rc->get_user_name(), $event);
    }

    protected function rotateAuthenticatedSession(): void
    {
        if ($this->rc->session->regenerate_id(true) !== true) {
            throw new RegistrationException('Session rotation failed.', diagnosticCode: 'state');
        }
        $this->rc->session->set_auth_cookie();
    }

    private function gateSession(): GateSession
    {
        return new GateSession($_SESSION);
    }

    private function emergencySession(): EmergencyRecoverySession
    {
        $this->loadEmergencySessionDependencies();
        return new EmergencyRecoverySession($_SESSION);
    }

    private function currentUserId(): int
    {
        $value = $_SESSION['user_id'] ?? null;
        if (is_int($value)) return $value > 0 ? $value : 0;
        if (is_string($value) && preg_match('/\A[1-9][0-9]{0,9}\z/D', $value) === 1) {
            return (int) $value;
        }
        return 0;
    }

    private function requireAuthenticatedUser(): int
    {
        $userId = $this->currentUserId();
        if ($userId <= 0) throw new RegistrationException('Authentication is required.');
        return $userId;
    }

    private function requirePendingUser(): int
    {
        $userId = $this->requireAuthenticatedUser();
        $this->requirePendingAt($userId, time());
        return $userId;
    }

    private function requireOwnerAccount(): string
    {
        $owner = $this->requireAuthenticatedUser();
        $account = $_SESSION['username'] ?? null;
        if (!is_string($account)) throw new EmergencyRecoveryException('Owner unavailable.', 'authentication');
        try {
            return \MailServer\RoundcubePasskeyGeneral\AccountIdentity::requireOwner($this->rc->get_dbh(), $owner, $account);
        } catch (Throwable $error) {
            throw new EmergencyRecoveryException('Owner binding unavailable.', 'authentication');
        }
    }

    /** @return array{0: int, 1: string} */
    private function requireRestrictedEmergencyUser(): array
    {
        $userId = $this->currentUserId();
        $account = $this->requireOwnerAccount();
        if ($userId <= 0) {
            throw new EmergencyRecoveryException('Recovery is unavailable.', 'authentication');
        }
        $this->emergencySession()->requirePending($userId, $account);
        return [$userId, $account];
    }

    private function requireCsrf(): void
    {
        $actual = rcube_utils::request_header('X-Roundcube-Request');
        $expected = $this->rc->get_request_token();
        if (!is_string($actual) || !hash_equals($expected, $actual)) {
            throw new RegistrationException('Request security check failed.');
        }
        $this->rc->request_security_check(rcube_utils::INPUT_POST);
    }

    private function isAllowedPendingRoute(string $task, string $action): bool
    {
        if ($task === 'logout' && ($action === '' || $action === 'logout')) return true;
        return $task === self::GATE_TASK
            && in_array(
                $action,
                [
                    self::ACTION_GATE,
                    self::ACTION_OPTIONS,
                    self::ACTION_FINISH,
                    self::ACTION_RECOVERY,
                    self::ACTION_EMERGENCY_CLAIM,
                ],
                true,
            );
    }

    private function isAllowedEmergencyRoute(string $task, string $action): bool
    {
        if ($task === 'logout' && ($action === '' || $action === 'logout')) return true;
        return $task === self::GATE_TASK
            && in_array(
                $action,
                [self::ACTION_EMERGENCY_GATE, self::ACTION_EMERGENCY_OPTIONS, self::ACTION_EMERGENCY_FINISH],
                true,
            );
    }

    private function gateFailure(string $diagnosticCode): never
    {
        $status = $diagnosticCode === 'rate-limit' ? 429 : 400;
        $this->json($status, [
            'ok' => false,
            'error' => $this->gettext('verificationfailed'),
            'error_code' => $diagnosticCode,
        ]);
    }

    /** @param array<string, mixed> $payload */
    private function json(int $status, array $payload): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store');
        echo json_encode($payload, JSON_THROW_ON_ERROR);
        exit;
    }
}
