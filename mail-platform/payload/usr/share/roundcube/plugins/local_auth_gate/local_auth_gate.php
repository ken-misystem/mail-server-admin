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

    private function assertionService(): AssertionService
    {
        $this->loadAssertionDependencies();
        return new AssertionService(
            new RoundcubeCredentialRepository($this->rc->get_dbh()),
            WebauthnLibAssertionValidator::create(),
            new AssertionChallengeStore($_SESSION),
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
