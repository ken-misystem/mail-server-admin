<?php

declare(strict_types=1);

use MailServer\RoundcubeAuth\AssertionChallengeStore;
use MailServer\RoundcubeAuth\AssertionService;
use MailServer\RoundcubeAuth\RegistrationChallengeStore;
use MailServer\RoundcubeAuth\RegistrationConfig;
use MailServer\RoundcubeAuth\RegistrationException;
use MailServer\RoundcubeAuth\RegistrationService;
use MailServer\RoundcubeAuth\RoundcubeCredentialRepository;
use MailServer\RoundcubeAuth\WebauthnLibAssertionValidator;
use MailServer\RoundcubeAuth\WebauthnLibRegistrationValidator;
use MailServer\RoundcubeAuthManagement\CredentialManagementService;
use MailServer\RoundcubeAuthManagement\ManagementException;
use MailServer\RoundcubeAuthManagement\MailAuthSessionEpochInvalidator;
use MailServer\RoundcubeAuthManagement\PhpRecoveryCodeHasher;
use MailServer\RoundcubeAuthManagement\RecentFactorSession;
use MailServer\RoundcubeAuthManagement\RecoveryCodeService;
use MailServer\RoundcubeAuthManagement\MailAuthRecoveryAddressRepository;
use MailServer\RoundcubeAuthManagement\RoundcubeCredentialManagementRepository;
use MailServer\RoundcubeAuthManagement\RoundcubeRecoveryCodeRepository;
use MailServer\RoundcubeAuthManagement\RoundcubeSecurityEventNotifier;
use MailServer\RoundcubeAuthManagement\SecurityEventNotifier;

/**
 * General authenticated-owner management candidate; not deployed.
 *
 * This file is an overlay for the existing local_auth plugin. It is not a
 * deployment artifact until the policy, notification, and session-epoch gates
 * documented in MANAGEMENT_RECOVERY_PLAN.md are complete.
 */
require_once __DIR__ . '/OwnerPasskeyActions.php';
require_once __DIR__ . '/OwnerPolicyActions.php';
require_once __DIR__ . '/OwnerLifecycleIntegrationV1.php';

final class local_auth extends rcube_plugin
{
    use OwnerPasskeyActions;
    use OwnerPolicyActions;
    use OwnerLifecycleIntegrationV1;

    public $task = 'settings';

    private const LOCAL_AUTH_SOURCE = '/usr/share/roundcube/plugins/.passkey-management-v2-mobile-fixed/local_auth/src';

    private rcmail $rc;

    public function init(): void
    {
        require_once self::LOCAL_AUTH_SOURCE . '/RegistrationConfig.php';
        require_once self::LOCAL_AUTH_SOURCE . '/RegistrationException.php';
        require_once self::LOCAL_AUTH_SOURCE . '/ManagementException.php';
        $this->rc = rcmail::get_instance();
        $this->add_texts('localization/', true);
        $this->add_hook('settings_actions', [$this, 'settingsActions']);
        $this->register_action('plugin.local_auth', [$this, 'show']);
        $this->register_action('plugin.local_auth-register-options', [$this, 'begin']);
        $this->register_action('plugin.local_auth-register-finish', [$this, 'finish']);
        $this->register_action('plugin.local_auth-assert-options', [$this, 'beginAssertion']);
        $this->register_action('plugin.local_auth-owner-verification-status', [$this, 'ownerVerificationStatus']);
        $this->register_action('plugin.local_auth-assert-finish', [$this, 'finishAssertion']);
        $this->register_action('plugin.local_auth-credentials', [$this, 'credentials']);
        $this->register_action('plugin.local_auth-owner-credentials', [$this, 'ownerCredentials']);
        $this->register_action('plugin.local_auth-disable', [$this, 'disable']);
        $this->register_action('plugin.local_auth-recovery-replace', [$this, 'replaceRecoveryCodes']);
        $this->register_action('plugin.local_auth-owner-policy', [$this, 'ownerPolicy']);
        $this->register_action('plugin.local_auth-owner-policy-save', [$this, 'ownerPolicySave']);
        $this->register_action('plugin.local_auth-owner-recovery-verify', [$this, 'ownerRecoveryVerify']);
        $this->register_action('plugin.local_auth-owner-remove-options', [$this, 'ownerRemovalOptions']);
        $this->register_action('plugin.local_auth-owner-remove-finish', [$this, 'ownerRemovalFinish']);
        $this->include_script('local_auth_general_v1.js');
        $this->include_stylesheet('local_auth.css');
        $this->include_stylesheet('owner_management_v1.css');
    }

    public function settingsActions(array $args): array
    {
        $args['actions'][] = [
            'action' => 'plugin.local_auth',
            'class' => 'local-auth-passkeys',
            'label' => 'passkeys',
            'domain' => 'local_auth',
        ];
        return $args;
    }

    public function show(): void
    {
        $this->requireAuthenticatedUser();
        $managementEnabled = true;
        $this->rc->output->set_env('local_auth_owner_list_enabled', true);
        $this->rc->output->set_env('local_auth_owner_actions_enabled', true);
        $this->rc->output->set_env('local_auth_management_enabled', $managementEnabled);
        $this->rc->output->set_pagetitle($this->gettext('passkeys'));
        $this->rc->output->send(
            $managementEnabled ? 'local_auth.passkeys' : 'local_auth.passkeys_basic',
        );
    }

    /** Owner metadata only; the owner always comes from the authenticated session. */
    public function ownerCredentials(): never
    {
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $rows = array_map(
                static fn ($row): array => [
                    'id' => $row->id,
                    'label' => $row->label,
                    'enabled' => $row->enabled,
                    'created_at' => $row->createdAt,
                    'last_used_at' => $row->lastUsedAt,
                ],
                $this->managementService()->list($userId),
            );
            $this->json(200, ['ok' => true, 'credentials' => $rows]);
        } catch (ManagementException $e) {
            $this->managementFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->managementFailure('internal');
        }
    }

    public function credentials(): never
    {
        $this->ownerCredentials();
    }

    public function begin(): never
    {
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->sharedRegistration($userId, false);
            $this->managementService()->requireRegistrationAuthorization($userId);
            $username = (string) $this->rc->get_user_name();
            $result = $this->registrationService()->begin($userId, $username, $username);
            $this->json(200, ['ok' => true] + $result);
        } catch (ManagementException $e) {
            $this->managementFailure($e->diagnosticCode);
        } catch (RegistrationException $e) {
            $this->registrationFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->registrationFailure('internal');
        }
    }

    public function finish(): never
    {
        $guard = null;
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $management = $this->managementService();
            $body = $this->readJsonBody();
            $guard = new OwnerRegistrationTransaction($this->rc->get_dbh());
            $guard->run($userId, function () use ($userId, $body, $management): void {
                $this->sharedRegistration($userId, true);
                $management->requireRegistrationAuthorization($userId);
                $this->registrationService()->finish(
                    $userId,
                    (string) ($body['ceremony_id'] ?? ''),
                    json_encode($body['credential'] ?? null, JSON_THROW_ON_ERROR),
                    (string) ($body['label'] ?? ''),
                );
            });
            $management->completeRegistrationAuthorization($userId);
        } catch (Throwable $error) {
            $this->clearOwnerProof();
            if ($guard !== null && $guard->commitAttempted && !$guard->committed) {
                $this->registrationFailure('registration-unverified');
            }
            $this->registrationFailure($error instanceof ManagementException || $error instanceof RegistrationException
                ? $error->diagnosticCode : 'internal');
        }
        // A notification failure after commit must not report registration failure.
        try { $notified = $this->notifySecurityEvent(SecurityEventNotifier::PASSKEY_ADDED); }
        catch (Throwable $error) { $notified = false; }
        $this->json(200, ['ok' => true, 'notification_sent' => $notified]);
    }

    public function beginAssertion(): never
    {
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $result = $this->sharedOwnerClient()->begin();
            if (isset($result['action_id'])) { $result['ceremony_id']=$result['action_id']; unset($result['action_id']); }
            $this->json(200, ['ok' => true] + $result);
        } catch (RegistrationException $e) {
            $this->assertionFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->assertionFailure('internal');
        }
    }

    public function finishAssertion(): never
    {
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $this->sharedOwnerClient()->finish((string)($body['ceremony_id']??''), $body['credential']??null);
            $this->recentFactor()->mark($userId, 'passkey');
            $this->json(200, ['ok' => true]);
        } catch (RegistrationException $e) {
            $this->assertionFailure($e->diagnosticCode);
        } catch (Throwable $e) {
            $this->assertionFailure('internal');
        }
    }

    public function disable(): never
    {
        try {
            $this->requireAuthenticatedUser();
            $this->requireCsrf();
            // Retire the unbound legacy route. Use the deployed owner/target/
            // one-use ceremony endpoints, never a generic recent-factor bypass.
            $this->managementFailure('action-required');
        } catch (Throwable $error) {
            $this->managementFailure('authentication');
        }
    }

    public function replaceRecoveryCodes(): never
    {
        $repository = null;
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->loadDependencies();
            $this->sharedOwnerAction($userId,'recovery_codes',['owner'=>$userId],true);
            $repository = new OwnerRecoveryCodeRepository($this->rc->get_dbh());
            $codes = $this->recoveryCodeService($repository)->replace($userId);
        } catch (Throwable $error) {
            $this->clearOwnerProof();
            if ($repository !== null && $repository->commitAttempted && !$repository->committed) {
                $this->managementFailure('recovery-unverified');
            }
            $this->managementFailure($error instanceof ManagementException ? $error->diagnosticCode : 'internal');
        }
        try { $notified = $this->notifySecurityEvent(SecurityEventNotifier::RECOVERY_CODES_REPLACED); }
        catch (Throwable $error) { $notified = false; }
        $this->json(200, ['ok' => true, 'recovery_codes' => $codes, 'notification_sent' => $notified]);
    }

    public function ownerRecoveryVerify(): never
    {
        $attempted = false;
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $body = $this->readJsonBody();
            $code = $body['code'] ?? null;
            if (!is_string($code) || strlen($code) > 120) {
                throw new ManagementException('Invalid code input.', 'input');
            }
            $service = $this->recoveryCodeService();
            $this->clearOwnerProof();
            $attempted = true;
            if (!$service->consume($userId, $code)) {
                $this->managementFailure('authentication');
            }
            // This is management proof, not a login or emergency recovery.
            // Do not send the legacy notification claiming a sign-in occurred.
            $this->json(200, ['ok' => true]);
        } catch (Throwable $error) {
            $this->clearOwnerProof();
            $code = $error instanceof ManagementException ? $error->diagnosticCode : 'internal';
            $this->managementFailure($attempted && in_array($code, ['storage', 'internal'], true)
                ? 'proof-unverified' : $code);
        }
    }

    private function clearOwnerProof(): void
    {
        if (class_exists(RecentFactorSession::class, false)) {
            $this->recentFactor()->clear();
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

    private function registrationService(): RegistrationService
    {
        $this->loadDependencies();
        return new RegistrationService(
            new RoundcubeCredentialRepository($this->rc->get_dbh()),
            WebauthnLibRegistrationValidator::create(),
            new RegistrationChallengeStore($_SESSION),
        );
    }

    private function assertionService(): AssertionService
    {
        $this->loadDependencies();
        return new AssertionService(
            new RoundcubeCredentialRepository($this->rc->get_dbh()),
            WebauthnLibAssertionValidator::create(),
            new AssertionChallengeStore($_SESSION),
        );
    }

    private function managementService(): CredentialManagementService
    {
        $this->loadDependencies();
        return new CredentialManagementService(
            new RoundcubeCredentialManagementRepository($this->rc->get_dbh()),
            $this->recentFactor(),
        );
    }

    private function recoveryCodeService(?OwnerRecoveryCodeRepository $repository = null): RecoveryCodeService
    {
        $this->loadDependencies();
        return new RecoveryCodeService(
            $repository ?? new OwnerRecoveryCodeRepository($this->rc->get_dbh()),
            new PhpRecoveryCodeHasher(),
            $this->recentFactor(),
        );
    }

    private function recentFactor(): RecentFactorSession
    {
        return new RecentFactorSession($_SESSION);
    }

    private function loadDependencies(): void
    {
        $autoload = '/opt/roundcube-auth/vendor/autoload.php';
        if (!is_readable($autoload)) {
            throw new RegistrationException(
                'Isolated WebAuthn dependencies are unavailable.',
                diagnosticCode: 'setup',
            );
        }
        require_once $autoload;
        foreach ([
            'RegistrationConfig.php',
            'StoredCredential.php',
            'ValidatedAssertion.php',
            'ValidatedCredential.php',
            'AssertionCredentialRepository.php',
            'CredentialRepository.php',
            'AssertionValidator.php',
            'RegistrationValidator.php',
            'AssertionChallengeStore.php',
            'RegistrationChallengeStore.php',
            'AssertionService.php',
            'RegistrationService.php',
            'RoundcubeCredentialRepository.php',
            'WebauthnLibAssertionValidator.php',
            'WebauthnLibRegistrationValidator.php',
            'ManagementException.php',
            'RecentFactorSession.php',
            'CredentialSummary.php',
            'CredentialManagementRepository.php',
            'CredentialManagementService.php',
            'RecoveryCodeHasher.php',
            'PhpRecoveryCodeHasher.php',
            'NewRecoveryCode.php',
            'StoredRecoveryCode.php',
            'RecoveryCodeRepository.php',
            'RecoveryCodeService.php',
            'RoundcubeCredentialManagementRepository.php',
            'RoundcubeRecoveryCodeRepository.php',
            'SessionEpochInvalidator.php',
            'MailAuthSessionEpochInvalidator.php',
            'RecoveryAddressRepository.php',
            'MailAuthRecoveryAddressRepository.php',
            'SecurityEventNotifier.php',
            'RoundcubeSecurityEventNotifier.php',
        ] as $file) {
            require_once self::LOCAL_AUTH_SOURCE . '/' . $file;
        }
        require_once __DIR__ . '/OwnerRegistrationTransaction.php';
        require_once __DIR__ . '/OwnerRecoveryCodeRepository.php';
        require_once self::LOCAL_AUTH_SOURCE . '/MfaRequirement.php';
        require_once __DIR__ . '/AccountIdentity.php';
        require_once __DIR__ . '/OwnerMfaPolicyRepository.php';
        require_once __DIR__ . '/OwnerPolicyNotifier.php';
    }

    private function notifySecurityEvent(string $event): bool
    {
        $this->loadDependencies();
        return (new RoundcubeSecurityEventNotifier(
            $this->rc,
            new MailAuthRecoveryAddressRepository(),
        ))->notify((string) $this->rc->get_user_name(), $event);
    }

    private function requireAuthenticatedUser(): int
    {
        $value = $_SESSION['user_id'] ?? null;
        if (is_int($value) && $value > 0) {
            return $value;
        }
        if (is_string($value) && preg_match('/\A[1-9][0-9]{0,9}\z/D', $value) === 1) {
            return (int) $value;
        }
        throw new RegistrationException('Authentication is required.');
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

    private function rotateAuthenticatedSession(): void
    {
        if ($this->rc->session->regenerate_id(true) !== true) {
            throw new ManagementException('Session rotation failed.', 'storage');
        }
        $this->rc->session->set_auth_cookie();
    }

    private function registrationFailure(string $diagnosticCode): never
    {
        $this->json(400, [
            'ok' => false,
            'error' => $this->gettext('registrationfailed'),
            'error_code' => $diagnosticCode,
        ]);
    }

    private function assertionFailure(string $diagnosticCode): never
    {
        $this->json(400, [
            'ok' => false,
            'error' => $this->gettext('assertionfailed'),
            'error_code' => $diagnosticCode,
        ]);
    }

    private function managementFailure(string $diagnosticCode): never
    {
        $status = $diagnosticCode === 'rate-limit' ? 429 : 400;
        $this->json($status, [
            'ok' => false,
            'error' => $this->gettext('managementfailed'),
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
