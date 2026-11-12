<?php
declare(strict_types=1);
namespace MailServer\CertificateWebCandidate;

require_once __DIR__ . '/../candidate-v1/OwnerController.php';
require_once '/usr/share/roundcube/plugins/.passkey-general-v1/local_auth/AccountIdentity.php';

use MailServer\ClientCertificatesCandidate\OwnerBridge;
use MailServer\ClientCertificatesCandidate\DownloadStream;
use MailServer\RoundcubePasskeyGeneral\AccountIdentity;

class BoundaryError extends \RuntimeException {}
function guard(bool $ok, string $code): void { if (!$ok) throw new BoundaryError($code); }

interface SessionState { public function snapshot(): array; }
final class NativeSessionState implements SessionState
{
    public function snapshot(): array
    {
        guard(session_status() === PHP_SESSION_ACTIVE, 'session_not_active');
        $id = session_id();
        guard(is_string($id) && strlen($id) >= 16 && strlen($id) <= 256, 'session_identifier_shape');
        return ['values' => $_SESSION, 'binding_hash' => hash('sha256', "mail-device-v1\0" . $id)];
    }
}

interface CurrentPolicy
{
    /** Reuse installed epoch guard/login Gate. No generic recent-factor bypass. */
    public function requireCurrent(\rcmail $rc, int $roundcubeId): void;
}
interface OwnerChannel
{
    /** Must attest this SERVER context via reviewed peer/session authority.
     * Serializing these fields alone is NOT authentication. No insecure default. */
    public function call(string $operation, object $context, array $input): array;
    /** Atomic owner/session claim before response headers. Range/replay denied. */
    public function claim(object $context, array $input): DownloadStream;
}
interface FailureAudit { public function record(\Throwable $error, string $operation): void; }

/** Calls real Roundcube APIs but never gets/boots an instance or opens DB/IPC. */
final class RoundcubeBridge implements OwnerBridge
{
    private ?object $issued = null;
    private bool $checked = false;
    public function __construct(private \rcmail $rc, private SessionState $state,
        private CurrentPolicy $policy, private OwnerChannel $channel, private FailureAudit $audit) {}

    public function requirePostCsrf(): void
    {
        $this->checked = false; $this->issued = null;
        guard(($_SERVER['REQUEST_METHOD'] ?? null) === 'POST'
            && !isset($_SERVER['HTTP_RANGE']), 'post_or_range_denied');
        $actual = \rcube_utils::request_header('X-Roundcube-Request');
        $expected = $this->rc->get_request_token();
        guard(is_string($expected) && strlen($expected) >= 16 && strlen($expected) <= 256
            && is_string($actual) && hash_equals($expected, $actual), 'csrf_mismatch');
        guard($this->rc->check_request(\rcube_utils::INPUT_POST) === true, 'roundcube_csrf_denied');
        $this->checked = true;
    }

    private function snapshot(): array
    {
        guard($this->checked, 'post_csrf_required');
        guard($this->rc->session instanceof \rcube_session
            && $this->rc->user instanceof \rcube_user
            && $this->rc->session->check_auth() === true, 'roundcube_auth_denied');
        $snapshot = $this->state->snapshot();
        $values = $snapshot['values'] ?? null; $binding = $snapshot['binding_hash'] ?? null;
        guard(is_array($values) && is_string($binding) && preg_match('/\A[0-9a-f]{64}\z/D', $binding) === 1,
            'session_snapshot_shape');
        $id = $this->rc->get_user_id();
        guard((is_int($id) || is_string($id)) && preg_match('/\A[1-9][0-9]{0,9}\z/D', (string) $id) === 1
            && (int) $id <= 4294967295 && (string) ($values['user_id'] ?? '') === (string) $id,
            'roundcube_id_mismatch');
        $name = $this->rc->get_user_name();
        guard(is_string($name) && is_string($values['username'] ?? null), 'session_username_shape');
        $name = AccountIdentity::canonical($name);
        guard(hash_equals($name, AccountIdentity::canonical($values['username']))
            && ($values['storage_host'] ?? null) === AccountIdentity::MAIL_HOST
            && ($this->rc->user->data['mail_host'] ?? null) === AccountIdentity::MAIL_HOST,
            'roundcube_session_mismatch');
        $this->policy->requireCurrent($this->rc, (int) $id);
        return ['roundcube_id' => (int) $id, 'username' => $name,
                'mail_host' => AccountIdentity::MAIL_HOST, 'binding_hash' => $binding];
    }

    public function authenticatedContext(): object
    {
        $this->issued = (object) $this->snapshot();
        return $this->issued;
    }

    private function recheck(object $context): void
    {
        guard($context === $this->issued && (array) $context === $this->snapshot(), 'session_changed');
    }

    public function call(string $operation, object $context, array $input): array
    {
        $this->recheck($context);
        guard(in_array($operation, ['list','issue_options','issue_finish','revoke_options','revoke_finish','verification_status','verification_options','verification_finish','verification_authorize','verification_consume','verification_invalidate'], true),
            'operation_scope');
        return $this->channel->call($operation, $context, $input);
    }
    public function claimDownload(object $context, array $input): DownloadStream
    {
        $this->recheck($context);
        guard(array_diff(array_keys($input), ['device_id','download_handle']) === [], 'download_input_scope');
        return $this->channel->claim($context, $input);
    }
    public function recordFailure(\Throwable $error, string $operation): void { $this->audit->record($error, $operation); }
}
