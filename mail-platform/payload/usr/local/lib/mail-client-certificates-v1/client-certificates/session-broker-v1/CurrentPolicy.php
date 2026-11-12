<?php
declare(strict_types=1);
namespace MailServer\CertificateSessionCandidate;
require_once __DIR__ . '/../web-runtime-v1/RoundcubeBridge.php';
require_once __DIR__ . '/../../roundcube-passkey/general/candidate/local_auth_gate/src/GateSession.php';
require_once __DIR__ . '/../../roundcube-passkey/general/candidate/local_auth_gate/src/emergency/EmergencyRecoverySession.php';

use MailServer\CertificateWebCandidate\CurrentPolicy;
use MailServer\CertificateWebCandidate\SessionState;
use MailServer\RoundcubeAuthGate\GateSession;
use MailServer\RoundcubeEmergencyRecovery\EmergencyRecoverySession;
use MailServer\RoundcubePasskeyGeneral\AccountIdentity;
use function MailServer\CertificateWebCandidate\guard;

final class EpochView
{
    public function __construct(public readonly int $roundcubeId, public readonly string $username,
        public readonly int $epoch, public readonly bool $active) {}
}
interface EpochReader
{
    /** Fresh current owner/epoch lookup; no cached allow or session-echo implementation. */
    public function current(int $roundcubeId, string $username): EpochView;
}

final class BoundCurrentPolicy implements CurrentPolicy
{
    public function __construct(private SessionState $state, private EpochReader $epochs) {}
    public function requireCurrent(\rcmail $rc, int $roundcubeId): void
    {
        $before = $this->state->snapshot();
        $values = $before['values'] ?? null;
        guard(is_array($values) && $roundcubeId > 0
            && (string)($values['user_id'] ?? '') === (string)$roundcubeId, 'policy_session_owner');
        // Presence rejects pending, expired AND malformed Gate/recovery state.
        guard(!(new GateSession($values))->hasState()
            && !(new EmergencyRecoverySession($values))->hasState(), 'policy_gate_pending');
        $name = AccountIdentity::canonical($rc->get_user_name());
        guard(is_string($values['username'] ?? null)
            && hash_equals($name, AccountIdentity::canonical($values['username']))
            && ($values['storage_host'] ?? null) === AccountIdentity::MAIL_HOST, 'policy_session_identity');
        $epoch = $values['mail_auth_epoch'] ?? null;
        guard(is_int($epoch) && $epoch >= 0, 'policy_session_epoch_type');
        $current = $this->epochs->current($roundcubeId, $name);
        guard($current->roundcubeId === $roundcubeId && $current->username === $name
            && $current->active && $current->epoch === $epoch, 'policy_epoch_changed');
        guard($this->state->snapshot() === $before, 'policy_session_changed');
    }
}

