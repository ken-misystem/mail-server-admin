<?php
declare(strict_types=1);
namespace MailServer\OwnerLifecycleV1;

/** Explicit authenticated owner IPC port. Browser flags never authorize mutations. */
final class OwnerVerification
{
    private \Closure $ipc;
    public function __construct(callable $authenticatedOwnerIpc)
    {
        $this->ipc = \Closure::fromCallable($authenticatedOwnerIpc);
    }
    public function status(): array
    {
        $value = ($this->ipc)('verification_status', []);
        if (!is_bool($value['authentication_required'] ?? null)
            || !is_int($value['remaining_seconds'] ?? null) || $value['remaining_seconds'] < 0
            || $value['remaining_seconds'] > 900) { throw new \DomainException('verification_status_contract'); }
        return $value;
    }
    public function begin(): array
    {
        $value = ($this->ipc)('verification_options', []);
        if (($value['authentication_required'] ?? null) === false) { return $this->status(); }
        if (($value['authentication_required'] ?? null) !== true || !is_string($value['action_id'] ?? null)
            || !is_array($value['publicKey'] ?? null)) { throw new \DomainException('verification_options_contract'); }
        return $value;
    }
    public function finish(string $action, mixed $assertion): void
    {
        $value = ($this->ipc)('verification_finish', ['action_id'=>$action, 'assertion'=>$assertion]);
        if (($value['authentication_required'] ?? null) !== false || ($value['remaining_seconds'] ?? null) !== 900) {
            throw new \DomainException('verification_finish_contract');
        }
    }
    public function invalidate(): void
    {
        if (($this->ipc)('verification_invalidate', []) !== ['invalidated'=>true]) {
            throw new \DomainException('verification_invalidation_unverified');
        }
    }
    public function requireAction(string $purpose, array $trustedTarget): void
    {
        $allowed = ['passkey_add','passkey_disable','passkey_policy','recovery_codes',
            'app_password_issue','app_password_revoke','certificate_issue','certificate_revoke',
            'password_change','recovery_address'];
        if (!in_array($purpose, $allowed, true)) { throw new \DomainException('owner_action_scope'); }
        // Caller derives target from its validated existing owner operation, not an auth flag.
        $target = hash('sha256', json_encode($trustedTarget, JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES));
        $grant = ($this->ipc)('verification_authorize', ['purpose'=>$purpose,'target'=>$target]);
        if (!is_array($grant) || !is_string($grant['authorization_id'] ?? null)
            || !preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $grant['authorization_id'])) {
            throw new \DomainException('fresh_passkey_required');
        }
        $receipt = ($this->ipc)('verification_consume', ['purpose'=>$purpose,'target'=>$target,'authorization_id'=>$grant['authorization_id']]);
        if ($receipt !== ['authorized'=>true]) { throw new \DomainException('owner_action_unverified'); }
    }
}
