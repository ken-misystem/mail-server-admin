<?php
declare(strict_types=1);

/** Included only by local_auth, after its declarations. No plugin init. */
trait OwnerLifecycleIntegrationV1
{
    private function sharedOwnerClient(): \MailServer\OwnerLifecycleV1\OwnerVerification
    {
        require_once '/usr/local/lib/mail-client-certificates-web-v3/client-certificates/owner-lifecycle-v1/OwnerClient.php';
        return \MailServer\OwnerLifecycleV1\ownerClient($this->rc);
    }
    public function ownerVerificationStatus(): never
    {
        try {
            $this->requireAuthenticatedUser(); $this->requireCsrf();
            $this->json(200, ['ok'=>true] + $this->sharedOwnerClient()->status());
        } catch (Throwable $error) { $this->managementFailure('authentication'); }
    }
    private function sharedOwnerAction(int $owner, string $purpose, array $target, bool $invalidate = false): void
    {
        // Preserve the existing Recovery Code fallback, with its existing300s
        // scope. It never mints or extends the shared Passkey900s authority.
        $legacy = $_SESSION[\MailServer\RoundcubeAuthManagement\RecentFactorSession::SESSION_KEY] ?? null;
        if (is_array($legacy) && ($legacy['factor'] ?? null) === 'recovery-code'
            && $this->recentFactor()->isRecent($owner)) {
            if ($invalidate) { $this->sharedOwnerClient()->invalidate(); }
            return;
        }
        $client = $this->sharedOwnerClient();
        $client->requireAction($purpose, $target);
        if ($invalidate) { $client->invalidate(); }
        // Existing services keep their original checks. Only this trusted
        // path marks their short-lived local proof after broker authorization.
        $this->recentFactor()->mark($owner, 'passkey');
    }
    private function sharedRegistration(int $owner, bool $finish): void
    {
        $enabled = array_filter($this->managementService()->list($owner), static fn($row): bool => $row->enabled);
        if ($enabled !== []) { $this->sharedOwnerAction($owner, 'passkey_add', ['owner'=>$owner], $finish); }
        // No existing Passkey: retain the existing first-registration bootstrap.
    }
}
