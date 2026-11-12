<?php
declare(strict_types=1);

use MailServer\RoundcubePasskeyGeneral\OwnerMfaPolicyRepository;
use MailServer\RoundcubePasskeyGeneral\OwnerPolicyNotifier;

trait OwnerPolicyActions
{
    public function ownerPolicy(): never
    {
        try {
            $owner = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->loadDependencies();
            $state = (new OwnerMfaPolicyRepository($this->rc->get_dbh()))->status($owner);
            $this->json(200, ['ok'=>true, 'policy'=>$state]);
        } catch (Throwable $error) { $this->managementFailure('storage'); }
    }

    public function ownerPolicySave(): never
    {
        $repository = null;
        try {
            $owner = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->loadDependencies();
            $body = $this->readJsonBody();
            $required = $body['required'] ?? null;
            if (!is_bool($required)) throw new \MailServer\RoundcubeAuthManagement\ManagementException('Invalid choice.', 'input');
            $this->sharedOwnerAction($owner,'passkey_policy',['required'=>$required],true);
            if (!$this->recentFactor()->isRecent($owner)) {
                throw new \MailServer\RoundcubeAuthManagement\ManagementException('Fresh owner proof required.', 'authentication');
            }
            $repository = new OwnerMfaPolicyRepository($this->rc->get_dbh());
            $repository->save($owner, $required, function (): void {
                $_SESSION['mail_auth_epoch'] = (new \MailServer\RoundcubeAuthManagement\MailAuthSessionEpochInvalidator())->bump(
                    (string) $this->rc->get_user_name());
            });
            $this->clearOwnerProof();
        } catch (Throwable $error) {
            $this->clearOwnerProof();
            if ($repository !== null && $repository->commitAttempted && !$repository->committed) {
                $this->managementFailure('policy-unverified');
            }
            $this->managementFailure($error instanceof \MailServer\RoundcubeAuthManagement\ManagementException
                ? $error->diagnosticCode : 'storage');
        }
        $warning = false;
        try { $this->rotateAuthenticatedSession(); } catch (Throwable $error) { $warning = true; }
        $notified = (new OwnerPolicyNotifier())->notify($this->rc, (string) $this->rc->get_user_name(), $required);
        $this->json(200, ['ok'=>true, 'required'=>$required, 'session_warning'=>$warning, 'notification_sent'=>$notified]);
    }
}
