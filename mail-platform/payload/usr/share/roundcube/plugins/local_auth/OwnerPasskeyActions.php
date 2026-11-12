<?php
declare(strict_types=1);

use MailServer\RoundcubeAuth\RegistrationException;
use MailServer\RoundcubeAuthManagement\ManagementException;
use MailServer\RoundcubeAuthManagement\MailAuthSessionEpochInvalidator;
use MailServer\RoundcubeAuthManagement\SecurityEventNotifier;

require_once __DIR__ . '/OwnerActionSession.php';
require_once __DIR__ . '/OwnerCredentialRemoval.php';

trait OwnerPasskeyActions
{
    public function ownerRemovalOptions(): never
    {
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->loadDependencies();
            $body = $this->readJsonBody();
            $id = $body['credential_id'] ?? null;
            if (!is_int($id) || $id <= 0) { throw new ManagementException('Invalid target.', 'input'); }
            $rows = $this->managementService()->list($userId);
            $found = false; $enabled = 0;
            foreach ($rows as $row) {
                if ($row->enabled) { ++$enabled; $found = $found || $row->id === $id; }
            }
            if (!$found) { throw new ManagementException('Target unavailable.', 'input'); }
            if ($enabled <= 1) { throw new ManagementException('Keep one Passkey.', 'last-factor'); }
            $this->sharedOwnerAction($userId,'passkey_disable',['credential_id'=>$id]);
            $start=['ceremony_id'=>bin2hex(random_bytes(32)),'publicKey'=>new stdClass(),'authentication_required'=>false];
            OwnerActionSession::issue($_SESSION, $userId, $id, $start['ceremony_id']);
            $this->json(200, ['ok' => true] + $start);
        } catch (ManagementException $e) { $this->managementFailure($e->diagnosticCode); }
        catch (RegistrationException $e) { $this->assertionFailure($e->diagnosticCode); }
        catch (Throwable $e) { $this->managementFailure('internal'); }
    }

    public function ownerRemovalFinish(): never
    {
        $removed = false;
        $repository = null;
        try {
            $userId = $this->requireAuthenticatedUser();
            $this->requireCsrf();
            $this->loadDependencies();
            $body = $this->readJsonBody();
            $ceremony = $body['ceremony_id'] ?? null;
            if (!is_string($ceremony)) { throw new ManagementException('Invalid proof.', 'input'); }
            $id = OwnerActionSession::consume($_SESSION, $userId, $ceremony);
            // Success here requires the existing UV/RP/origin/challenge/owner validator.
            if (($body['credential']??null)!==null) { throw new ManagementException('Invalid proof.', 'input'); }
            $this->sharedOwnerAction($userId,'passkey_disable',['credential_id'=>$id],true);
            $repository = new OwnerCredentialRemoval($this->rc->get_dbh());
            $repository->remove($userId, $id, function (): void {
                $_SESSION['mail_auth_epoch'] = (new MailAuthSessionEpochInvalidator())->bump((string) $this->rc->get_user_name());
            });
            $removed = true;
            $this->rotateAuthenticatedSession();
            $notified = $this->notifySecurityEvent(SecurityEventNotifier::PASSKEY_DISABLED);
            $this->json(200, ['ok' => true, 'notification_sent' => $notified, 'session_warning' => false]);
        } catch (Throwable $e) {
            // Post-commit session/notification error must not falsely report no change.
            if ($removed) { $this->json(200, ['ok' => true, 'notification_sent' => false, 'session_warning' => true]); }
            if ($repository !== null && $repository->mutationAttempted) {
                $this->json(409, ['ok' => false, 'error_code' => 'removal-unverified']);
            }
            if ($e instanceof ManagementException) { $this->managementFailure($e->diagnosticCode); }
            if ($e instanceof RegistrationException) { $this->assertionFailure($e->diagnosticCode); }
            $this->managementFailure('internal');
        }
    }
}
