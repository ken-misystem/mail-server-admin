<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use MailServer\RoundcubeAuth\RegistrationException;
use MailServer\RoundcubeAuth\RegistrationValidator;
use Throwable;

final class UpstreamEmergencyRecoveryRegistrationCeremony implements EmergencyRecoveryRegistrationCeremony
{
    public function __construct(
        private readonly EmergencyRecoveryWebauthnSource $credentials,
        private readonly RegistrationValidator $validator,
        private readonly EmergencyRecoveryRegistrationChallengeStore $challenges,
    ) {
    }

    public function begin(int $roundcubeUserId, string $accountIdentifier): array
    {
        $account = strtolower(trim($accountIdentifier));
        if ($roundcubeUserId <= 0
            || !\MailServer\RoundcubePasskeyGeneral\AccountIdentity::valid($account)
        ) {
            throw new EmergencyRecoveryException('Recovery is unavailable.', 'authentication');
        }

        try {
            $userHandle = $this->credentials->userHandle($roundcubeUserId);
            $optionsJson = $this->validator->createOptions(
                $account,
                $account,
                $userHandle,
                random_bytes(32),
                $this->credentials->allCredentialDescriptors($roundcubeUserId),
            );
            $options = json_decode($optionsJson, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($options)) {
                throw new EmergencyRecoveryException('Registration options are invalid.', 'internal');
            }
            $ceremonyId = $this->challenges->issue(
                $roundcubeUserId,
                $userHandle,
                $optionsJson,
            );
            return ['ceremony_id' => $ceremonyId, 'publicKey' => $options];
        } catch (EmergencyRecoveryException $e) {
            throw $e;
        } catch (RegistrationException $e) {
            throw self::fromRegistrationException($e);
        } catch (Throwable $e) {
            throw new EmergencyRecoveryException('Registration options are unavailable.', 'internal');
        }
    }

    public function finish(
        int $roundcubeUserId,
        string $ceremonyId,
        string $responseJson,
    ): EmergencyRecoveryCredential {
        try {
            $state = $this->challenges->consume($roundcubeUserId, $ceremonyId);
            $validated = $this->validator->validate($responseJson, $state['options_json']);
            if (!hash_equals($state['user_handle'], $validated->userHandle)
                || $this->credentials->credentialExists($validated->credentialId)
            ) {
                throw new EmergencyRecoveryException('Credential is unavailable.', 'input');
            }
            return new EmergencyRecoveryCredential(
                $validated->credentialId,
                $validated->userHandle,
                $validated->credentialRecordJson,
                $validated->signCount,
                $validated->transports,
            );
        } catch (EmergencyRecoveryException $e) {
            throw $e;
        } catch (RegistrationException $e) {
            throw self::fromRegistrationException($e);
        } catch (Throwable $e) {
            throw new EmergencyRecoveryException('Registration validation failed.', 'internal');
        }
    }

    private static function fromRegistrationException(RegistrationException $exception): EmergencyRecoveryException
    {
        $code = match ($exception->diagnosticCode) {
            'setup' => 'setup',
            'state' => 'state',
            'storage' => 'storage',
            default => 'input',
        };
        return new EmergencyRecoveryException('Registration failed.', $code);
    }
}
