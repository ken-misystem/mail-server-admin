<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

final class RegistrationService
{
    public function __construct(
        private readonly CredentialRepository $repository,
        private readonly RegistrationValidator $validator,
        private readonly RegistrationChallengeStore $challengeStore,
    ) {
    }

    /** @return array{ceremony_id: string, publicKey: array<string, mixed>} */
    public function begin(int $userId, string $username, string $displayName): array
    {
        if ($userId <= 0 || $username === '') {
            throw new RegistrationException('An authenticated Roundcube user is required.');
        }

        $userHandle = $this->repository->getOrCreateUserHandle($userId);
        if (strlen($userHandle) !== 32) {
            throw new RegistrationException('The WebAuthn user handle is invalid.');
        }

        $optionsJson = $this->validator->createOptions(
            $username,
            $displayName !== '' ? $displayName : $username,
            $userHandle,
            random_bytes(32),
            $this->repository->enabledCredentialDescriptors($userId),
        );

        $options = json_decode($optionsJson, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($options)) {
            throw new RegistrationException('WebAuthn options are invalid.');
        }

        return [
            'ceremony_id' => $this->challengeStore->issue($userId, $userHandle, $optionsJson),
            'publicKey' => $options,
        ];
    }

    public function finish(
        int $userId,
        string $ceremonyId,
        string $responseJson,
        string $label,
    ): void {
        // Consume at the start of every finish attempt, before parsing or
        // validation, so malformed input cannot be retried with the same state.
        $state = $this->challengeStore->consume($userId, $ceremonyId);

        if (strlen($responseJson) > RegistrationConfig::MAX_RESPONSE_BYTES) {
            throw new RegistrationException(
                'Registration response is too large.',
                diagnosticCode: 'input',
            );
        }

        $label = trim($label);
        $labelPattern = '/\A.{1,' . RegistrationConfig::MAX_LABEL_CHARACTERS . '}\z/us';
        if (preg_match($labelPattern, $label) !== 1
            || preg_match('/[\x00-\x1F\x7F]/u', $label)
        ) {
            throw new RegistrationException(
                'Passkey label is invalid.',
                diagnosticCode: 'input',
            );
        }

        $credential = $this->validator->validate($responseJson, $state['options_json']);

        $credentialIdLength = strlen($credential->credentialId);
        if ($credentialIdLength < 1
            || $credentialIdLength > RegistrationConfig::MAX_CREDENTIAL_ID_BYTES
        ) {
            throw new RegistrationException(
                'Credential ID has an invalid length.',
                diagnosticCode: 'credential',
            );
        }

        if (!hash_equals($state['user_handle'], $credential->userHandle)) {
            throw new RegistrationException(
                'Credential user handle does not match.',
                diagnosticCode: 'credential',
            );
        }

        if ($this->repository->credentialExists($credential->credentialId)) {
            throw new RegistrationException(
                'This credential is already registered.',
                diagnosticCode: 'credential',
            );
        }

        $this->repository->saveNewCredential($userId, $credential, $label);
    }
}
