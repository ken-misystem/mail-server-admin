<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

use Throwable;

final class AssertionService
{
    public function __construct(
        private readonly AssertionCredentialRepository $repository,
        private readonly AssertionValidator $validator,
        private readonly AssertionChallengeStore $challengeStore,
    ) {
    }

    /** @return array{ceremony_id: string, publicKey: array<string, mixed>} */
    public function begin(int $userId): array
    {
        if ($userId <= 0) {
            throw new RegistrationException('An authenticated Roundcube user is required.');
        }

        $userHandle = $this->repository->getUserHandle($userId);
        $descriptors = $this->repository->enabledCredentialDescriptors($userId);
        if (!is_string($userHandle) || strlen($userHandle) !== 32 || $descriptors === []) {
            throw new RegistrationException(
                'No enabled Passkey is available.',
                diagnosticCode: 'credential',
            );
        }

        $optionsJson = $this->validator->createOptions(
            random_bytes(32),
            $descriptors,
        );
        $options = json_decode($optionsJson, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($options)) {
            throw new RegistrationException(
                'Passkey assertion options are invalid.',
                diagnosticCode: 'options-encode',
            );
        }

        return [
            'ceremony_id' => $this->challengeStore->issue($userId, $userHandle, $optionsJson),
            'publicKey' => $options,
        ];
    }

    public function finish(int $userId, string $ceremonyId, string $responseJson): void
    {
        $state = $this->challengeStore->consume($userId, $ceremonyId);

        if (strlen($responseJson) > RegistrationConfig::MAX_RESPONSE_BYTES) {
            throw new RegistrationException(
                'Passkey assertion response is too large.',
                diagnosticCode: 'input',
            );
        }

        $credentialId = self::credentialIdFromResponse($responseJson);
        $stored = $this->repository->lockEnabledCredential($userId, $credentialId);

        try {
            if (!hash_equals($state['user_handle'], $stored->userHandle)) {
                throw new RegistrationException(
                    'Stored credential user handle does not match.',
                    diagnosticCode: 'credential',
                );
            }

            $validated = $this->validator->validate(
                $responseJson,
                $state['options_json'],
                $stored,
                $state['user_handle'],
            );

            if (!hash_equals($stored->credentialId, $validated->credentialId)
                || !hash_equals($state['user_handle'], $validated->userHandle)
                || $validated->signCount < 0
                || strlen($validated->credentialRecordJson) > RegistrationConfig::MAX_RECORD_BYTES
            ) {
                throw new RegistrationException(
                    'Validated credential is inconsistent.',
                    diagnosticCode: 'credential',
                );
            }

            $this->repository->completeAssertion($userId, $stored, $validated);
        } catch (Throwable $e) {
            $this->repository->rollbackAssertion();
            throw $e;
        }
    }

    private static function credentialIdFromResponse(string $responseJson): string
    {
        try {
            $response = json_decode($responseJson, true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey assertion response decoding failed.',
                0,
                $e,
                'response-decode',
            );
        }

        $encoded = is_array($response) ? ($response['rawId'] ?? null) : null;
        $maxEncodedLength = (int) ceil(RegistrationConfig::MAX_CREDENTIAL_ID_BYTES * 4 / 3);
        if (!is_string($encoded)
            || strlen($encoded) < 2
            || strlen($encoded) > $maxEncodedLength
            || preg_match('/\A[A-Za-z0-9_-]+\z/D', $encoded) !== 1
        ) {
            throw new RegistrationException(
                'Passkey credential ID is invalid.',
                diagnosticCode: 'input',
            );
        }

        $padding = (4 - strlen($encoded) % 4) % 4;
        $decoded = base64_decode(strtr($encoded . str_repeat('=', $padding), '-_', '+/'), true);
        if (!is_string($decoded)
            || strlen($decoded) < 1
            || strlen($decoded) > RegistrationConfig::MAX_CREDENTIAL_ID_BYTES
        ) {
            throw new RegistrationException(
                'Passkey credential ID is invalid.',
                diagnosticCode: 'input',
            );
        }

        return $decoded;
    }
}
