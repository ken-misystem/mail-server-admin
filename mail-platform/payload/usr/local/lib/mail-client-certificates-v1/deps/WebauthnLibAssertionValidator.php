<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebauthnLibAssertionValidator implements AssertionValidator
{
    private function __construct(
        private readonly SerializerInterface $serializer,
        private readonly AuthenticatorAssertionResponseValidator $validator,
    ) {
    }

    public static function create(): self
    {
        $attestationManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);
        $ceremonyFactory = new CeremonyStepManagerFactory();
        $ceremonyFactory->setAttestationStatementSupportManager($attestationManager);
        $ceremonyFactory->setAllowedOrigins([RegistrationConfig::ORIGIN], false);

        $serializer = (new WebauthnSerializerFactory($attestationManager))->create();
        $validator = AuthenticatorAssertionResponseValidator::create(
            $ceremonyFactory->requestCeremony(),
        );

        // Never attach an application logger. Assertion contexts contain the
        // challenge, credential ID, public key, signature, and user handle.
        return new self($serializer, $validator);
    }

    public function createOptions(string $challenge, array $allowedCredentials): string
    {
        try {
            $allowed = array_map(
                static fn (array $item): PublicKeyCredentialDescriptor =>
                    PublicKeyCredentialDescriptor::create(
                        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                        $item['id'],
                        $item['transports'],
                    ),
                $allowedCredentials,
            );

            $options = PublicKeyCredentialRequestOptions::create(
                challenge: $challenge,
                rpId: RegistrationConfig::RP_ID,
                allowCredentials: $allowed,
                userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                timeout: RegistrationConfig::CHALLENGE_TTL_SECONDS * 1000,
            );

            return $this->serialize($options);
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey assertion options could not be created.',
                0,
                $e,
                'options-encode',
            );
        }
    }

    public function validate(
        string $responseJson,
        string $optionsJson,
        StoredCredential $stored,
        string $expectedUserHandle,
    ): ValidatedAssertion {
        try {
            $publicKeyCredential = $this->serializer->deserialize(
                $responseJson,
                PublicKeyCredential::class,
                'json',
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey assertion response decoding failed.',
                0,
                $e,
                'response-decode',
            );
        }

        try {
            $options = $this->serializer->deserialize(
                $optionsJson,
                PublicKeyCredentialRequestOptions::class,
                'json',
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey assertion options decoding failed.',
                0,
                $e,
                'options-decode',
            );
        }

        try {
            $record = $this->serializer->deserialize(
                $stored->credentialRecordJson,
                CredentialRecord::class,
                'json',
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Stored credential record decoding failed.',
                0,
                $e,
                'record-decode',
            );
        }

        if (!$publicKeyCredential instanceof PublicKeyCredential
            || !$publicKeyCredential->response instanceof AuthenticatorAssertionResponse
            || !$options instanceof PublicKeyCredentialRequestOptions
            || !$record instanceof CredentialRecord
        ) {
            throw new RegistrationException(
                'Passkey assertion has an unexpected type.',
                diagnosticCode: 'response-type',
            );
        }

        if (!hash_equals($stored->credentialId, $publicKeyCredential->rawId)
            || !hash_equals($stored->credentialId, $record->publicKeyCredentialId)
            || !hash_equals($stored->userHandle, $record->userHandle)
            || !hash_equals($expectedUserHandle, $stored->userHandle)
        ) {
            throw new RegistrationException(
                'Passkey assertion credential does not match.',
                diagnosticCode: 'credential',
            );
        }

        try {
            $validated = $this->validator->check(
                $record,
                $publicKeyCredential->response,
                $options,
                RegistrationConfig::RP_ID,
                $expectedUserHandle,
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey assertion validation failed.',
                0,
                $e,
                self::safeCeremonyCode($e),
            );
        }

        if (!$validated instanceof CredentialRecord) {
            throw new RegistrationException(
                'Passkey assertion returned an invalid record.',
                diagnosticCode: 'record-type',
            );
        }

        try {
            return new ValidatedAssertion(
                $validated->publicKeyCredentialId,
                $validated->userHandle,
                $this->serialize($validated),
                $validated->counter,
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Updated credential record encoding failed.',
                0,
                $e,
                'record-encode',
            );
        }
    }

    private static function safeCeremonyCode(Throwable $exception): string
    {
        // Inspect only in memory and emit a fixed category. Never return or log
        // the upstream message or any assertion material.
        $message = strtolower($exception->getMessage());

        return match (true) {
            str_contains($message, 'challenge') => 'ceremony-challenge',
            str_contains($message, 'origin') => 'ceremony-origin',
            str_contains($message, 'rpid'), str_contains($message, 'rp id') => 'ceremony-rp',
            str_contains($message, 'user verification'), str_contains($message, 'user verified')
                => 'ceremony-user-verification',
            str_contains($message, 'user presence'), str_contains($message, 'user present')
                => 'ceremony-user-presence',
            str_contains($message, 'counter'), str_contains($message, 'sign count')
                => 'ceremony-counter',
            str_contains($message, 'credential') => 'credential',
            str_contains($message, 'algorithm') => 'ceremony-algorithm',
            str_contains($message, 'signature') => 'ceremony-signature',
            default => 'ceremony-other',
        };
    }

    private function serialize(object $value): string
    {
        return $this->serializer->serialize(
            $value,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ],
        );
    }
}
