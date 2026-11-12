<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebauthnLibRegistrationValidator implements RegistrationValidator
{
    private function __construct(
        private readonly SerializerInterface $serializer,
        private readonly AuthenticatorAttestationResponseValidator $validator,
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
        $validator = AuthenticatorAttestationResponseValidator::create(
            $ceremonyFactory->creationCeremony(),
        );

        // Do not attach an application logger. Upstream validator contexts contain
        // challenges, responses, credential IDs, and public-key material.
        return new self($serializer, $validator);
    }

    public function createOptions(
        string $username,
        string $displayName,
        string $userHandle,
        string $challenge,
        array $excludedCredentials,
    ): string {
        $excluded = array_map(
            static fn (array $item): PublicKeyCredentialDescriptor =>
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    $item['id'],
                    $item['transports'],
                ),
            $excludedCredentials,
        );

        $selection = AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        );

        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create(
                RegistrationConfig::RP_NAME,
                RegistrationConfig::RP_ID,
            ),
            PublicKeyCredentialUserEntity::create(
                $username,
                $userHandle,
                $displayName,
            ),
            $challenge,
            authenticatorSelection: $selection,
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $excluded,
            timeout: RegistrationConfig::CHALLENGE_TTL_SECONDS * 1000,
        );

        return $this->serialize($options);
    }

    public function validate(string $responseJson, string $optionsJson): ValidatedCredential
    {
        try {
            $publicKeyCredential = $this->serializer->deserialize(
                $responseJson,
                PublicKeyCredential::class,
                'json',
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey response decoding failed.',
                0,
                $e,
                'response-decode',
            );
        }

        try {
            $options = $this->serializer->deserialize(
                $optionsJson,
                PublicKeyCredentialCreationOptions::class,
                'json',
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey options decoding failed.',
                0,
                $e,
                'options-decode',
            );
        }

        if (!$publicKeyCredential instanceof PublicKeyCredential
            || !$publicKeyCredential->response instanceof AuthenticatorAttestationResponse
            || !$options instanceof PublicKeyCredentialCreationOptions
        ) {
            throw new RegistrationException(
                'Registration response has an unexpected type.',
                diagnosticCode: 'response-type',
            );
        }

        try {
            // The third argument is the fixed RP host. Exact Origin enforcement is
            // independently configured in CeremonyStepManagerFactory above.
            $record = $this->validator->check(
                $publicKeyCredential->response,
                $options,
                RegistrationConfig::RP_ID,
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Passkey ceremony validation failed.',
                0,
                $e,
                self::safeCeremonyCode($e),
            );
        }

        if (!$record instanceof CredentialRecord) {
            throw new RegistrationException(
                'Upstream validation returned an invalid record.',
                diagnosticCode: 'record-type',
            );
        }

        try {
            return new ValidatedCredential(
                $record->publicKeyCredentialId,
                $record->userHandle,
                $this->serialize($record),
                $record->counter,
                array_values($record->transports),
            );
        } catch (Throwable $e) {
            throw new RegistrationException(
                'Credential record encoding failed.',
                0,
                $e,
                'record-encode',
            );
        }
    }

    private static function safeCeremonyCode(Throwable $exception): string
    {
        // Inspect only in memory and emit a fixed category. Never return or log
        // the upstream message, which may retain ceremony context.
        $message = strtolower($exception->getMessage());

        return match (true) {
            str_contains($message, 'challenge') => 'ceremony-challenge',
            str_contains($message, 'origin') => 'ceremony-origin',
            str_contains($message, 'rpid'), str_contains($message, 'rp id') => 'ceremony-rp',
            str_contains($message, 'user verification'), str_contains($message, 'user verified')
                => 'ceremony-user-verification',
            str_contains($message, 'user presence'), str_contains($message, 'user present')
                => 'ceremony-user-presence',
            str_contains($message, 'algorithm') => 'ceremony-algorithm',
            str_contains($message, 'attestation') => 'ceremony-attestation',
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
