<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use MailServer\RoundcubeAuth\StoredCredential;
use MailServer\RoundcubeAuth\WebauthnLibRegistrationValidator;
use MailServer\RoundcubeAuth\WebauthnLibAssertionValidator;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;

/** UI/storage facade over the existing unchanged Roundcube validation core. */
final class AdminWebauthn
{
    public const RP_ID = 'mx.mi-sys.jp';
    public const ORIGIN = 'https://mx.mi-sys.jp';
    public const TTL = 120;
    private readonly SerializerInterface $serializer;
    private readonly WebauthnLibRegistrationValidator $registration;
    private readonly WebauthnLibAssertionValidator $assertion;

    public function __construct()
    {
        SharedPasskeyCore::register();
        if (\MailServer\RoundcubeAuth\RegistrationConfig::RP_ID !== self::RP_ID
            || \MailServer\RoundcubeAuth\RegistrationConfig::ORIGIN !== self::ORIGIN) {
            throw new \DomainException('shared_passkey_scope');
        }
        // Record codec only; options and ceremony validation are delegated to the existing core.
        $manager = new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]);
        $this->serializer = (new WebauthnSerializerFactory($manager))->create();
        $this->registration = WebauthnLibRegistrationValidator::create();
        $this->assertion = WebauthnLibAssertionValidator::create();
    }

    public function registrationOptions(AdminUser $user, string $handle, array $records): string
    {
        if (strlen($handle) < 16 || strlen($handle) > 64) { throw new \DomainException('invalid_user_handle'); }
        $options = json_decode($this->registration->createOptions($user->getUserIdentifier(),
            $user->getUserIdentifier(), $handle, random_bytes(32), $this->descriptors($records)), true, 32, JSON_THROW_ON_ERROR);
        $options['rp']['name'] = 'Mail administration'; // Display-only adapter difference.
        $options['timeout'] = self::TTL * 1000; // Preserve existing admin session deadline.
        return json_encode($options, JSON_THROW_ON_ERROR);
    }

    public function assertionOptions(array $records): string
    {
        if (!$records) { throw new \DomainException('no_enabled_passkey'); }
        $options = json_decode($this->assertion->createOptions(random_bytes(32), $this->descriptors($records)),
            true, 32, JSON_THROW_ON_ERROR);
        $options['timeout'] = self::TTL * 1000;
        return json_encode($options, JSON_THROW_ON_ERROR);
    }

    public function registration(string $response, string $options): CredentialRecord
    {
        try {
            $credential = $this->serializer->deserialize($response, PublicKeyCredential::class, 'json');
            $creation = $this->serializer->deserialize($options, PublicKeyCredentialCreationOptions::class, 'json');
            if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAttestationResponse
                || !$creation instanceof PublicKeyCredentialCreationOptions) { throw new \DomainException(); }
            $record = $this->decode($this->registration->validate($response, $options)->credentialRecordJson);
            if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)
                || !hash_equals($record->userHandle, $creation->user->id)) { throw new \DomainException(); }
            return $record;
        } catch (\Throwable) { throw new \DomainException('passkey_validation_failed'); }
    }

    public function credentialId(string $response): string
    {
        try {
            $credential = $this->serializer->deserialize($response, PublicKeyCredential::class, 'json');
            if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAssertionResponse) {
                throw new \DomainException();
            }
            return $credential->rawId;
        } catch (\Throwable) { throw new \DomainException('passkey_validation_failed'); }
    }

    public function assertion(string $response, string $options, string $stored, string $handle): CredentialRecord
    {
        try {
            $record = $this->decode($stored);
            return $this->decode($this->assertion->validate($response, $options,
                new StoredCredential($record->publicKeyCredentialId, $record->userHandle, $stored), $handle)->credentialRecordJson);
        } catch (\Throwable) { throw new \DomainException('passkey_validation_failed'); }
    }

    public function decode(string $json): CredentialRecord
    {
        try {
            $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
            if (!$record instanceof CredentialRecord) { throw new \DomainException(); }
            return $record;
        } catch (\Throwable) { throw new \DomainException('invalid_credential_record'); }
    }

    public function encode(object $value): string
    {
        return $this->serializer->serialize($value, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true, JsonEncode::OPTIONS => JSON_THROW_ON_ERROR]);
    }

    private function descriptors(array $records): array
    {
        return array_map(static fn (CredentialRecord $r): array => ['id' => $r->publicKeyCredentialId,
            'transports' => array_values($r->transports)], $records);
    }
}
