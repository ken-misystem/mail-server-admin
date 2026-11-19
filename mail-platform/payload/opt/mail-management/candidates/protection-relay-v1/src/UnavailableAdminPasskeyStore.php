<?php

declare(strict_types=1);

namespace MailServer\Management;

use Webauthn\CredentialRecord;

/** No silent bootstrap or in-memory fallback when production storage is absent. */
final class UnavailableAdminPasskeyStore implements AdminPasskeyStore
{
    public function snapshot(AdminUser $user): array { throw new \DomainException('passkey_storage_unavailable'); }
    public function ownerOfCredential(string $credentialId, string $userHandle): ?string
    { throw new \DomainException('passkey_storage_unavailable'); }
    public function register(AdminUser $user, CredentialRecord $record, string $label, bool $first): void
    { throw new \DomainException('passkey_storage_unavailable'); }
    public function authenticate(AdminUser $user, string $response, string $options, AdminWebauthn $validator): void
    { throw new \DomainException('passkey_storage_unavailable'); }
}
