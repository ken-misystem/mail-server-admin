<?php

declare(strict_types=1);

namespace MailServer\Management;

use Webauthn\CredentialRecord;

interface AdminPasskeyStore
{
    /** handle=binary stable user handle; records=enabled CredentialRecords; has_any includes disabled. */
    public function snapshot(AdminUser $user): array;
    public function register(AdminUser $user, CredentialRecord $record, string $label, bool $first): void;
    /** Validate against the locked current record, then update it before granting factor evidence. */
    public function authenticate(AdminUser $user, string $response, string $options, AdminWebauthn $validator): void;
}
