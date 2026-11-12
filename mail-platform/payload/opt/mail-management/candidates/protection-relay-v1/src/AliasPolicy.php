<?php

declare(strict_types=1);

namespace MailServer\Management;

/** Local policy prototype. The caller must obtain identity/counts in a DB transaction. */
final class AliasPolicy
{
    public const MAX_ADDRESS_BYTES = 254;
    private const RESERVED = [
        'admin', 'postmaster', 'abuse', 'hostmaster', 'root', 'mailer-daemon',
        'spam-report',
    ];

    /** Domain comes from the authenticated account's active canonical domain. */
    public static function newAddress(
        string $localPart,
        string $accountDomain,
        int $limit,
        int $ownedCount,
        bool $namespaceAvailable,
    ): string {
        if ($limit < 0 || $ownedCount < 0) {
            throw new \DomainException('invalid_policy');
        }
        if ($limit === 0 || $ownedCount >= $limit) {
            throw new \DomainException('alias_limit');
        }
        $localPart = self::registrationLocal($localPart);
        if (self::isReserved($localPart) || !$namespaceAvailable) {
            throw new \DomainException('alias_unavailable');
        }
        $domain = strtolower($accountDomain);
        if (strlen($domain) > 253 || !str_contains($domain, '.')) {
            throw new \DomainException('invalid_domain');
        }
        foreach (explode('.', $domain) as $label) {
            if (!preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D', $label)) {
                throw new \DomainException('invalid_domain');
            }
        }
        return self::registrationAddress($localPart, $domain);
    }

    /** Only new local registrations; never validate external senders or existing routes here. */
    public static function registrationAddress(string $localPart, string $domain): string
    {
        $address = $localPart . '@' . $domain;
        if (strlen($address) > self::MAX_ADDRESS_BYTES) {
            throw new \DomainException('invalid_alias');
        }
        return $address;
    }

    /** New receiving identities only; never use for login IDs or destinations. */
    public static function registrationLocal(string $localPart): string
    {
        if (!preg_match('/\A[a-z0-9][a-z0-9._-]{0,63}\z/iD', $localPart)
            || str_ends_with($localPart, '.') || str_contains($localPart, '..')) {
            throw new \DomainException('invalid_alias');
        }
        return str_replace('.', '', strtolower($localPart));
    }

    /** Fixed SQL identifiers only. Include disabled/legacy names in reservations. */
    public static function namespaceSql(string $column): string
    {
        if (!in_array($column, ['email', 'source'], true)) { throw new \LogicException('invalid_column'); }
        $base = "REPLACE(SUBSTRING_INDEX(SUBSTRING_INDEX($column,'@',1),'+',1),'.','')";
        return "CASE WHEN LOCATE('@',$column)=0 THEN $base ELSE CONCAT($base,'@',SUBSTRING_INDEX($column,'@',-1)) END";
    }

    public static function isReserved(string $localPart): bool
    {
        return in_array(str_replace('.', '', strtolower(explode('+', $localPart, 2)[0])), self::RESERVED, true);
    }

    public static function requireOwner(int|string $authenticatedAccountId, int|string $ownerId): void
    {
        $actor = (string) $authenticatedAccountId;
        if (!preg_match('/\A[1-9][0-9]{0,19}\z/D', $actor) || (string) $ownerId !== $actor) {
            throw new \DomainException('not_authorized');
        }
    }
}
