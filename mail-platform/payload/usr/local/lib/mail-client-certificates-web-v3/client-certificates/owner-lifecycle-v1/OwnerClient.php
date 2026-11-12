<?php
declare(strict_types=1);
namespace MailServer\OwnerLifecycleV1;
require_once __DIR__.'/OwnerVerification.php';
require_once __DIR__.'/../production-apply-v1/PluginRuntime.php';

/** Reuses exact native peer/session/epoch/CSRF bridge; never starts a plugin. */
function ownerClient(\rcmail $rc): OwnerVerification
{
    $bridge = \MailServer\CertificateDeployment\ownerBridge($rc,
        \MailServer\CertificateDeployment\protectedWebConfiguration());
    $bridge->requirePostCsrf();
    $context = $bridge->authenticatedContext();
    return new OwnerVerification(static function(string $op, array $data) use ($bridge, $context): array {
        try { return $bridge->call($op, $context, $data); }
        catch (\Throwable $error) { $bridge->recordFailure($error, 'owner_verification'); throw $error; }
    });
}
