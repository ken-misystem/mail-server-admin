<?php
declare(strict_types=1);

use MailServer\Management as M;
use Symfony\Component\HttpFoundation\Request;

try {
    require '/opt/mail-management/candidates/protection-relay-v1/bootstrap.php';
    $config = require '/etc/mail-management/admin.php';
    $database = new PDO($config['dsn'], $config['db_user'], $config['db_password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $usage = new M\FileQuotaUsageProvider();
    $kernel = new M\ConsoleKernel(
        directory: new M\PdoAdminDirectory($database),
        applicationSecret: $config['application_secret'],
        stateDirectory: $config['state_directory'],
        passkeys: new M\PdoAdminPasskeyStore($database, new M\AdminWebauthn()),
        settings: new M\PdoAdminSettingsStore($database),
        operations: new M\PdoAdminOperationsStore($database),
        audit: new M\PdoAdminAuditStore($database),
        legacySmtp: new M\PdoLegacySmtpStore($database),
        cutover: new M\PdoCutoverStore($database, $usage),
        domainDelivery: new M\PdoDomainDeliveryStore($database),
        accessBlacklist: new M\UnixAccessBlacklistStore(),
        sendLimits: new M\PdoSendLimitStore($database),
        queueAdmin: new M\UnixQueueAdminStore(),
        ownerStatus: new M\UnixOwnerStatusStore(),
        bulkMailbox: new M\PdoBulkMailboxStore($database),
        domainDelegation: new M\PdoDomainDelegationStore($database),
        scopedRead: new M\PdoScopedAdminReadStore($database, $usage),
        scopedWrites: new M\PdoScopedWriteStore($database, $usage),
        forwardStore: new M\PdoForwardStore($database),
        featureSettings: new M\PdoManagedSettingsStore($database),
        featureObservations: new M\FileFeatureObservations(),
        protectionStore: new M\UnixProtectionStore(new M\FeatureControlClient()),
    );
    $request = Request::createFromGlobals();
    $response = $kernel->handle($request);
    $response->send();
    $kernel->terminate($request, $response);
} catch (Throwable $error) {
    error_log('mail_management_bootstrap_failure ' . get_class($error));
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo '管理サービスを利用できません。';
}
