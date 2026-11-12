<?php

declare(strict_types=1);

// Future dedicated FPM entry; LOCAL CANDIDATE ONLY. Not installed or publicly routed.
ini_set('display_errors', '0');
ini_set('log_errors', '0'); // Never emit raw config/PDO/framework exception details.
$bufferLevel = ob_get_level();
ob_start();
try {
    if (!in_array($_SERVER['HTTP_HOST'] ?? '', ['mx.mi-sys.jp', 'mx.mi-sys.jp:443'], true)
        || ($_SERVER['HTTPS'] ?? '') !== 'on' || ($_SERVER['SCRIPT_NAME'] ?? '') !== '/index.php'
        || ($_SERVER['PHP_SELF'] ?? '') !== '/index.php'
        || !preg_match('~^/mail-admin(?:/|\?|$)~D', $_SERVER['REQUEST_URI'] ?? '')) {
        throw new RuntimeException('request_boundary');
    }
    require '/opt/mail-management/candidates/protection-relay-v1/bootstrap.php';
    $config = require '/etc/mail-management/admin.php';
    if (!is_array($config) || ($config['db_user'] ?? null) !== 'mail_management_app'
        || ($config['state_directory'] ?? null) !== '/var/lib/mail-management'
        || ($config['rp_id'] ?? null) !== 'mx.mi-sys.jp' || ($config['origin'] ?? null) !== 'https://mx.mi-sys.jp'
        || !is_string($config['dsn'] ?? null)
        || !preg_match('~^mysql:unix_socket=/[A-Za-z0-9/._-]+;dbname=mail_management;charset=utf8mb4$~D', $config['dsn'])
        || !is_string($config['db_password'] ?? null) || !is_string($config['application_secret'] ?? null)) {
        throw new RuntimeException('runtime_boundary');
    }
    $db = new PDO($config['dsn'], $config['db_user'], $config['db_password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    $kernel = new \MailServer\Management\ConsoleKernel(
        new \MailServer\Management\PdoAdminDirectory($db), $config['application_secret'], '/var/lib/mail-management/operations-status-v1', false,
        new \MailServer\Management\PdoAdminPasskeyStore($db, new \MailServer\Management\AdminWebauthn()),
        new \MailServer\Management\PdoAdminSettingsStore($db),
        new \MailServer\Management\PdoAdminOperationsStore($db),
        audit: new \MailServer\Management\PdoAdminAuditStore($db),
 legacySmtp: new \MailServer\Management\PdoLegacySmtpStore($db),
 domainDelivery: new \MailServer\Management\PdoDomainDeliveryStore($db),
 cutover: new \MailServer\Management\PdoCutoverStore($db, $featurePortQuotaUsage = (new \MailServer\Management\FileQuotaUsageProvider("/var/lib/mail-quota-v1/snapshot.json", "48d2e4f42baa7470a5db0a0c4bcd7a0857ad8b9afbc958be6b8b6cc6833b0f4d")
)),
 sendLimits: new \MailServer\Management\PdoSendLimitStore($db),
 queueAdmin: new \MailServer\Management\UnixQueueAdminStore(),
 ownerStatus: new \MailServer\Management\UnixOwnerStatusStore(),
 bulkMailbox: new \MailServer\Management\PdoBulkMailboxStore($db),
 domainDelegation: new \MailServer\Management\PdoDomainDelegationStore($db),
 scopedRead: new \MailServer\Management\PdoScopedAdminReadStore($db, $featurePortQuotaUsage)
,
 scopedWrites: new \MailServer\Management\PdoScopedWriteStore($db, $featurePortQuotaUsage)
,
 forwardStore: new \MailServer\Management\PdoForwardStore($db)
,
 featureSettings: new \MailServer\Management\PdoManagedSettingsStore($db),
 featureObservations: new \MailServer\Management\FileFeatureObservations()
);
    $request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
    if ($request->getBaseUrl() !== '' || $request->getSchemeAndHttpHost() !== 'https://mx.mi-sys.jp') {
        throw new RuntimeException('routing_boundary');
    }
    $response = $kernel->handle($request);
    while (ob_get_level() > $bufferLevel) { ob_end_clean(); }
    $response->send();
    $kernel->terminate($request, $response);
} catch (Throwable) {
    while (ob_get_level() > $bufferLevel) { ob_end_clean(); }
    if (!headers_sent()) {
        http_response_code(503);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        echo 'Management service is unavailable.';
    }
}
