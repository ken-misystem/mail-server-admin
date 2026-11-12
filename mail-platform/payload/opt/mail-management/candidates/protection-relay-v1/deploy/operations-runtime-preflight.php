<?php

declare(strict_types=1);

// Candidate source only: no private config, PDO construction, kernel/session boot or network.
require dirname(__DIR__) . '/bootstrap.php';
try {
    if (PHP_VERSION_ID < 80400 || !extension_loaded('pdo_mysql') || !in_array('argon2id', password_algos(), true)) {
        throw new RuntimeException();
    }
    foreach (['symfony/framework-bundle' => '7.4.20', 'symfony/security-bundle' => '7.4.20',
        'symfony/rate-limiter' => '7.4.8', 'symfony/lock' => '7.4.8', 'web-auth/webauthn-lib' => '5.3.8'] as $name => $version) {
        if (ltrim(\Composer\InstalledVersions::getPrettyVersion($name), 'v') !== $version) { throw new RuntimeException(); }
    }
    foreach (['AdminMailPolicy', 'AdminMutation', 'AdminOperationsController', 'AdminOperationsForms',
        'AdminPasswordEncoder', 'PdoAdminOperationsStore', 'UnavailableAdminOperationsStore',
        'AdminSettingsController', 'PdoAdminSettingsStore', 'ConsoleKernel'] as $name) {
        if (!class_exists('MailServer\\Management\\' . $name)) { throw new RuntimeException(); }
    }
    if (!interface_exists(\MailServer\Management\AdminOperationsStore::class)
        || count(\MailServer\Management\AdminMutation::ACTIONS) !== 13) { throw new RuntimeException(); }
    echo "OPERATIONS RUNTIME: PASS (fixed libraries/classes/Argon2id; DB/network/session/mutations NOT_RUN)\n";
} catch (Throwable) { fwrite(STDERR, "OPERATIONS RUNTIME: FAIL (no raw error/credential output)\n"); exit(1); }
