<?php

declare(strict_types=1);

// Packaging/delegation only. No options, ceremony, private config, PDO, session or network.
try {
    $release = dirname(__DIR__);
    if (!is_dir($release . '/shared-passkey-core')) { throw new RuntimeException(); }
    require $release . '/bootstrap.php';
    $adapter = new \MailServer\Management\AdminWebauthn();
    $pins = \MailServer\Management\SharedPasskeyCore::PINS;
    if (count($pins) !== 9) { throw new RuntimeException(); }
    foreach ($pins as $file => $hash) {
        $path = $release . '/shared-passkey-core/' . $file;
        $class = 'MailServer\\RoundcubeAuth\\' . basename($file, '.php');
        if (!hash_equals($hash, hash_file('sha256', $path))
            || (!class_exists($class) && !interface_exists($class))
            || realpath((new ReflectionClass($class))->getFileName()) !== realpath($path)) {
            throw new RuntimeException();
        }
    }
    foreach (['registration' => \MailServer\RoundcubeAuth\WebauthnLibRegistrationValidator::class,
        'assertion' => \MailServer\RoundcubeAuth\WebauthnLibAssertionValidator::class] as $property => $class) {
        if (!(new ReflectionProperty($adapter, $property))->getValue($adapter) instanceof $class) {
            throw new RuntimeException();
        }
    }
    echo "SHARED CORE PACKAGE: PASS (exact9 sources, packaged imports, existing delegates)\n";
    echo "CEREMONY/OPTIONS/CONFIG/DB/SESSION/NETWORK: NOT_RUN\n";
} catch (Throwable) {
    fwrite(STDERR, "SHARED CORE PACKAGE: FAIL (no raw error output)\n");
    exit(1);
}
