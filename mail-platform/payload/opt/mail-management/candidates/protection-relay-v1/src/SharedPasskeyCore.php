<?php

declare(strict_types=1);
namespace MailServer\Management;

/** Existing unchanged Roundcube validation core; packaged sources must match these pins. */
final class SharedPasskeyCore
{
    public const PINS = [
        'RegistrationConfig.php' => 'fd89a2d47c16c68ac1718d008429d1fb957ec10c654aade4bc3d1de0a9da01dc',
        'RegistrationException.php' => '1d5e509eed96cd212cfad795bbce137721246c13a5952966851607e7f831a7aa',
        'RegistrationValidator.php' => 'ea1dd6b13dd9be36de1824161dc25ea8b5fb8906ee16602b083fd0efe08f100a',
        'AssertionValidator.php' => 'de08d187386be062a0ba272d6d03ab62cd2d3ce3f96c59d2210fbe74cc7d7233',
        'StoredCredential.php' => '65d1fb5bd4221836db15632cc8b3d6a43da6e65e62303deb94dc3b44c2a9e825',
        'ValidatedCredential.php' => 'bf6a1d05590daa772fa75b9687d1309ceafc2d4fd611eaa02e9db1679617b131',
        'ValidatedAssertion.php' => 'e25cbd711a123ae051f71aa23464aa3f9d3b516cbc85fc9736a221940ffc4cac',
        'WebauthnLibRegistrationValidator.php' => 'f994f75e8af5b4689dc5024b5ee6f2c79409fb0b890d26b9f5a6869d308ff8e7',
        'WebauthnLibAssertionValidator.php' => '7368e33f0fe3821c093219acafba0eade4e52c5c30eeab27db104c7b41ea4b18',
    ];
    private static bool $registered = false;

    public static function register(): void
    {
        if (self::$registered) { return; }
        $root = dirname(__DIR__) . '/shared-passkey-core';
        if (!is_dir($root)) {
            // Development fallback only; Web deployments must package the exact core.
            if (PHP_SAPI !== 'cli' || !is_file(dirname(__DIR__, 2) . '/AGENTS.md')) {
                throw new \RuntimeException('shared_passkey_core_missing');
            }
            $root = dirname(__DIR__, 2) . '/roundcube-passkey/plugin/local_auth/src';
        }
        $root = realpath($root);
        if ($root === false) { throw new \RuntimeException('shared_passkey_core_missing'); }
        foreach (self::PINS as $file => $pin) {
            $path = realpath($root . '/' . $file);
            if ($path !== $root . DIRECTORY_SEPARATOR . $file || !is_file($path)) {
                throw new \RuntimeException('shared_passkey_core_path');
            }
            $canonical = str_replace("\r\n", "\n", file_get_contents($path));
            if (str_starts_with($canonical, "\xef\xbb\xbf") || str_contains($canonical, "\r")
                || preg_match('//u', $canonical) !== 1 || !hash_equals($pin, hash('sha256', $canonical))) {
                throw new \RuntimeException('shared_passkey_core_pin');
            }
            $class = 'MailServer\\RoundcubeAuth\\' . basename($file, '.php');
            if ((class_exists($class, false) || interface_exists($class, false))
                && realpath((new \ReflectionClass($class))->getFileName()) !== $path) {
                throw new \RuntimeException('shared_passkey_core_collision');
            }
        }
        spl_autoload_register(static function (string $class) use ($root): void {
            $prefix = 'MailServer\\RoundcubeAuth\\';
            if (!str_starts_with($class, $prefix)) { return; }
            $file = substr($class, strlen($prefix)) . '.php';
            if (isset(self::PINS[$file])) { require_once $root . '/' . $file; }
        });
        self::$registered = true;
    }
}
