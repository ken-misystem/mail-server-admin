<?php

declare(strict_types=1);

// Development uses ignored vendor.tmp; reviewed deployment would supply normal vendor.
$autoload = __DIR__ . '/dependency/vendor/autoload.php';
if (!is_file($autoload)) { $autoload = __DIR__ . '/dependency/vendor.tmp/autoload.php'; }
if (!is_file($autoload)) { throw new RuntimeException('locked_dependencies_missing'); }
require_once $autoload;
spl_autoload_register(static function (string $class): void {
    $prefix = 'MailServer\\Management\\';
    if (!str_starts_with($class, $prefix)) { return; }
    $name = substr($class, strlen($prefix));
    if (!preg_match('/^[A-Za-z][A-Za-z0-9]*$/D', $name)) { return; }
    $path = __DIR__ . '/src/' . $name . '.php';
    if (is_file($path)) { require_once $path; }
});
