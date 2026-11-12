<?php

declare(strict_types=1);

/**
 * Keep Roundcube's logical IMAP host stable while routing the socket locally.
 *
 * Roundcube uses the host supplied to rcmail::login() as part of the stable
 * users(username, mail_host) identity before it runs storage_connect. This
 * hook changes only the physical connection parameters at the final boundary.
 */
class local_imap_loopback extends rcube_plugin
{
    public $task = '.*';

    private const LOGICAL_HOST = 'mx.mi-sys.jp';
    private const LOGICAL_PORT = 993;
    private const LOGICAL_SSL_MODE = 'ssl';
    private const LOOPBACK_HOST = '127.0.0.1';
    private const LOOPBACK_PORT = 143;

    public function init(): void
    {
        $this->add_hook('storage_connect', [$this, 'routeConnection']);
    }

    /** @param array<string, mixed> $args
     *  @return array<string, mixed>
     */
    public function routeConnection(array $args): array
    {
        if (!$this->isExpectedLogicalConnection($args)) {
            // A configuration or call-shape drift must not fall back to the
            // public App-Password-capable listener. Port 1 is intentionally
            // closed, and implicit TLS is required before any IMAP exchange.
            $args['host'] = self::LOOPBACK_HOST;
            $args['port'] = 1;
            $args['ssl_mode'] = 'ssl';
            $args['socket_options'] = self::tlsOptions();
            $args['retry'] = false;
            return $args;
        }

        $args['host'] = self::LOOPBACK_HOST;
        $args['port'] = self::LOOPBACK_PORT;
        $args['ssl_mode'] = 'tls';
        $args['socket_options'] = self::tlsOptions();
        $args['retry'] = false;

        return $args;
    }

    /** @return array{ssl: array<string, bool|string>} */
    private static function tlsOptions(): array
    {
        return [
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'peer_name' => self::LOGICAL_HOST,
            ],
        ];
    }

    /** @param array<string, mixed> $args */
    private function isExpectedLogicalConnection(array $args): bool
    {
        return ($args['host'] ?? null) === self::LOGICAL_HOST
            && ($args['port'] ?? null) === self::LOGICAL_PORT
            && ($args['ssl_mode'] ?? null) === self::LOGICAL_SSL_MODE
            && ($args['attempt'] ?? null) === 1;
    }
}
