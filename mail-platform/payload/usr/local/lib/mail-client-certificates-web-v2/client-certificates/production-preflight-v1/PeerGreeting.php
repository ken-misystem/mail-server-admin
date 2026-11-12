<?php
declare(strict_types=1);
namespace MailServer\CertificatePeerCandidate;

/** Uninstalled Linux SCM_CREDENTIALS handshake. No shell/helper/FFI/secret read. */
final class PeerFailure extends \RuntimeException {}
function check(bool $ok, string $reason): void { if (!$ok) throw new PeerFailure($reason); }

final class PeerGreeting
{
    /** Input MUST be obtained by receive(), never from HTTP/application JSON. */
    public static function classify(array $message, int $uid, int $gid, int $pid = 0): array
    {
        check($uid > 0 && $gid > 0 && $pid >= 0, 'peer_expected_identity');
        check(isset($message['flags']) && is_int($message['flags']) && $message['flags'] === 0,
            'peer_ancillary_flags');
        check(($message['iov'] ?? null) === ['P'], 'peer_greeting_marker');
        $control = $message['control'] ?? null;
        check(is_array($control) && array_is_list($control) && count($control) === 1,
            'peer_ancillary_inventory');
        $item = $control[0];
        check(is_array($item) && array_keys($item) === ['level','type','data']
            && $item['level'] === SOL_SOCKET && $item['type'] === SCM_CREDENTIALS,
            'peer_ancillary_kind');
        $identity = $item['data'];
        check(is_array($identity) && array_keys($identity) === ['pid','uid','gid']
            && is_int($identity['pid']) && $identity['pid'] > 0
            && is_int($identity['uid']) && $identity['uid'] === $uid
            && is_int($identity['gid']) && $identity['gid'] === $gid
            && ($pid === 0 || $identity['pid'] === $pid), 'peer_identity_mismatch');
        return $identity;
    }

    /** Passcred MUST be enabled on the socket before connect. Reads one public byte. */
    public static function receive(\Socket $socket, int $uid, int $gid, int $pid = 0): array
    {
        check(PHP_OS_FAMILY === 'Linux' && defined('SO_PASSCRED') && defined('SCM_CREDENTIALS'),
            'peer_linux_api_required');
        check(socket_get_option($socket, SOL_SOCKET, SO_TYPE) === SOCK_STREAM
            && socket_get_option($socket, SOL_SOCKET, SO_PASSCRED) === 1, 'peer_socket_profile');
        // Oversized ancillary frames and unexpected SCM_RIGHTS are refused.
        $message = ['buffer_size'=>1, 'controllen'=>socket_cmsg_space(SOL_SOCKET, SCM_CREDENTIALS)];
        try {
            $count = socket_recvmsg($socket, $message, 0);
            check($count === 1 && is_array($message), 'peer_greeting_receive');
            $peer = self::classify($message, $uid, $gid, $pid);
            check(socket_set_option($socket, SOL_SOCKET, SO_PASSCRED, 0), 'peer_passcred_disable');
            return $peer;
        } finally {
            if (is_array($message)) self::closeUnexpectedResources($message);
        }
    }

    private static function closeUnexpectedResources(mixed $value): void
    {
        if (is_array($value)) { foreach ($value as $part) self::closeUnexpectedResources($part); }
        elseif (is_resource($value)) fclose($value);
        elseif ($value instanceof \Socket) socket_close($value);
    }
}

/** Trusted startup supplies a fixed pathname and independently checked parent guard. */
final class GreetingConnection
{
    private bool $closed = false;
    private function __construct(private \Socket $socket, private mixed $stream,
        private array $peer, private \Closure $parentGuard, private float $deadline) {}

    public static function open(string $path, int $uid, int $gid, \Closure $parentGuard): self
    {
        check(PHP_OS_FAMILY === 'Linux' && $uid > 0 && $gid > 0
            && str_starts_with($path,'/') && strlen($path) <= 107
            && !str_contains($path,"\0") && !preg_match('~(?:^|/)(?:\.|\.\.)(?:/|$)|//|\s~',$path),
            'peer_endpoint_profile');
        $parentGuard(); // Dedicated trusted parent/socket manifest, not browser-controlled.
        $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
        check($socket instanceof \Socket, 'peer_socket_create');
        try {
            check(socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,['sec'=>2,'usec'=>0])
                && socket_set_option($socket,SOL_SOCKET,SO_SNDTIMEO,['sec'=>2,'usec'=>0])
                && socket_set_option($socket,SOL_SOCKET,SO_PASSCRED,1), 'peer_socket_options');
            check(socket_connect($socket,$path), 'peer_connect');
            $peer = PeerGreeting::receive($socket,$uid,$gid);
            $parentGuard();
            $stream = socket_export_stream($socket);
            check(is_resource($stream), 'peer_export_stream');
            return new self($socket,$stream,$peer,$parentGuard,hrtime(true)/1e9+15);
        } catch (\Throwable $error) { socket_close($socket); throw $error; }
    }

    public function stream(): mixed { $this->requirePeer($this->stream); return $this->stream; }
    public function requirePeer(mixed $stream): void
    {
        check(!$this->closed && $stream === $this->stream && is_resource($stream)
            && hrtime(true)/1e9 < $this->deadline, 'peer_connection_lifetime');
        ($this->parentGuard)();
        // Same held connected socket; never replace it or infer identity from HTTP.
        check($this->peer['pid'] > 0 && $this->peer['uid'] > 0 && $this->peer['gid'] > 0,
            'peer_connection_identity');
    }
    public function close(): void
    {
        if (!$this->closed) { $this->closed=true; if (is_resource($this->stream)) fclose($this->stream); }
    }
}
