<?php
declare(strict_types=1);
namespace MailServer\Management;

/** The frontend only talks to a fixed local socket; never invokes an OS command. */
final class FeatureControlClient
{
    public function __construct(private readonly string $path = '/run/mail-feature-admin-v1/control.sock') {}
    public function call(array $request): array
    {
        $socket = @stream_socket_client('unix://' . $this->path, $number, $message, 2);
        if ($socket === false) { throw new \RuntimeException('feature_service_unavailable'); }
        try {
            stream_set_timeout($socket, 15);
            $raw = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
            if (strlen($raw) > 32768) { throw new \DomainException('request_bound'); }
            for ($offset = 0; $offset < strlen($raw);) {
                $written = fwrite($socket, substr($raw, $offset));
                if ($written === false || $written === 0) { throw new \RuntimeException('feature_request_unknown'); }
                $offset += $written;
            }
            $line = fgets($socket, 2 * 1024 * 1024);
            if ($line === false || !str_ends_with($line, "\n") || strlen($line) >= 2 * 1024 * 1024 - 1 || stream_get_meta_data($socket)['timed_out']) {
                throw new \RuntimeException('feature_result_unknown');
            }
            $reply = json_decode($line, true, 32, JSON_THROW_ON_ERROR);
            if (($reply['status'] ?? null) !== 'ok' || !is_array($reply['data'] ?? null)) { throw new \RuntimeException('feature_operation_failed'); }
            return $reply['data'];
        } finally { fclose($socket); }
    }
}
