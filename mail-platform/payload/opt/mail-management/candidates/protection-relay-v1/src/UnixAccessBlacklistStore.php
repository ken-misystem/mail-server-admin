<?php
declare(strict_types=1);
namespace MailServer\Management;

final class UnixAccessBlacklistStore implements AccessBlacklistStore
{
    public function __construct(private readonly string $socketPath = '/run/mail-access-admin-v1/control.sock') {}
    public function overview(): array { return $this->call(['operation' => 'overview']); }
    public function release(array $request): array { return $this->call($request); }

    private function call(array $request): array
    {
        $socket = @stream_socket_client('unix://' . $this->socketPath, $errno, $error, 2);
        if ($socket === false) { throw new \RuntimeException('access_monitor_unavailable'); }
        try {
            stream_set_timeout($socket, 12);
            $wire = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
            $offset = 0;
            while ($offset < strlen($wire)) {
                $written = fwrite($socket, substr($wire, $offset));
                if ($written === false || $written === 0) { throw new \RuntimeException('access_request_unknown'); }
                $offset += $written;
            }
            $response = stream_get_line($socket, 4 * 1024 * 1024, "\n");
            $metadata = stream_get_meta_data($socket);
            if ($response === false || $metadata['timed_out'] || strlen($response) >= 4 * 1024 * 1024 - 1) {
                throw new \RuntimeException('access_result_unknown');
            }
            $value = json_decode($response, true, 32, JSON_THROW_ON_ERROR);
            if (($value['status'] ?? null) !== 'ok' || !is_array($value['data'] ?? null)) {
                throw new \RuntimeException('access_operation_failed');
            }
            return $value['data'];
        } finally { fclose($socket); }
    }
}
