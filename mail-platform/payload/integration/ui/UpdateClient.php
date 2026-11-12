<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UpdateClient
{
    public function call(array $request): array
    {
        $socket = @stream_socket_client('unix:///run/mail-platform-update/ui.sock', $errno, $error, 2);
        if (!$socket) { throw new \RuntimeException('update_service_unavailable'); }
        try {
            stream_set_timeout($socket, 3);
            $raw = json_encode($request, JSON_THROW_ON_ERROR)."\n";
            if (strlen($raw)>4096 || fwrite($socket,$raw)!==strlen($raw)) { throw new \RuntimeException('update_write'); }
            $line = fgets($socket, 65537);
            if (!is_string($line) || !str_ends_with($line,"\n")) { throw new \RuntimeException('update_read'); }
            $reply = json_decode($line,true,16,JSON_THROW_ON_ERROR);
            if (!is_array($reply) || ($reply['status']??null)!=='ok') { throw new \RuntimeException('update_refused'); }
            return $reply;
        } finally { fclose($socket); }
    }
}
