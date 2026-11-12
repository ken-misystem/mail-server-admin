<?php
declare(strict_types=1);
namespace MailServer\CertificateWebCandidate;
require_once __DIR__ . '/RoundcubeBridge.php';

use MailServer\ClientCertificatesCandidate\DownloadStream;

interface DownloadLease
{
    public function length(): int;
    public function requireActive(): void;
    public function read(int $maximum, float $deadline): string;
    /** Broker completion acknowledgement, never client-save proof. */
    public function complete(): void;
    /** Idempotent cancellation/retirement, including after partial output. */
    public function retire(): void;
}
final class RetirementError extends BoundaryError
{
    public function __construct(public readonly ?\Throwable $primary, public readonly \Throwable $cleanup)
    { parent::__construct('p12_retirement_unverified', 0, $primary ?? $cleanup); }
}
interface HttpSink
{
    public function ready(): void;
    public function headers(int $status, array $headers): void;
    public function connected(): bool;
    public function write(string $bytes): int;
}
final class NativeHttpSink implements HttpSink
{
    public function ready(): void
    {
        guard(!headers_sent() && ob_get_level() === 0 && !ini_get('zlib.output_compression'), 'http_output_not_clean');
    }
    public function headers(int $status, array $headers): void
    {
        $this->ready();
        // Continue long enough to execute finally/retire when client disconnects.
        // A separate broker deadline is still mandatory for process death.
        ignore_user_abort(true);
        http_response_code($status);
        foreach ($headers as $key => $value) header($key . ': ' . $value, true);
    }
    public function connected(): bool { return connection_aborted() === 0; }
    public function write(string $bytes): int { echo $bytes; flush(); return strlen($bytes); }
}

final class P12Stream implements DownloadStream
{
    private bool $used = false;
    private bool $retired = false;
    public readonly int $bytes;
    public function __construct(private DownloadLease $lease, private HttpSink $sink, private \Closure $clock)
    {
        try {
            $this->bytes = $lease->length();
            guard($this->bytes > 0 && $this->bytes <= 131072, 'p12_size_bound');
        } catch (\Throwable $error) {
            try { $this->abort(); } catch (\Throwable $cleanup) { throw new RetirementError($error, $cleanup); }
            throw $error;
        }
    }
    public function emit(): void
    {
        guard(!$this->used && !$this->retired, 'p12_already_consumed');
        $this->used = true; $deadline = ($this->clock)() + 15.0;
        $primary = null;
        try {
            $remaining = $this->bytes;
            while ($remaining > 0) {
                guard(($this->clock)() < $deadline && $this->sink->connected(), 'p12_deadline_or_disconnect');
                $this->lease->requireActive();
                $chunk = $this->lease->read(min(8192, $remaining), $deadline);
                guard(strlen($chunk) > 0 && strlen($chunk) <= min(8192, $remaining), 'p12_eof_or_overrun');
                $offset = 0;
                while ($offset < strlen($chunk)) {
                    guard(($this->clock)() < $deadline && $this->sink->connected(), 'p12_deadline_or_disconnect');
                    $this->lease->requireActive();
                    $written = $this->sink->write(substr($chunk, $offset));
                    guard($written > 0 && $written <= strlen($chunk) - $offset, 'p12_write_unverified');
                    $offset += $written;
                }
                $remaining -= strlen($chunk);
                unset($chunk);
            }
            guard(($this->clock)() < $deadline && $this->sink->connected(), 'p12_deadline_or_disconnect');
            $this->lease->requireActive();
            $this->lease->complete();
        } catch (\Throwable $error) { $primary = $error; throw $error; }
        finally {
            try { $this->abort(); } catch (\Throwable $cleanup) { throw new RetirementError($primary, $cleanup); }
        }
    }
    public function abort(): void
    {
        if (!$this->retired) {
            $this->retired = true; // Failure is uncertain; NEVER retry retirement/stream automatically.
            $this->lease->retire();
        }
    }
}

/** Emits only the fixed controller contract. Never append JSON after partial P12. */
final class ResponseEmitter
{
    public function __construct(private HttpSink $sink, private FailureAudit $audit) {}
    public function send(array $response): bool
    {
        $stream = $response['stream'] ?? null;
        $ok = false;
        try {
            $this->sink->ready();
            $status = $response['status'] ?? null;
            guard(is_int($status) && in_array($status, [200,202,400,503], true), 'response_status');
            // Ignore response-controlled header names/values. All headers here are constants.
            $headers = ['Cache-Control'=>'no-store, private','Pragma'=>'no-cache',
                'X-Content-Type-Options'=>'nosniff','Referrer-Policy'=>'no-referrer'];
            if ($stream !== null) {
                guard($stream instanceof P12Stream && $status === 200 && !isset($response['body']), 'response_stream');
                $headers += ['Content-Type'=>'application/x-pkcs12',
                    'Content-Disposition'=>'attachment; filename="mail-device.p12"',
                    'Content-Length'=>(string) $stream->bytes,'Accept-Ranges'=>'none','X-Accel-Buffering'=>'no'];
                $this->sink->headers($status, $headers);
                $stream->emit();
            } else {
                guard(is_array($response['body'] ?? null), 'response_body');
                $json = json_encode($response['body'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                guard(strlen($json) <= 65536, 'response_bound');
                $this->sink->headers($status, $headers + ['Content-Type'=>'application/json; charset=utf-8']);
                guard($this->sink->write($json) === strlen($json), 'response_write_unverified');
            }
            $ok = true;
        } catch (\Throwable $error) {
            $this->audit->record($error, 'response');
            // No error body after output has started.
        } finally {
            if ($stream instanceof DownloadStream) {
                try { $stream->abort(); }
                catch (\Throwable $cleanup) { $ok = false; $this->audit->record($cleanup, 'retire'); }
            }
        }
        return $ok;
    }
}
