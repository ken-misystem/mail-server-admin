<?php
declare(strict_types=1);
namespace MailServer\CertificateSessionCandidate;
require_once __DIR__ . '/../wiring-v1/SessionAttestor.php';
require_once __DIR__ . '/../web-runtime-v1/P12Response.php';
use MailServer\CertificateWebCandidate\OwnerChannel;
use MailServer\CertificateWebCandidate\DownloadLease;
use MailServer\CertificateWebCandidate\P12Stream;
use MailServer\CertificateWebCandidate\HttpSink;
use MailServer\ClientCertificatesCandidate\DownloadStream;
use MailServer\CertificateWiringCandidate\SessionAttestor;
use function MailServer\CertificateWebCandidate\guard;

interface AuthenticatedWire
{
    /** Independent kernel peer/socket-parent/runtime verification, throws on unknown. */
    public function requirePeer(): void;
    public function send(array $value): void;
    public function receive(): array;
    public function close(): void;
}
interface OwnerWireFactory { public function open(): AuthenticatedWire; }
interface DownloadClaim
{
    /** Transfers this authenticated connection only on success. No JSON P12 bytes. */
    public function claim(AuthenticatedWire $wire, object $context, array $input): DownloadLease;
}

final class AttestedOwnerChannel implements OwnerChannel
{
    // Deferred binding breaks bridge->channel->attestor->bridge constructor cycle.
    private ?SessionAttestor $attestor = null;
    public function __construct(private OwnerWireFactory $factory, private DownloadClaim $downloads,
        private HttpSink $sink, private \Closure $clock) {}
    public function bind(SessionAttestor $attestor): void
    { guard($this->attestor === null, 'owner_channel_already_bound'); $this->attestor = $attestor; }
    private function authenticate(AuthenticatedWire $wire, string $operation, object $context, array $input): void
    {
        guard($this->attestor !== null, 'owner_channel_unbound');
        $wire->requirePeer(); // BEFORE input containing password or attestation-key access.
        guard($input === [] || !array_is_list($input), 'owner_channel_input_object');
        $raw = json_encode((object)$input, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        guard(strlen($raw) > 0 && strlen($raw) <= 65536, 'owner_channel_input_bound');
        $wire->send(['operation'=>$operation, 'input'=>base64_encode($raw)]);
        $challenge = $wire->receive();
        $wire->requirePeer();
        $proof = $this->attestor->sign($challenge, $operation, $raw);
        $payload = base64_decode(strtr($proof['payload'], '-_', '+/'), true);
        guard(is_string($payload), 'owner_channel_proof_encoding');
        $signed = json_decode($payload, true, 16, JSON_THROW_ON_ERROR);
        guard(($signed['context'] ?? null) === (array)$context, 'owner_channel_context_changed');
        $wire->send($proof);
    }
    public function call(string $operation, object $context, array $input): array
    {
        guard(in_array($operation, ['list','issue_options','issue_finish','revoke_options','revoke_finish','verification_status','verification_options','verification_finish','verification_authorize','verification_consume','verification_invalidate'], true)
            && $this->attestor !== null, 'owner_channel_operation');
        $wire = $this->factory->open();
        try {
            $this->authenticate($wire, $operation, $context, $input);
            $response = $wire->receive();
            guard(array_diff(array_keys($response), ['items','next','device_id','label','state','created_at',
                'expires_at','revocation_pending_components','detail','download_handle','download_expires_at',
                'action_id','publicKey','authentication_required','remaining_seconds','authorization_id','authorized','invalidated']) === [], 'owner_channel_response');
            return $response;
        } finally { $wire->close(); }
    }
    public function claim(object $context, array $input): DownloadStream
    {
        guard($this->attestor !== null && count($input) === 2
            && array_diff(array_keys($input), ['device_id','download_handle']) === [], 'owner_download_input');
        $wire = $this->factory->open(); $transferred = false;
        try {
            $this->authenticate($wire, 'download', $context, $input);
            $lease = $this->downloads->claim($wire, $context, $input);
            $transferred = true;
            return new P12Stream($lease, $this->sink, $this->clock);
        } finally { if (!$transferred) $wire->close(); }
    }
}

/** Already connected private stream; opener/peer policy is a required port. */
final class FramedStreamWire implements AuthenticatedWire
{
    private bool $closed = false;
    public function __construct(private mixed $stream, private \Closure $peer,
        private \Closure $clock, private float $deadline)
    {
        guard(is_resource($stream) && get_resource_type($stream) === 'stream', 'wire_stream_type');
        $now = ($this->clock)();
        guard(is_finite($this->deadline) && is_finite((float)$now)
            && $this->deadline > $now && $this->deadline <= $now + 15, 'wire_deadline_bound');
    }
    public function requirePeer(): void
    {
        guard(!$this->closed && ($this->clock)() < $this->deadline, 'wire_closed_or_deadline');
        ($this->peer)($this->stream); // Throws on failure; never trust a boolean allow flag.
    }
    private function exact(int $bytes): string
    {
        $raw = '';
        while (strlen($raw) < $bytes) {
            $this->requirePeer();
            guard(stream_set_timeout($this->stream, 1), 'wire_timeout_setting');
            $part = fread($this->stream, $bytes - strlen($raw));
            guard(is_string($part) && $part !== '', 'wire_eof_or_read_failure');
            $raw .= $part;
        }
        return $raw;
    }
    public function receive(): array
    {
        $size = unpack('Nsize', $this->exact(4))['size'];
        guard($size > 0 && $size <= 65536, 'wire_frame_bound');
        $raw = $this->exact($size);
        $value = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        guard(is_array($value) && !array_is_list($value), 'wire_response_object');
        // Require canonical semantic round-trip separately at each protocol field;
        // production server never emits duplicate JSON keys. Native wire remains gated.
        return $value;
    }
    public function send(array $value): void
    {
        $this->requirePeer();
        $raw = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        guard(strlen($raw) > 0 && strlen($raw) <= 131072, 'wire_frame_bound');
        $raw = pack('N', strlen($raw)) . $raw; $offset = 0;
        while ($offset < strlen($raw)) {
            $this->requirePeer();
            guard(stream_set_timeout($this->stream, 1), 'wire_timeout_setting');
            $sent = fwrite($this->stream, substr($raw, $offset));
            guard(is_int($sent) && $sent > 0, 'wire_write_failure');
            $offset += $sent;
        }
    }
    public function close(): void
    {
        if (!$this->closed) {
            $this->closed = true;
            guard(fclose($this->stream), 'wire_close_failure');
        }
    }
}

