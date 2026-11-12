<?php
declare(strict_types=1);
namespace MailServer\ClientCertificatesCandidate;

/** Uninstalled controller seam. No rcube boot, socket, DB, signing or live route. */
interface OwnerBridge
{
    /** Validates current RC session/host, unique active mail owner/domain/epoch.
     * POST+CSRF are checked before any body, broker or assertion is processed. */
    public function authenticatedContext(): object;
    public function requirePostCsrf(): void;
    /** Fixed operation only. Broker rechecks context, proof and owner; never trust body owner IDs. */
    public function call(string $operation, object $context, array $input): array;
    /** Consumes single-owner/session download before any output; private fixed broker only.
     * Must prohibit Range, enforce size/time limits, cancel on revoke and retire on all outcomes. */
    public function claimDownload(object $context, array $input): DownloadStream;
    /** Fixed safe fields: phase/code/source hash/line/class/errno. No raw message. */
    public function recordFailure(\Throwable $error, string $operation): void;
}

interface DownloadStream
{
    /** Route sets headers first, emits once, aborts/retires in finally (even on disconnect). */
    public function emit(): void;
    public function abort(): void;
}

final class OwnerController
{
    private const INPUTS = [
        'list' => ['cursor'],
        'issue_options' => ['label', 'request_id'],
        'issue_finish' => ['action_id', 'assertion', 'p12_password'],
        'revoke_options' => ['device_id', 'request_id'],
        'revoke_finish' => ['action_id', 'assertion'],
        'download' => ['device_id', 'download_handle'],
        'verification_status' => [],
        'verification_options' => [],
        'verification_finish' => ['action_id', 'assertion'],
        'verification_authorize' => ['purpose', 'target'],
        'verification_consume' => ['purpose', 'target', 'authorization_id'],
        'verification_invalidate' => [],
    ];
    public const HEADERS = [
        'Cache-Control' => 'no-store, private', 'Pragma' => 'no-cache',
        'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'no-referrer',
    ];

    public function __construct(private OwnerBridge $bridge) {}

    /** Returns structured response for a later reviewed Roundcube route adapter. */
    public function dispatch(string $operation, string $json, bool $rangePresent = false): array
    {
        $context = null;
        try {
            $this->bridge->requirePostCsrf();
            $context = $this->bridge->authenticatedContext();
            if (!array_key_exists($operation, self::INPUTS) || strlen($json) > 65536 || $rangePresent) {
                return $this->error('input_invalid', 400);
            }
            $body = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($body) || (array_is_list($body) && $body !== [])
                || array_diff(array_keys($body), self::INPUTS[$operation]) !== []) {
                return $this->error('input_invalid', 400);
            }
            if ($operation === 'download') {
                // The actual route must commit status/headers ONLY after stream claim.
                // Never buffer or JSON-encode P12 in call(), audit or exception details.
                $stream = $this->bridge->claimDownload($context, $body);
                return ['status' => 200, 'headers' => self::HEADERS + [
                    'Content-Type' => 'application/x-pkcs12',
                    'Content-Disposition' => 'attachment; filename="mail-device.p12"',
                ], 'stream' => $stream, 'client_save_verified' => false];
            }
            $result = $this->bridge->call($operation, $context, $body);
            return ['status' => ($result['state'] ?? null) === 'revoke_pending' ? 202 : 200,
                'headers' => self::HEADERS, 'body' => $this->publicResult($result)];
        } catch (\Throwable $error) {
            // A separate trusted audit adapter must capture code + source hash/line,
            // never raw message, arguments, assertion, context or secret body.
            $this->bridge->recordFailure($error, array_key_exists($operation, self::INPUTS) ? $operation : 'invalid_operation');
            return $this->error('operation_unverified', 503);
        } finally {
            unset($json, $body, $context);
        }
    }

    private function publicResult(array $result): array
    {
        $allowed = ['items','next','device_id','label','state','created_at','expires_at',
            'revocation_pending_components','detail','download_handle','download_expires_at',
            'action_id','publicKey','authentication_required','remaining_seconds','authorization_id','authorized','invalidated'];
        if (array_diff(array_keys($result), $allowed) !== []) throw new \RuntimeException('response_contract');
        if (isset($result['items'])) {
            if (!is_array($result['items']) || count($result['items']) > 10) throw new \RuntimeException('response_contract');
            foreach ($result['items'] as $row) {
                if (!is_array($row) || array_diff(array_keys($row),
                    ['device_id','label','state','created_at','expires_at','revocation_pending_components']) !== []) {
                    throw new \RuntimeException('response_contract');
                }
            }
        }
        return $result;
    }

    private function error(string $code, int $status): array
    {
        return ['status' => $status, 'headers' => self::HEADERS,
            'body' => ['ok' => false, 'error_code' => $code]];
    }
}
