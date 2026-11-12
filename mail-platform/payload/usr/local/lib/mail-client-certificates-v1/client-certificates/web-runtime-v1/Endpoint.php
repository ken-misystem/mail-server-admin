<?php
declare(strict_types=1);
namespace MailServer\CertificateWebCandidate;
require_once __DIR__ . '/P12Response.php';
use MailServer\ClientCertificatesCandidate\OwnerController;

/** Registered only by a later reviewed plugin bootstrap. No init/route on include. */
final class Endpoint
{
    public function __construct(private RoundcubeBridge $bridge, private ResponseEmitter $emitter) {}
    public function serve(string $operation, \Closure $readBody): bool
    {
        try {
            // Deliberately gate BEFORE invoking the body-reader callback.
            $this->bridge->requirePostCsrf();
            $this->bridge->authenticatedContext();
            $body = $readBody(65537);
            guard(is_string($body) && strlen($body) <= 65536, 'request_body_bound');
            $response = (new OwnerController($this->bridge))->dispatch($operation, $body);
        } catch (\Throwable $error) {
            $this->bridge->recordFailure($error, 'endpoint');
            $response = ['status'=>503, 'body'=>['ok'=>false,'error_code'=>'operation_unverified']];
        }
        return $this->emitter->send($response);
    }
    public static function readNativeBody(int $maximum): string
    {
        guard($maximum === 65537, 'request_body_bound');
        $handle = fopen('php://input', 'rb');
        guard(is_resource($handle), 'request_body_unavailable');
        try {
            $body = stream_get_contents($handle, $maximum);
            guard(is_string($body), 'request_body_unavailable');
            return $body;
        } finally { fclose($handle); }
    }
}
