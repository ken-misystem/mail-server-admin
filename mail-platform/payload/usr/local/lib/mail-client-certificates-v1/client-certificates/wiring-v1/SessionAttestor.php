<?php
declare(strict_types=1);
namespace MailServer\CertificateWiringCandidate;
require_once __DIR__ . '/../web-runtime-v1/RoundcubeBridge.php';
use MailServer\CertificateWebCandidate\RoundcubeBridge;
use function MailServer\CertificateWebCandidate\guard;

/** Internal only. Challenge comes from a peer-verified private channel, never HTTP. */
final class SessionAttestor
{
    public function __construct(private RoundcubeBridge $bridge, private \Closure $privateKey,
        private \Closure $requireProtectedRuntime) {}
    public function sign(array $challenge, string $operation, string $rawInput): array
    {
        ($this->requireProtectedRuntime)();
        guard(array_keys($challenge) === ['nonce','peer','operation','input_sha256']
            && is_string($challenge['nonce']) && preg_match('/\A[0-9a-f]{64}\z/D',$challenge['nonce'])===1
            && is_array($challenge['peer']) && count($challenge['peer'])===3
            && array_is_list($challenge['peer']) && count(array_filter($challenge['peer'],fn($x)=>is_int($x)&&$x>0))===3
            && $challenge['peer'][0]===getmypid()
            && in_array($operation,['list','issue_options','issue_finish','revoke_options','revoke_finish','download'],true)
            && $challenge['operation']===$operation && strlen($rawInput)<=65536
            && hash_equals(hash('sha256',$rawInput),$challenge['input_sha256']), 'attestation_binding');
        $this->bridge->requirePostCsrf();
        $context=$this->bridge->authenticatedContext();
        $payload=json_encode(['version'=>1,'nonce'=>$challenge['nonce'],'peer'=>$challenge['peer'],
            'operation'=>$operation,'input_sha256'=>$challenge['input_sha256'],'context'=>$context],
            JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
        guard(strlen($payload)<=4096,'attestation_bound');
        $key=($this->privateKey)();
        try {
            guard(is_string($key)&&strlen($key)===32,'attestation_key_shape');
            $mac=hash_hmac('sha256',"mail-device-ipc-v1\0".$payload,$key);
        } finally { unset($key); }
        return ['payload'=>rtrim(strtr(base64_encode($payload),'+/','-_'),'='),'mac'=>$mac];
    }
}
