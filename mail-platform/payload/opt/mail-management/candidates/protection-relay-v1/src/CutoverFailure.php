<?php
declare(strict_types=1);
namespace MailServer\Management;

final class CutoverFailure extends \RuntimeException
{
    public readonly array $detail;
    public function __construct(string $phase, \Throwable $error, bool $uncertain, ?\Throwable $cleanup = null)
    {
        $state = $error instanceof \PDOException ? ($error->errorInfo[0] ?? null) : null;
        $code = $error instanceof \PDOException ? ($error->errorInfo[1] ?? null) : null;
        $this->detail = ['phase'=>$phase, 'exception'=>get_class($error), 'source'=>basename($error->getFile()),
            'line'=>$error->getLine(), 'sqlstate'=>is_string($state) && preg_match('/^[A-Z0-9]{5}$/D', $state) ? $state : null,
            'native_code'=>is_int($code) ? $code : null, 'outcome_uncertain'=>$uncertain,
            'rollback_failure'=>$cleanup === null ? null : ['exception'=>get_class($cleanup),
                'source'=>basename($cleanup->getFile()), 'line'=>$cleanup->getLine()], 'raw_error_output'=>false];
        parent::__construct($uncertain ? 'result_unverified' : 'storage_unavailable');
    }
}
