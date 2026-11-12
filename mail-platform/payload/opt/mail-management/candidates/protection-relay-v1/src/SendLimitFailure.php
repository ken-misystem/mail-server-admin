<?php
declare(strict_types=1);
namespace MailServer\Management;

final class SendLimitFailure extends \RuntimeException
{
    public readonly array $detail;

    public function __construct(string $stage, \Throwable $error, ?\Throwable $cleanup, bool $committing)
    {
        $info = $error instanceof \PDOException ? $error->errorInfo : null;
        $this->detail = ['stage'=>$stage, 'class'=>get_class($error),
            'sqlstate'=>is_array($info) && preg_match('/^[A-Z0-9]{5}$/D', (string)($info[0] ?? '')) ? $info[0] : null,
            'driver_code'=>is_array($info) && is_int($info[1] ?? null) ? $info[1] : null,
            'cleanup_class'=>$cleanup ? get_class($cleanup) : null, 'commit_outcome_unknown'=>$committing];
        parent::__construct('send_limit_storage_failed');
    }
}
