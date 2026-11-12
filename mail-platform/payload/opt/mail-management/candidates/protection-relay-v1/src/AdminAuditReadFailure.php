<?php
declare(strict_types=1);
namespace MailServer\Management;
final class AdminAuditReadFailure extends \RuntimeException
{
    public function __construct(public readonly string $stage,\Throwable $cause,public readonly ?\Throwable $cleanup=null)
    {parent::__construct('audit_read_failed',0,$cause);}
}
