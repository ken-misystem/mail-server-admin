<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Finite diagnostics only; no SQL text, parameter values or raw error message. */
final class FeatureStorageFailure extends \DomainException
{
    public readonly array $detail;
    public function __construct(string $message,string $stage,#[\SensitiveParameter] \Throwable $error,#[\SensitiveParameter] ?\Throwable $cleanup,bool $committing)
    {
        $info=$error instanceof \PDOException?$error->errorInfo:null;
        $permission=null;$column=null;
        if(is_array($info)&&($info[1]??null)===1143&&is_string($info[2]??null)
            &&preg_match("/(SELECT|INSERT|UPDATE|DELETE) command denied .*? for column '([A-Za-z_][A-Za-z0-9_]{0,63})'/",$info[2],$parts)){$permission=$parts[1];$column=$parts[2];}
        $this->detail=['stage'=>$stage,'class'=>get_class($error),'sqlstate'=>is_array($info)&&preg_match('/^[A-Z0-9]{5}$/D',(string)($info[0]??''))?$info[0]:null,
            'driver_code'=>is_array($info)&&is_int($info[1]??null)?$info[1]:null,'source'=>basename($error->getFile()),'line'=>$error->getLine(),
            'cleanup_class'=>$cleanup?get_class($cleanup):null,'commit_outcome_unknown'=>$committing,'denied_permission'=>$permission,'denied_column'=>$column];
        parent::__construct($message);
    }
}
