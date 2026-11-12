<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Safe diagnostic fields are retained even when PDO/native text must not escape. */
final class DomainDeliveryFailure extends \RuntimeException
{
    public readonly array $detail;
    public function __construct(string $phase,\Throwable $error,bool $uncertain,?\Throwable $cleanup=null)
    {
        $sqlstate=$error instanceof \PDOException?($error->errorInfo[0]??(string)$error->getCode()):null;
        $code=$error instanceof \PDOException?($error->errorInfo[1]??null):null;
        $detail=['phase'=>$phase,'class'=>get_class($error),'source'=>basename($error->getFile()),
            'line'=>$error->getLine(),'sqlstate'=>is_string($sqlstate)&&preg_match('/^[A-Z0-9]{5}$/D',$sqlstate)?$sqlstate:null,
            'native_code'=>is_int($code)?$code:null,'outcome_uncertain'=>$uncertain,'raw_error_output'=>false];
        if ($cleanup!==null) { $detail['cleanup_failure']=['class'=>get_class($cleanup),
            'source'=>basename($cleanup->getFile()),'line'=>$cleanup->getLine()]; }
        $this->detail=$detail;
        parent::__construct($uncertain?'routing_result_unverified':'routing_storage_unavailable');
    }
}
