<?php
declare(strict_types=1);
namespace MailServer\Management;
final class LegacySmtpFailure extends \RuntimeException
{
    public readonly array $detail;
    public function __construct(string $stage,\Throwable $cause,?\Throwable $cleanup=null)
    {
        $safe=static function(\Throwable $e):array {
            $info=$e instanceof \PDOException ? $e->errorInfo : null;
            $state=is_array($info)&&is_string($info[0]??null)&&preg_match('/^[A-Z0-9]{5}$/D',$info[0])?$info[0]:null;
            $code=is_array($info)&&is_int($info[1]??null)?$info[1]:null;
            $frames=[];
            foreach(array_slice($e->getTrace(),0,6)as$f) {
                $file=basename($f['file']??'');
                $frames[]=['component'=>in_array($file,['PdoLegacySmtpStore.php','LegacySmtpController.php'],true)?$file:'dependency',
                    'line'=>is_int($f['line']??null)?$f['line']:null];
            }
            return ['class'=>$e instanceof \PDOException?'PDOException':($e instanceof \DomainException?'DomainException':'Throwable'),
                'sqlstate'=>$state,'native_code'=>$code,'frames'=>$frames];
        };
        $this->detail=['stage'=>$stage,'primary'=>$safe($cause),'cleanup'=>$cleanup?$safe($cleanup):null];
        parent::__construct('legacy_smtp_operation_unverified');
    }
}
