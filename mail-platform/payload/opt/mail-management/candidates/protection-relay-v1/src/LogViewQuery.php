<?php
declare(strict_types=1);
namespace MailServer\Management;
final class LogViewQuery
{
    public const CATEGORIES=['smtp_in'=>'SMTP受信・拒否','smtp_out'=>'SMTP送信・転送','delivery'=>'配送処理','access'=>'IMAP・POP接続','filter'=>'迷惑メール判定・日報','pop'=>'外部POP定期取得','web'=>'Web・PHP','security'=>'不正アクセス対策','system'=>'システム・監視'];
    public const LEVELS=['info'=>'通常','warning'=>'警告','error'=>'エラー'];
    public function __construct(public readonly string $category='',public readonly string $level='',
        public readonly string $word='',public readonly int $hours=24,public readonly int $before=PHP_INT_MAX)
    {
        if (($category!==''&&!isset(self::CATEGORIES[$category])) || ($level!==''&&!isset(self::LEVELS[$level]))
            || !in_array($hours,[1,24,168],true) || strlen($word)>160 || preg_match('//u',$word)!==1
            || preg_match('/[\x00-\x1f\x7f]/',$word) || $before<1) throw new \DomainException('invalid_log_query');
    }
    public static function fromArray(array $input): self
    {
        if(array_diff(array_keys($input),['category','level','word','hours','before','_token'])) throw new \DomainException('invalid_log_query');
        foreach(['category','level','word','hours','before']as$k) if(isset($input[$k])&&!is_string($input[$k])) throw new \DomainException('invalid_log_query');
        $hours=$input['hours']??'24';$before=$input['before']??'';
        if(!in_array($hours,['1','24','168'],true) || ($before!=='' && (!ctype_digit($before)||strlen($before)>19||strcmp(str_pad($before,19,'0',STR_PAD_LEFT),(string)PHP_INT_MAX)>0))) throw new \DomainException('invalid_log_query');
        return new self($input['category']??'',$input['level']??'',$input['word']??'',(int)$hours,$before===''?PHP_INT_MAX:(int)$before);
    }
}
