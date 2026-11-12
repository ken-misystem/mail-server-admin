<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Private request-memory plan; preview and diagnostics never include passwords/hashes. */
final class BulkMailboxPlan
{
    private bool $consumed=false;
    private function __construct(#[\SensitiveParameter] private array $rows) {}
    public function __debugInfo():array{return ['rows'=>count($this->rows),'values'=>'[omitted]'];}
    public function __serialize():array{throw new \LogicException('bulk_plan_not_serializable');}
    public static function parse(#[\SensitiveParameter] string $csv,array $domains):self
    {
        if(strlen($csv)>2*1024*1024||str_contains($csv,"\0")||!preg_match('//u',$csv)){throw new \DomainException('CSV形式を確認してください');}
        $csv=preg_replace('/^\xEF\xBB\xBF/','',$csv);$stream=fopen('php://temp','w+');fwrite($stream,$csv);rewind($stream);
        try{
            $headers=fgetcsv($stream,null,',','"','');
            if($headers!==['domain_id','local_part','password','quota_bytes']){throw new \DomainException('CSV見出しを確認してください');}
            $rows=[];$seen=[];$line=1;
            while(($values=fgetcsv($stream,null,',','"',''))!==false){
                ++$line;if($values===[null]){continue;}
                if(count($rows)>=1000||count($values)!==4){throw new \DomainException('CSV行数または列数を確認してください');}
                [$id,$local,$password,$quota]=$values;
                if(!is_string($id)||!preg_match('/^[1-9][0-9]{0,9}$/D',$id)||!isset($domains[$id])||!is_string($domains[$id])){throw new \DomainException('対象ドメインを確認してください');}
                $host=AdminMailPolicy::domain($domains[$id]);$local=AliasPolicy::registrationLocal(AdminMailPolicy::localPart((string)$local));
                if(AliasPolicy::isReserved($local)){throw new \DomainException('予約された名前は個別に登録してください');}
                $email=AliasPolicy::registrationAddress($local,$host);
                if(isset($seen[$email])){throw new \DomainException('CSV内の正規化後アドレスが重複しています');}$seen[$email]=true;
                if(!is_string($password)||strlen($password)<12||strlen($password)>1024||preg_match('/[\x00-\x1f\x7f]/',$password)) {throw new \DomainException('パスワードの入力条件を確認してください');}
                if(!is_string($quota)||!preg_match('/^(?:0|[1-9][0-9]{0,14})$/D',$quota)||(int)$quota>100000000000000){throw new \DomainException('容量上限を確認してください');}
                $rows[]=['line'=>$line,'domain_id'=>$id,'email'=>$email,'password'=>$password,'quota_bytes'=>(int)$quota];
            }
            if(!$rows){throw new \DomainException('登録対象の行がありません');}return new self($rows);
        }finally{fclose($stream);}
    }
    public function preview():array
    {
        return array_map(static fn(array $r):array=>['line'=>$r['line'],'domain_id'=>$r['domain_id'],'email'=>$r['email'],'quota_bytes'=>$r['quota_bytes'],'initial_state'=>'無効'],$this->rows);
    }
    public function selected(#[\SensitiveParameter] array $lines):array
    {
        if($this->consumed||count($lines)<1||count($lines)>25||count(array_unique($lines,SORT_REGULAR))!==count($lines)){throw new \DomainException('選択は1回25件までです');}
        foreach($lines as $line){if(!is_int($line)||$line<2||$line>2097153){throw new \DomainException('選択行を確認してください');}}
        $selected=array_values(array_filter($this->rows,static fn(array $r):bool=>in_array($r['line'],$lines,true)));
        if(count($selected)!==count($lines)){throw new \DomainException('選択行が存在しません');}
        $out=[];
        foreach($selected as $r){$out[]=['line'=>$r['line'],'domain_id'=>$r['domain_id'],'email'=>$r['email'],'quota_bytes'=>$r['quota_bytes'],
            'hash'=>(new AdminPasswordEncoder())->encode($r['password'],$r['password'],true)];}
        $this->consumed=true;$this->rows=[];return $out;
    }
}
