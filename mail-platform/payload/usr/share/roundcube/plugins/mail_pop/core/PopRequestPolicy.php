<?php
declare(strict_types=1);
namespace MailServer\Pop;
final class PopRequestPolicy
{
    /** Source host/port belong to the user; identity/recipient/quota/worker flags never do. */
    public static function command(#[\SensitiveParameter]array $input):array
    {
        try{return self::validate($input);}
        catch(\DomainException){throw new \DomainException('invalid_request');}
    }
    private static function validate(#[\SensitiveParameter]array $input):array
    {
        $kind=$input['kind']??null;
        $keys=array_keys($input);sort($keys);
        $expected=match($kind){'list'=>['kind'],'create'=>['host','kind','label','password','port','username'],
            'edit'=>['host','id','kind','label','password','port','username'],
            'state'=>['enabled','id','kind'],'password'=>['id','kind','password'],'remove'=>['confirm','id','kind'],default=>[]};
        if(!$expected || $keys!==$expected)throw new \DomainException('invalid_request');
        if($kind==='list')return $input;
        if($kind==='create' || $kind==='edit'){
            if($kind==='edit'){if(!is_string($input['id']))throw new \DomainException('invalid_request');PopSourcePolicy::accountId($input['id']);}
            foreach(['host','port','username','label','password'] as $key)if(!is_string($input[$key]))throw new \DomainException('invalid_request');
            if(!preg_match('/\A[1-9][0-9]{0,4}\z/D',$input['port']))throw new \DomainException('invalid_request');
            $input['host']=PopSourcePolicy::host($input['host']);$input['port']=PopSourcePolicy::port((int)$input['port']);
            PopSourcePolicy::username($input['username']);
            if($kind==='create' || $input['password']!=='')PopSourcePolicy::password($input['password']);
            if($input['label']==='' || strlen($input['label'])>128 || preg_match('//u',$input['label'])!==1 || preg_match('/[\x00-\x1f\x7f]/',$input['label']))throw new \DomainException('invalid_request');
        }else{
            if(!is_string($input['id']))throw new \DomainException('invalid_request');PopSourcePolicy::accountId($input['id']);
            if($kind==='state' && !is_bool($input['enabled']))throw new \DomainException('invalid_request');
            if($kind==='password'){if(!is_string($input['password']))throw new \DomainException('invalid_request');PopSourcePolicy::password($input['password']);}
            if($kind==='remove' && $input['confirm']!=='remove')throw new \DomainException('invalid_request');
        }
        return $input;
    }
}
