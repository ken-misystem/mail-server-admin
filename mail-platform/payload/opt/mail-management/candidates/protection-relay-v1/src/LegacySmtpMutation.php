<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Only hashes enter this DTO; never serialize or log its values. */
final readonly class LegacySmtpMutation
{
    private function __construct(public string $action, #[\SensitiveParameter] private array $values) {}
    public function value(string $key): mixed { return $this->values[$key]; }
    public function __debugInfo(): array { return ['action'=>$this->action,'values'=>'[omitted]']; }
    public function __serialize(): array { throw new \LogicException('secret_mutation_not_serializable'); }
    public static function number(string $value): string
    {
        if (!preg_match('/^[1-9][0-9]{0,19}$/D',$value)
            || (strlen($value)===20 && strcmp($value,'18446744073709551615')>0)) { throw new \DomainException('invalid_input'); }
        return $value;
    }
    public static function login(string $value): string
    {
        // Preserve original spelling. Do not rewrite a legacy ID as a mailbox name.
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,127}$/D',$value)) { throw new \DomainException('invalid_login'); }
        return $value;
    }
    // Explicit ASCII addr-spec, no display name, wildcard or local-domain lookup.
    // Canonical lower-case keys match the dedicated sender-map policy.
    public static function sender(string $value): string
    {
        if ($value !== trim($value) || strlen($value)>254 || substr_count($value,'@')!==1) {
            throw new \DomainException('invalid_sender');
        }
        [$local,$domain]=explode('@',$value,2);
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$/D',$local)
            || str_ends_with($local,'.') || str_contains($local,'..')) {
            throw new \DomainException('invalid_sender');
        }
        try { $domain=AdminMailPolicy::domain($domain); }
        catch (\DomainException) { throw new \DomainException('invalid_sender'); }
        // domain() trims: reject whitespace in the input before accepting it.
        if (preg_match('/\s/', $value)) { throw new \DomainException('invalid_sender'); }
        return strtolower($local).'@'.$domain;
    }
    public static function fromForm(#[\SensitiveParameter] array $input): self
    {
        $action=$input['action']??null;
        $keys=match($action) {
            'create'=>['action','login_id','sender_address','new_password','repeat_password','_csrf_token'],
            'password'=>['action','id','revision','confirm_login','new_password','repeat_password','_csrf_token'],
            'state'=>['action','id','revision','confirm_login','enabled','_csrf_token'],
            default=>throw new \DomainException('invalid_action'),
        };
        if (array_diff(array_keys($input),$keys)) { throw new \DomainException('invalid_input'); }
        $text=static function(string $key)use($input):string {
            if (!is_string($input[$key]??null)||strlen($input[$key])>1024) { throw new \DomainException('invalid_input'); }
            return $input[$key];
        };
        $values=$action==='create'
            ? ['login'=>self::login($text('login_id')),'sender'=>self::sender($text('sender_address'))]
            : ['id'=>self::number($text('id')),'revision'=>self::number($text('revision')),'confirm'=>self::login($text('confirm_login'))];
        if ($action==='state') {
            if (!in_array($text('enabled'),['0','1'],true)) { throw new \DomainException('invalid_input'); }
            $values['enabled']=$text('enabled')==='1';
        } else {
            $password=$text('new_password');$repeat=$text('repeat_password');
            // SMTP-only compatibility password: retain the existing management password policy.
            $values['hash']=(new AdminPasswordEncoder())->encode($password,$repeat,true);
            unset($password,$repeat);
        }
        return new self($action,$values);
    }
}
