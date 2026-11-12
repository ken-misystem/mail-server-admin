<?php
declare(strict_types=1);
use MailServer\AliasUi\RequestPolicy;
use MailServer\Pop\PopAccountRepository;
use MailServer\Pop\PopRequestPolicy;
use MailServer\Pop\PopSealedBox;

/** Local candidate: reuse existing Roundcube actor/token security; separate POP DB/public key. */
final class mail_pop extends rcube_plugin
{
    public $task='settings';
    private rcmail $rc;
    public function init():void
    {
        require_once dirname(__DIR__).'/mail_aliases/src/RequestPolicy.php'; // Same file as mail_aliases; never redeclare the shared actor class.
        $this->rc=rcmail::get_instance();$this->load_config();$this->add_texts('localization/',true);
        $this->add_hook('settings_actions',[$this,'settingsActions']);
        $this->register_action('plugin.mail_pop',[$this,'show']);$this->register_action('plugin.mail_pop-rpc',[$this,'rpc']);
        $this->include_script('mail_pop.js');$this->include_stylesheet('mail_pop.css');
    }
    public function settingsActions(array $args):array
    {
        try{$this->actor();}catch(Throwable){return $args;}
        $args['actions'][]=['action'=>'plugin.mail_pop','class'=>'mail-pop','label'=>'popsettings','domain'=>'mail_pop'];return $args;
    }
    public function show():void
    {
        try{$this->actor();}catch(Throwable){$this->json(403,['ok'=>false,'error_code'=>'not_authorized']);}
        $this->rc->output->set_pagetitle($this->gettext('popsettings'));$this->rc->output->send('mail_pop.pop');
    }
    public function rpc():never
    {
        try{
            $actor=$this->actor();
            if(($_SERVER['REQUEST_METHOD']??'')!=='POST')throw new DomainException('invalid_request');
            $header=rcube_utils::request_header('X-Roundcube-Request');
            if(!is_string($header) || !hash_equals($this->rc->get_request_token(),$header))throw new DomainException('not_authorized');
            $this->rc->request_security_check(rcube_utils::INPUT_POST);
            $body=file_get_contents('php://input',false,null,0,8193);
            if(!is_string($body) || strlen($body)>8192)throw new DomainException('invalid_request');
            $input=json_decode($body,true,16,JSON_THROW_ON_ERROR);if(!is_array($input))throw new DomainException('invalid_request');
            foreach(['PopSourcePolicy','PopSealedBox','PopRequestPolicy','PopAccountRepository'] as $name)require_once __DIR__.'/core/'.$name.'.php';
            $command=PopRequestPolicy::command($input);$repository=$this->repository();
            switch($command['kind']){
                case 'list':$this->json(200,['ok'=>true,...$repository->overview($actor)]);
                case 'create':$repository->create($actor,$command['host'],$command['port'],$command['username'],$command['label'],$command['password']);break;
                case 'edit':$repository->edit($actor,$command['id'],$command['host'],$command['port'],$command['username'],$command['label'],$command['password']);break;
                case 'state':$repository->setEnabled($actor,$command['id'],$command['enabled']);break;
                case 'password':$repository->replacePassword($actor,$command['id'],$command['password']);break;
                case 'remove':$repository->remove($actor,$command['id']);break;
            }
            $this->json(200,['ok'=>true]);
        }catch(Throwable $error){
            $code=$error instanceof DomainException?$error->getMessage():'unavailable';
            if(!in_array($code,['not_authorized','invalid_request','pop_limit',
                'pop_pause_required','pop_source_review_required','pop_source_password_required','pop_storage_unavailable','result_unverified'],true))$code='unavailable';
            $this->json(400,['ok'=>false,'error_code'=>$code]); // No exception/protocol/password text.
        }
    }
    private function actor():string
    {
        $pilots=$this->rc->config->get('mail_pop_pilot_users',[]);
        return RequestPolicy::actor($this->rc->config->get('mail_pop_enabled',false)===true,
            is_array($pilots)?$pilots:[],$_SESSION['user_id']??null,$_SESSION['username']??null,$this->rc->get_user_name());
    }
    private function repository():PopAccountRepository
    {
        // Proposed NEW paths, not yet provisioned. Web never receives the worker private key.
        $path='/etc/roundcube/mail-pop.json';$public='/etc/roundcube/mail-pop-public.key';
        foreach([$path,$public] as $file){
            $info=lstat($file);
            if(!$info || !is_file($file) || is_link($file) || $info['uid']!==0 || $info['gid']!==33
                || ($info['mode']&0777)!==0640)throw new DomainException('unavailable');
        }
        $data=file_get_contents($path,false,null,0,4097);if(!is_string($data) || strlen($data)>4096)throw new DomainException('unavailable');
        $config=json_decode($data,true,8,JSON_THROW_ON_ERROR);$key=file_get_contents($public,false,null,0,33);
        if(!is_array($config) || count($config)!==3 || ($config['user']??null)!=='mail_pop_ui'
            || !is_string($config['password']??null) || !is_string($config['dsn']??null)
            || !preg_match('~\Amysql:unix_socket=/[A-Za-z0-9/._-]+;dbname=mail_management;charset=utf8mb4\z~D',$config['dsn'])
            || !is_string($key) || strlen($key)!==32)throw new DomainException('unavailable');
        return new PopAccountRepository(new PDO($config['dsn'],$config['user'],$config['password'],
            [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]),
            static fn(#[SensitiveParameter]string $password):string=>PopSealedBox::seal($password,$key));
    }
    private function json(int $status,array $data):never
    {
        while(ob_get_level()>0)ob_end_clean();http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
        echo json_encode($data,JSON_THROW_ON_ERROR);exit;
    }
}
