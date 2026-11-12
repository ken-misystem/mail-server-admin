<?php
declare(strict_types=1);
/** Candidate plugin. No installation or default-policy change is performed here. */
final class app_passwords extends rcube_plugin
{
    public $task='settings';
    private $rc;
    public function init():void
    {
        $this->rc=rcmail::get_instance();
        $this->add_hook('settings_actions',[$this,'menu']);
        $this->register_action('plugin.app_passwords',[$this,'show']);
        $this->register_action('plugin.app_passwords-api',[$this,'api']);
        $this->include_script('app_passwords.js');$this->include_stylesheet('app_passwords.css');
    }
    public function menu(array $args):array
    {
        $args['actions'][]=['action'=>'plugin.app_passwords','class'=>'password','label'=>'アプリ用パスワード','domain'=>''];return $args;
    }
    private function identity():string
    {
        // Load only declarations; never initialize the active Passkey plugin again.
        require_once '/var/lib/roundcube/plugins/local_auth/AccountIdentity.php';
        $id=$this->rc->user->ID??0;
        if(!is_int($id) || $id<=0 || (string)($_SESSION['user_id']??'')!==(string)$id)throw new RuntimeException('owner_session');
        return \MailServer\RoundcubePasskeyGeneral\AccountIdentity::requireOwner($this->rc->get_dbh(),$id,(string)$this->rc->get_user_name());
    }
    public function show():void
    {
        $this->identity();$this->rc->output->set_env('app_passwords_owner_username',(string)$this->rc->get_user_name());$this->rc->output->set_env('app_passwords_api',$this->rc->url(['_task'=>'settings','_action'=>'plugin.app_passwords-api']));
        $this->rc->output->set_pagetitle('アプリ用パスワード');$this->rc->output->send('app_passwords.settings');
    }
    private function store():\MailServer\GeneralAccounts\OwnerAppPasswords
    {
        require_once __DIR__.'/OwnerAppPasswords.php';
        // NEW proposed dedicated UI config; deployment/grants require separate approval.
        $path='/etc/roundcube/app-passwords.json';$m=lstat($path);
        if(!$m || is_link($path) || !is_file($path) || $m['uid']!==0 || ($m['mode']&0777)!==0640 || $m['nlink']!==1 || $m['size']>4096)throw new RuntimeException('config_boundary');
        $c=json_decode(file_get_contents($path),true,8,JSON_THROW_ON_ERROR);
        if(!is_array($c) || array_keys($c)!==['dsn','user','password'] || $c['user']!=='mail_app_password_ui'
            || !preg_match('~\Amysql:unix_socket=/[A-Za-z0-9/._-]+;dbname=mailserver;charset=utf8mb4\z~D',$c['dsn'])
            || !is_string($c['password']) || !preg_match('/\A[0-9a-f]{64}\z/D',$c['password']))throw new RuntimeException('config_shape');
        $db=new PDO($c['dsn'],$c['user'],$c['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);unset($c);
        if($db->query('SELECT CURRENT_USER()')->fetchColumn()!=='mail_app_password_ui@localhost')throw new RuntimeException('database_identity');
        return new \MailServer\GeneralAccounts\OwnerAppPasswords($db);
    }
    public static function confirm(#[SensitiveParameter] mixed $supplied,#[SensitiveParameter] mixed $sessionPassword):void
    {
        if(!is_string($supplied) || !is_string($sessionPassword) || $supplied==='' || strlen($supplied)>1024
            || !hash_equals($sessionPassword,$supplied))throw new DomainException('owner_confirmation_required');
    }
    public function api():never
    {
        $step='owner';
        header('Cache-Control: no-store, private');header('Content-Type: application/json; charset=UTF-8');
        try {
            $email=$this->identity();$this->rc->request_security_check(rcube_utils::INPUT_POST);
            if(($_SERVER['REQUEST_METHOD']??'')!=='POST')throw new DomainException('post_required');
            $op=$_POST['_operation']??'';$id=$_POST['_id']??'';$label=$_POST['_label']??'';$cursor=$_POST['_cursor']??null;
            if(!in_array($op,['list','issue','revoke','verification'],true))throw new DomainException('invalid_operation');
            $verification=null;
            if($op!=='list'){
                require_once '/usr/local/lib/mail-client-certificates-web-v3/client-certificates/owner-lifecycle-v1/OwnerClient.php';
                $verification=\MailServer\OwnerLifecycleV1\ownerClient($this->rc);
                if($op==='verification'){echo json_encode(['ok'=>true,'value'=>$verification->status()],JSON_THROW_ON_ERROR);exit;}
            }
            if($op!=='list'){
                $step='confirmation';$supplied=$_POST['_owner_password']??null;unset($_POST['_owner_password']);
                try{
                    if($verification->status()['authentication_required']===false){$verification->requireAction($op==='issue'?'app_password_issue':'app_password_revoke',['operation'=>$op,'id'=>is_string($id)?$id:'','label'=>is_string($label)?$label:'']);}
                    else{self::confirm($supplied,$this->rc->decrypt($_SESSION['password']??''));}
                }finally{unset($supplied);}
            }
            $step='storage';$store=$this->store();
            $value=match($op){'list'=>$store->listing($email,is_string($cursor)&&$cursor!==''?$cursor:null),
                'issue'=>['credential'=>$store->issue($email,is_string($label)?$label:'')],
                'revoke'=>(function()use($store,$email,$id){$store->revoke($email,is_string($id)?$id:'');return ['revoked'=>true];})()};
            echo json_encode(['ok'=>true,'value'=>$value],JSON_THROW_ON_ERROR);exit;
        }catch(Throwable $error){
            unset($_POST['_owner_password']);http_response_code($step==='confirmation'?403:400);
            // Never echo raw PDO/exception/config/input/credential material.
            echo json_encode(['ok'=>false,'phase'=>$step,'error'=>$step==='confirmation'?'owner_confirmation_required':'operation_unverified',
                'error_class'=>in_array(get_class($error),['PDOException','DomainException','RuntimeException','TypeError'],true)?get_class($error):'other',
                'source_line'=>$error->getLine()],JSON_THROW_ON_ERROR);exit;
        }
    }
}
