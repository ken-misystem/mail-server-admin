<?php
declare(strict_types=1);
/** Authenticated settings routes only. No DB/key/credential configuration. */
final class mail_client_certificates extends rcube_plugin
{
    public $task='settings';
    private const ACTIONS=['list','issue_options','issue_finish','revoke_options','revoke_finish','download'];
    private rcmail $rc;
    public function init():void
    {
        $this->rc=rcmail::get_instance();$this->add_texts('localization/',true);
        $this->add_hook('settings_actions',[$this,'settingsActions']);
        $this->register_action('plugin.mail_client_certificates',[$this,'show']);
        foreach(self::ACTIONS as $action)$this->register_action('plugin.mail_client_certificates-'.$action,fn()=>$this->serve($action));
    }
    public function settingsActions(array $args):array
    {
        $args['actions'][]=['action'=>'plugin.mail_client_certificates','class'=>'mail-client-certificates','label'=>'title','domain'=>'mail_client_certificates'];return $args;
    }
    private function owner():void
    {
        if(!$this->rc->user||!$this->rc->get_user_id()||!$this->rc->session||$this->rc->session->check_auth()!==true)
            throw new RuntimeException('certificate_owner_login_required');
    }
    public function show():void
    {
        $this->owner();$this->include_script('owner-ui.js');$this->include_script('roundcube-transport.js');$this->include_stylesheet('owner-ui.css');
        $this->rc->output->set_env('mail_client_certificates_ready',true);$this->rc->output->set_pagetitle($this->gettext('title'));
        $this->rc->output->send('mail_client_certificates.certificates');
    }
    private function serve(string $action):never
    {
        try {
            $this->owner();
            require_once '/usr/local/lib/mail-client-certificates-v1/client-certificates/production-apply-v1/PluginRuntime.php';
            \MailServer\CertificateDeployment\endpoint($this->rc,\MailServer\CertificateDeployment\protectedWebConfiguration())
                ->serve($action,\MailServer\CertificateWebCandidate\Endpoint::readNativeBody(...));
        }catch(Throwable $error){
            if(class_exists(\MailServer\CertificateDeployment\Audit::class,false))(new \MailServer\CertificateDeployment\Audit())->record($error,'bootstrap');
            else error_log(json_encode(['component'=>'mail_client_certificates_web','phase'=>'bootstrap','class'=>get_class($error),
                'source'=>basename($error->getFile()),'line'=>$error->getLine(),'raw_error_saved'=>false]));
            if(!headers_sent()){
                http_response_code(503);header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store, private');
                header('X-Content-Type-Options: nosniff');echo '{"ok":false,"error_code":"operation_unverified"}';
            }
        }
        exit;
    }
}
