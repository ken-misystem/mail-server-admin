<?php
declare(strict_types=1);

use MISystem\RoundcubeCompat\LoginView;

require_once dirname(__DIR__) . '/mi_system_compat/LoginView.php';

class local_password_recovery extends rcube_plugin
{
    public $task = 'login';

    public function init(): void
    {
        $this->add_hook('loginform_content', [$this, 'link']);
    }

    public function link(array $form): array
    {
        return LoginView::button($form, 'password_recovery', 'password-recovery',
            html::a(['href' => '/recovery/', 'class' => 'button'], 'パスワードを忘れた場合'));
    }
}
