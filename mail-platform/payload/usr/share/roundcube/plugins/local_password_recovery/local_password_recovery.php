<?php

class local_password_recovery extends rcube_plugin
{
    public $task = 'login';

    public function init()
    {
        $this->add_hook(
            'loginform_content',
            [$this, 'loginform_content']
        );
    }

    public function loginform_content($args)
    {
        $link = html::a(
            [
                'href'  => '/recovery/',
                'class' => 'button',
            ],
            'パスワードを忘れた場合'
        );

        $args['buttons']['password_recovery'] = [
            'outterclass' => 'password-recovery',
            'content'     => $link,
        ];

        return $args;
    }
}
