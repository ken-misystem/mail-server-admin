<?php

class turnstile extends rcube_plugin
{
    public $task = 'login';

    private $rc;

    public function init()
    {
        $this->rc = rcmail::get_instance();

        $this->add_hook(
            'loginform_content',
            [$this, 'loginform_content']
        );

        $this->add_hook(
            'authenticate',
            [$this, 'authenticate']
        );
    }

    public function loginform_content($args)
    {
        $sitekey = (string) $this->rc->config->get(
            'turnstile_sitekey',
            ''
        );

        if ($sitekey === '') {
            return $args;
        }

        $action = (string) $this->rc->config->get(
            'turnstile_action',
            'roundcube-login'
        );

        $widget =
            '<div class="cf-turnstile"'
            . ' data-sitekey="' . rcube::Q($sitekey) . '"'
            . ' data-action="' . rcube::Q($action) . '"'
            . ' data-theme="auto"></div>'
            . '<script src="https://challenges.cloudflare.com/'
            . 'turnstile/v0/api.js" async defer></script>';

        $buttons = $args['buttons'] ?? [];

        $args['buttons'] = [
            'turnstile' => [
                'outterclass' => 'turnstile-login',
                'content' => $widget,
            ],
        ] + $buttons;

        return $args;
    }

    public function authenticate($args)
    {
        $secret = (string) $this->rc->config->get(
            'turnstile_secret',
            ''
        );

        $hostname = (string) $this->rc->config->get(
            'turnstile_hostname',
            'mx.mi-sys.jp'
        );

        $action = (string) $this->rc->config->get(
            'turnstile_action',
            'roundcube-login'
        );

        $token = isset($_POST['cf-turnstile-response'])
            ? (string) $_POST['cf-turnstile-response']
            : '';

        if ($secret === '' || $token === '') {
            return $this->deny($args);
        }

        $post = [
            'secret'   => $secret,
            'response' => $token,
        ];

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $post['remoteip'] = $_SERVER['REMOTE_ADDR'];
        }

        $ch = curl_init(
            'https://challenges.cloudflare.com/'
            . 'turnstile/v0/siteverify'
        );

        curl_setopt_array($ch, [
            CURLOPT_POST            => true,
            CURLOPT_POSTFIELDS      => http_build_query($post),
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_CONNECTTIMEOUT  => 3,
            CURLOPT_TIMEOUT         => 5,
            CURLOPT_HTTPHEADER      => [
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);

        $body = curl_exec($ch);
        $http = (int) curl_getinfo(
            $ch,
            CURLINFO_RESPONSE_CODE
        );

        curl_close($ch);

        if ($body === false || $http !== 200) {
            rcube::raise_error(
                [
                    'code' => 403,
                    'message' => 'Turnstile Siteverify request failed',
                ],
                true,
                false
            );

            return $this->deny($args);
        }

        $result = json_decode($body, true);

        if (
            !is_array($result)
            || empty($result['success'])
            || !hash_equals(
                $hostname,
                (string) ($result['hostname'] ?? '')
            )
            || !hash_equals(
                $action,
                (string) ($result['action'] ?? '')
            )
        ) {
            return $this->deny($args);
        }

        return $args;
    }

    private function deny($args)
    {
        $args['abort'] = true;
        $args['error'] = 'Human verification failed. Please retry.';

        return $args;
    }
}
