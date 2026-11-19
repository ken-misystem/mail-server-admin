<?php
declare(strict_types=1);

use MISystem\RoundcubeCompat\LoginView;
use MISystem\RoundcubeCompat\Siteverify;

require_once dirname(__DIR__) . '/mi_system_compat/LoginView.php';
require_once dirname(__DIR__) . '/mi_system_compat/Siteverify.php';

class turnstile extends rcube_plugin
{
    public $task = 'login';

    public function init(): void
    {
        $this->add_hook('loginform_content', [$this, 'widget']);
        $this->add_hook('authenticate', [$this, 'challenge']);
    }

    public function widget(array $form): array
    {
        $config = rcmail::get_instance()->config;
        $key = (string) $config->get('turnstile_sitekey', '');
        if ($key === '') {
            return $form;
        }
        $content = html::div(['class' => 'cf-turnstile', 'data-sitekey' => $key,
            'data-action' => (string) $config->get('turnstile_action', 'roundcube-login'),
            'data-theme' => 'auto'], '');
        $content .= '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
        return LoginView::button($form, 'turnstile', 'turnstile-login', $content, true);
    }

    public function challenge(array $state): array
    {
        if (!empty($state['abort'])) {
            return $state;
        }
        $config = rcmail::get_instance()->config;
        $payload = Siteverify::parameters((string) $config->get('turnstile_secret', ''),
            $_POST['cf-turnstile-response'] ?? null, $_SERVER['REMOTE_ADDR'] ?? null);
        if ($payload !== null) {
            try {
                [$status, $response] = $this->verify($payload);
                if (Siteverify::accepted($status, $response,
                    (string) $config->get('turnstile_hostname', 'mx.mi-sys.jp'),
                    (string) $config->get('turnstile_action', 'roundcube-login'))) {
                    return $state;
                }
            } catch (Throwable) {
                rcube::write_log('turnstile', 'Siteverify unavailable');
            }
        }
        return array_replace($state, ['abort' => true, 'error' => 'Human verification failed. Please retry.']);
    }

    protected function verify(array $payload): array
    {
        return Siteverify::send($payload);
    }
}
