<?php

class local_ja_tweaks extends rcube_plugin
{
    public $task = 'login|mail|settings|addressbook';

    public function init()
    {
        $rc = rcmail::get_instance();

        $lang = $_SESSION['language']
            ?? $rc->config->get('language', 'en_US');

        if ($lang !== 'ja_JP' && $lang !== 'ja') {
            return;
        }

        $file = '/etc/roundcube/local_ja_tweaks.php';

        if (is_readable($file)) {
            $overrides = require $file;

            if (is_array($overrides) && $overrides) {
                $rc->load_language(null, [], $overrides);

                if (isset($rc->output) && method_exists($rc->output, 'add_label')) {
                    $rc->output->add_label(array_keys($overrides));
                }
            }
        }

        // Small UI fixes not supported by localization strings alone.
        if ($rc->task === 'settings') {
            $this->add_hook(
                'preferences_sections_list',
                [$this, 'hide_mailvelope_settings']
            );
        }

        $this->include_script('local_ja_tweaks.js');
    }

    public function hide_mailvelope_settings($args)
    {
        // Roundcube built-in Mailvelope preferences.
        unset($args['list']['encryption']);

        return $args;
    }


}
