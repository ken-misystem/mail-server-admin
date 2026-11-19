<?php
declare(strict_types=1);

class local_ja_tweaks extends rcube_plugin
{
    public $task = 'login|mail|settings|addressbook';
    private const LABELS = '/etc/roundcube/local_ja_tweaks.php';

    public function init(): void
    {
        $roundcube = rcmail::get_instance();
        $language = $_SESSION['language'] ?? $roundcube->config->get('language', 'en_US');
        if (!in_array($language, ['ja', 'ja_JP'], true)) {
            return;
        }
        if (is_readable(self::LABELS)) {
            $labels = require self::LABELS;
            if (is_array($labels) && $labels !== []) {
                $roundcube->load_language(null, [], $labels);
                if (is_callable([$roundcube->output, 'add_label'])) {
                    $roundcube->output->add_label(array_keys($labels));
                }
            }
        }
        if ($roundcube->task === 'settings') {
            $this->add_hook('preferences_sections_list', [$this, 'sections']);
            // mail_settings supplies its own forwarding UI. Load the legacy adapter
            // only for installs still using the standard ManageSieve layout.
            if (in_array('managesieve', (array) $roundcube->config->get('plugins', []), true)) {
                $this->include_script('local_ja_tweaks.js');
            }
        }
    }

    public function sections(array $sections): array
    {
        unset($sections['list']['encryption']);
        return $sections;
    }
}
