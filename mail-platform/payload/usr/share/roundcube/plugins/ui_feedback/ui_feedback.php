<?php
declare(strict_types=1);

/** Presentation only: all Roundcube tasks, no actor/auth/DB/hooks or actions. */
final class ui_feedback extends rcube_plugin
{
    public $task = '.*';

    public function init(): void
    {
        $this->include_stylesheet('feedback.css');
        if (rcmail::get_instance()->task === 'settings') {
            $this->include_script('settings-menu.js');
            $this->include_stylesheet('settings-menu.css');
        }
    }
}
