<?php

declare(strict_types=1);

/** Local-only Roundcube preference prototype; no collector or sender. */
final class junk_digest extends rcube_plugin
{
    public $task = 'settings';

    private const PREF_KEY = 'junk_digest_daily_opt_in_v1';
    private const INPUT_NAME = '_junk_digest_daily_opt_in_v1';
    private const FIELD_ID = 'rcmfd_junk_digest_daily_opt_in_v1';

    public function init(): void
    {
        $this->add_texts('localization/', false);
        $this->add_hook('preferences_list', [$this, 'preferencesList']);
        $this->add_hook('preferences_save', [$this, 'preferencesSave']);
    }

    public function preferencesList(array $args): array
    {
        if (($args['section'] ?? null) !== 'server' || !$this->authenticated()) {
            return $args;
        }

        $rc = rcmail::get_instance();
        $prefs = $rc->user->get_prefs();
        $enabled = is_array($prefs) && ($prefs[self::PREF_KEY] ?? null) === true;
        $checkbox = new html_checkbox([
            'name' => self::INPUT_NAME,
            'id' => self::FIELD_ID,
            'value' => 1,
        ]);
        $args['blocks']['main']['options'][self::PREF_KEY] = [
            'title' => html::label(self::FIELD_ID, rcube::Q($this->gettext('receivereport'))),
            'content' => $checkbox->show($enabled ? 1 : 0),
        ];
        return $args;
    }

    public function preferencesSave(array $args): array
    {
        if (($args['section'] ?? null) !== 'server' || !$this->authenticated()) {
            return $args;
        }

        $rc = rcmail::get_instance();
        $rc->request_security_check(rcube_utils::INPUT_POST);
        $submitted = $_POST[self::INPUT_NAME] ?? null;
        // An absent checkbox means opt-out. Unexpected types/values cannot opt in.
        $args['prefs'][self::PREF_KEY] = $submitted === '1';
        return $args;
    }

    private function authenticated(): bool
    {
        $id = $_SESSION['user_id'] ?? null;
        return (is_int($id) && $id > 0)
            || (is_string($id) && preg_match('/\A[1-9][0-9]{0,9}\z/D', $id) === 1);
    }
}
