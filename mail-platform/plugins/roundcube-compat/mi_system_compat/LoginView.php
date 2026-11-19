<?php
declare(strict_types=1);

namespace MISystem\RoundcubeCompat;

final class LoginView
{
    public static function button(array $form, string $name, string $class, string $content,
        bool $first = false): array
    {
        $buttons = $form['buttons'] ?? [];
        $item = [$name => ['outterclass' => $class, 'content' => $content]];
        $form['buttons'] = $first ? $item + $buttons : array_replace($buttons, $item);
        return $form;
    }

    public static function notice(string $message, string $state = ''): string
    {
        return \html::div(['class' => trim('ui-feedback-result ' . $state)], \rcube::Q($message));
    }

    public static function mailbox(object $roundcube): string
    {
        return strtolower(trim((string) $roundcube->get_user_name()));
    }

    public static function redirect(string $location): never
    {
        header('Location: ' . $location, true, 303);
        exit;
    }
}
