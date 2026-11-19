<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

final class AdminPasswordLoginListener
{
    public function onLogin(LoginSuccessEvent $event): void
    {
        if ($event->getAuthenticator() instanceof AdminPasskeyAuthenticator) { return; }
        $user = $event->getAuthenticatedToken()->getUser();
        if (!$user instanceof AdminUser) { return; }
        $session = $event->getRequest()->getSession();
        $session->remove(AdminFactorGate::SESSION_KEY);
        $session->remove(AdminPasskeyCeremony::PENDING);
        $session->set(AdminPasskeyCeremony::PASSWORD_LOGIN, ['admin_id' => $user->id,
            'auth_epoch' => $user->epoch, 'at' => time()]);
    }
}
