<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class AdminPasskeyAuthenticator extends AbstractAuthenticator
{
    public function __construct(private readonly AdminPasskeyLogin $login) {}

    public function supports(Request $request): bool
    {
        return $request->isMethod('POST') && $request->attributes->get('_route') === 'mail_admin_guest_passkey_finish';
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $user = $this->login->authenticate($request);
        } catch (\Throwable $error) {
            $request->attributes->set('_mail_admin_passkey_failure', AdminPasskeyLogin::failure($error));
            throw new AuthenticationException('passkey_failed');
        }
        return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), static fn (): AdminUser => $user));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $user = $token->getUser();
        $session = $request->getSession();
        $session->remove(AdminPasskeyCeremony::PASSWORD_LOGIN);
        $session->remove(AdminPasskeyCeremony::PENDING);
        $session->set(AdminFactorGate::SESSION_KEY, ['admin_id' => $user->id, 'auth_epoch' => $user->epoch,
            'factor' => 'webauthn_uv', 'verified_at' => time()]);
        return AdminPasskeyLogin::json(['redirect' => '/mail-admin/'], 200);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $request->attributes->get('_mail_admin_passkey_failure') ?? AdminPasskeyLogin::failure($exception);
    }
}
