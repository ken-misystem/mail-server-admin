<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class AdminPasskeyLogin
{
    public const CSRF = 'mail_admin_passkey_login';
    private const PENDING = 'mail_admin_guest_passkey';

    public function __construct(
        private readonly AdminDirectory $directory,
        private readonly AdminPasskeyStore $store,
        private readonly AdminWebauthn $validator,
        private readonly CsrfTokenManagerInterface $csrf,
        private readonly RateLimiterFactory $limiter,
    ) {}

    public function options(Request $request): JsonResponse
    {
        try {
            $body = $this->read($request);
            $request->getSession()->remove(self::PENDING);
            $discoverable = !array_key_exists('email', $body);
            $user = null;
            if (!$discoverable) {
                if (!is_string($body['email'])) { throw new \DomainException('invalid_request'); }
                $user = $this->directory->byEmail(AdminPolicy::identity(trim($body['email'])));
            }
            $records = $user?->active ? $this->store->snapshot($user)['records'] : [];
            $options = $this->validator->loginOptions($records, $discoverable);
            $request->getSession()->set(self::PENDING, [
                'discoverable' => $discoverable,
                'id' => $records ? $user?->id : null,
                'epoch' => $records ? $user?->epoch : null,
                'at' => time(),
                'options' => $options,
            ]);
            return self::json(['publicKey' => json_decode($options, true, 32, JSON_THROW_ON_ERROR)], 200);
        } catch (\Throwable $error) {
            return self::failure($error);
        }
    }

    public function authenticate(Request $request): AdminUser
    {
        $body = $this->read($request);
        $pending = $request->getSession()->remove(self::PENDING);
        $now = time();
        if (!is_array($pending) || !is_bool($pending['discoverable'] ?? null) || !is_int($pending['at'])
            || $pending['at'] > $now || $pending['at'] <= $now - AdminWebauthn::TTL
            || !is_array($body['credential'] ?? null)) {
            throw new \DomainException('passkey_failed');
        }
        $response = json_encode($body['credential'], JSON_THROW_ON_ERROR);
        $id = $pending['id'];
        if ($pending['discoverable']) {
            [$credentialId, $userHandle] = $this->validator->discoverableIdentity($response);
            $id = $this->store->ownerOfCredential($credentialId, $userHandle);
        }
        $user = is_string($id) ? $this->directory->byId($id) : null;
        if (!$user?->active || (!$pending['discoverable'] && $user->epoch !== $pending['epoch'])) {
            throw new \DomainException('passkey_failed');
        }
        $this->store->authenticate($user, $response, $pending['options'], $this->validator);
        return $user;
    }

    private function read(Request $request): array
    {
        if ($request->getSchemeAndHttpHost() !== AdminWebauthn::ORIGIN
            || $request->headers->get('Origin') !== AdminWebauthn::ORIGIN
            || !$this->csrf->isTokenValid(new CsrfToken(self::CSRF, $request->headers->get('X-CSRF-Token', '')))) {
            throw new \DomainException('forbidden');
        }
        if (!$this->limiter->create('guest-passkey:' . $request->getClientIp())->consume()->isAccepted()) {
            throw new \DomainException('limited');
        }
        if ($request->getContentTypeFormat() !== 'json' || strlen($request->getContent()) > 131072) {
            throw new \DomainException('invalid_request');
        }
        $body = json_decode($request->getContent(), true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($body)) { throw new \DomainException('invalid_request'); }
        return $body;
    }

    public static function failure(\Throwable $error): JsonResponse
    {
        $status = $error instanceof \DomainException ? match ($error->getMessage()) {
            'forbidden' => 403,
            'limited' => 429,
            default => 400,
        } : 400;
        return self::json(['error' => 'passkey_failed'], $status);
    }

    public static function json(array $data, int $status): JsonResponse
    {
        return new JsonResponse(['ok' => $status === 200] + $data, $status, ['Cache-Control' => 'no-store']);
    }
}
