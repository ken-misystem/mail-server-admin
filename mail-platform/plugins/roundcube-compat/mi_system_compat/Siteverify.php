<?php
declare(strict_types=1);

namespace MISystem\RoundcubeCompat;

final class Siteverify
{
    private const URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    public static function accepted(int $status, mixed $body, string $host, string $action): bool
    {
        if ($status !== 200 || !is_string($body) || $host === '' || $action === '') {
            return false;
        }
        $response = json_decode($body, true, 8);
        return is_array($response) && ($response['success'] ?? null) === true
            && ($response['hostname'] ?? null) === $host && ($response['action'] ?? null) === $action;
    }

    public static function parameters(string $secret, mixed $token, mixed $address): ?array
    {
        if ($secret === '' || !is_string($token) || $token === '' || strlen($token) > 2048) {
            return null;
        }
        $payload = ['secret' => $secret, 'response' => $token];
        if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP)) {
            $payload['remoteip'] = $address;
        }
        return $payload;
    }

    public static function send(array $payload): array
    {
        $request = curl_init(self::URL);
        if ($request === false) {
            return [0, false];
        }
        try {
            curl_setopt_array($request, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($payload),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_FOLLOWLOCATION => false,
            ]);
            $body = curl_exec($request);
            return [(int) curl_getinfo($request, CURLINFO_RESPONSE_CODE), $body];
        } finally {
            curl_close($request);
        }
    }
}
