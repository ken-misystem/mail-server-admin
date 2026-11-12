<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use Closure;
use Throwable;

final class NetSmtpLoopbackMailTransport implements EmergencyRecoveryMailTransport
{
    private const HOST = '127.0.0.1';
    private const PORT = 25;
    private const HELO_HOST = 'mx.mi-sys.jp';
    private readonly string $sender;
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const MAX_BODY_BYTES = 16384;

    private readonly Closure $clientFactory;

    public function __construct(string $sender, ?Closure $clientFactory = null)
    {
        $this->sender = \MailServer\RoundcubePasskeyGeneral\AccountIdentity::canonical($sender);
        $this->clientFactory = $clientFactory ?? static function (): object {
            if (!class_exists('Net_SMTP')) {
                throw new EmergencyRecoveryException('SMTP library is unavailable.', 'setup');
            }

            return new \Net_SMTP(
                self::HOST,
                self::PORT,
                self::HELO_HOST,
                false,
                0,
                [],
            );
        };
    }

    public function submit(string $recipient, string $subject, string $body): bool
    {
        if (!$this->validAddress($recipient)
            || !in_array($subject, [self::TOKEN_SUBJECT, self::COMPLETION_SUBJECT], true)
            || $body === ''
            || strlen($body) > self::MAX_BODY_BYTES
            || str_contains($body, "\0")
        ) {
            return false;
        }

        $client = null;
        try {
            $client = ($this->clientFactory)();
            foreach (['connect', 'mailFrom', 'rcptTo', 'data', 'disconnect'] as $method) {
                if (!method_exists($client, $method)) {
                    return false;
                }
            }

            if ($client->connect(self::CONNECT_TIMEOUT_SECONDS, false) !== true
                || $client->mailFrom($this->sender) !== true
                || $client->rcptTo($recipient) !== true
            ) {
                return false;
            }

            $headers = implode("\r\n", [
                'From: ' . $this->sender,
                'To: ' . $recipient,
                'Subject: ' . $subject,
                'Date: ' . gmdate('r'),
                'Message-ID: <' . bin2hex(random_bytes(16)) . '@' . self::HELO_HOST . '>',
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
                'Content-Transfer-Encoding: 8bit',
                'Auto-Submitted: auto-generated',
                'X-Auto-Response-Suppress: All',
            ]);

            return $client->data($body, $headers) === true;
        } catch (Throwable $e) {
            // Do not expose SMTP responses, recipient addresses, or message data.
            return false;
        } finally {
            if (is_object($client) && method_exists($client, 'disconnect')) {
                try {
                    $client->disconnect();
                } catch (Throwable $e) {
                    // Submission status was already determined; never expose details.
                }
            }
        }
    }

    private function validAddress(string $value): bool
    {
        return strlen($value) >= 3
            && strlen($value) <= 320
            && strpbrk($value, "\r\n") === false
            && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
}
