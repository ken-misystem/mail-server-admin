<?php
declare(strict_types=1);
namespace MailServer\Management;

final class UnixProtectionStore implements ProtectionStore
{
    public function __construct(private readonly FeatureControlClient $client) {}

    public function read(AdminUser $actor, string $kind): array
    {
        $reply = $this->client->call([
            'operation' => 'protection.read', 'actor' => $actor->id, 'epoch' => $actor->epoch, 'kind' => $kind,
        ]);
        if (($reply['kind'] ?? null) !== $kind || !is_int($reply['revision'] ?? null)
            || $reply['revision'] < 0 || !is_array($reply['payload'] ?? null)
            || !is_bool($reply['credential_present'] ?? null) || !is_int($reply['applied_revision'] ?? null)
            || $reply['applied_revision'] < 0 || $reply['applied_revision'] > $reply['revision']
            || !in_array($reply['phase'] ?? null, ['applied','pending','applying','failed','unknown'], true)) {
            throw new \RuntimeException('protection_response');
        }
        return array_intersect_key($reply, array_flip([
            'kind','revision','payload','credential_present','applied_revision','phase','failure_code',
        ]));
    }

    public function save(AdminUser $actor, string $kind, int $revision, array $payload, #[\SensitiveParameter] array $credential, string $requestId): array
    {
        return $this->client->call([
            'operation' => 'protection.save', 'actor' => $actor->id, 'epoch' => $actor->epoch,
            'kind' => $kind, 'revision' => $revision, 'payload' => $payload,
            'credential' => $credential, 'request_id' => $requestId,
        ]);
    }
}
