<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnixQueueAdminStore implements QueueAdminStore
{
    public function __construct(private readonly FeatureControlClient $client = new FeatureControlClient()) {}
    public function browse(array $filters): array { return $this->client->call(['operation' => 'queue.browse', 'filters' => $filters]); }
    public function apply(array $request): array { return $this->client->call(['operation' => 'queue.apply', 'request' => $request]); }
}
