<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableFeatureObservations implements FeatureObservations
{
    public function status(int $now):array{throw new \RuntimeException('observations_unavailable');}
    public function dns(string $domain,int $now):array{throw new \RuntimeException('observations_unavailable');}
}
