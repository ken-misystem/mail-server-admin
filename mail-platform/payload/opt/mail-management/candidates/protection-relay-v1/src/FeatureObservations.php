<?php
declare(strict_types=1);
namespace MailServer\Management;
interface FeatureObservations
{
    public function status(int $now):array;
    public function dns(string $domain,int $now):array;
}
