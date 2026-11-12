<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnixOwnerStatusStore implements OwnerStatusStore
{
    public function __construct(private readonly FeatureControlClient $client=new FeatureControlClient()){}
    public function browse(array $filters):array{return $this->client->call(['operation'=>'owner.browse','filters'=>$filters]);}
    public function stop(array $request):array{return $this->client->call(['operation'=>'owner.stop','request'=>$request]);}
}
