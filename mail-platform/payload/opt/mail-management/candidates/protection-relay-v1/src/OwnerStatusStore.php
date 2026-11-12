<?php
declare(strict_types=1);
namespace MailServer\Management;
interface OwnerStatusStore { public function browse(array $filters):array; public function stop(array $request):array; }
