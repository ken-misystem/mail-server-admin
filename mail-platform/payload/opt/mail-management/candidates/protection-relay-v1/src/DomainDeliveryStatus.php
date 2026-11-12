<?php
declare(strict_types=1);
namespace MailServer\Management;

final class DomainDeliveryStatus
{
    public function __construct(private readonly string $path='/var/lib/mail-domain-routing-v1/snapshot.json') {}
    public function read(): array
    {
        try {
            $s=@lstat($this->path);
            if (!$s||is_link($this->path)||($s['mode']&0022)!==0||$s['nlink']!==1||$s['size']>1048576) { return []; }
            $raw=@file_get_contents($this->path);
            if (!is_string($raw)) { return []; }
            $data=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
            return is_array($data)&&($data['version']??null)===1&&is_array($data['domains']??null)?$data:[];
        } catch (\Throwable) { return []; }
    }
    public static function describe(array $policy,array $snapshot,int $now): array
    {
        $row=$snapshot['domains'][$policy['name']]??null;
        if (!is_array($row)||!is_int($snapshot['generated_at']??null)||$snapshot['generated_at']>$now
            ||$snapshot['generated_at']<$now-300||($row['revision']??null)!==(string)$policy['revision']
            ||($row['follow_mx']??null)!==((string)$policy['follow_mx']==='1')) {
            return ['state'=>'反映待ち','reason'=>'保存した設定と収集結果の照合待ちです。','checked_at'=>null,'expires_at'=>null];
        }
        if (!is_int($row['checked_at']??null)||!is_int($row['expires_at']??null)||$row['checked_at']>$now||$row['expires_at']<=$now) {
            return ['state'=>'一時保留','reason'=>'判定期限切れです。次回のDNS確認を待っています。','checked_at'=>null,'expires_at'=>null];
        }
        $state=match($row['state']??'') {'internal'=>'内部配送','external'=>'外部MXへ配送',default=>'一時保留'};
        $reason=match($row['reason']??'') {
            'configured_internal'=>'管理者の指定に従い、内部へ配送します。',
            'self_best_mx'=>'最優先MXがこのサーバーです。',
            'external_best_mx'=>'最優先MXが外部サーバーです。',
            'mixed_best_mx','mixed_host_addresses'=>'最優先MXまたは同じMXの接続先に、新旧サーバーが混在しています。',
            'dns_timeout'=>'DNS確認が時間切れです。','dns_failure','address_lookup_failed'=>'DNS確認に失敗しました。',
            'null_mx'=>'DNSにメールを受け付けない指定があります。','no_mx'=>'MXレコードを確認できません。',
            'unsafe_mx_address'=>'MXの接続先が許可されないアドレスです。',
            default=>'DNS判定が成立していません。配送を保留します。',
        };
        return ['state'=>$state,'reason'=>$reason,'checked_at'=>$row['checked_at'],'expires_at'=>$row['expires_at']];
    }

    public static function applied(array $policy,array $snapshot,int $now): array
    {
        if (($snapshot['activation_enabled']??null)!==true) {
            return ['state'=>'反映待ち','reason'=>'配送機能の有効化を確認できません。','checked_at'=>null,'expires_at'=>null];
        }
        if (($snapshot['lookup_healthy']??null)!==true) {
            return ['state'=>'一時保留','reason'=>'配送判定サービスの稼働を確認できません。','checked_at'=>null,'expires_at'=>null];
        }
        return self::describe($policy,$snapshot,$now);
    }
}
