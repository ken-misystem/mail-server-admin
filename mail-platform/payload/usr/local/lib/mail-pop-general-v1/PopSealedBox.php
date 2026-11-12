<?php
declare(strict_types=1);
namespace MailServer\Pop;

/** Native libsodium sealed boxes; Web gets public key only, future worker gets private keypair. */
final class PopSealedBox
{
    public static function seal(#[\SensitiveParameter] string $password,string $publicKey):string
    {
        PopSourcePolicy::password($password);
        if(strlen($publicKey)!==SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)throw new \DomainException('pop_key_unavailable');
        try {return sodium_crypto_box_seal($password,$publicKey);}
        catch(\SodiumException){throw new \DomainException('pop_secret_unavailable');}
    }
    /** Worker-only caller; never expose this output through a UI, error, log or argv. */
    public static function open(string $ciphertext,#[\SensitiveParameter] string $keypair):string
    {
        if(strlen($keypair)!==SODIUM_CRYPTO_BOX_KEYPAIRBYTES || strlen($ciphertext)<SODIUM_CRYPTO_BOX_SEALBYTES) {
            throw new \DomainException('pop_secret_unavailable');
        }
        try {$plain=sodium_crypto_box_seal_open($ciphertext,$keypair);}
        catch(\SodiumException){throw new \DomainException('pop_secret_unavailable');}
        if($plain===false)throw new \DomainException('pop_secret_unavailable');
        return PopSourcePolicy::password($plain);
    }
}
