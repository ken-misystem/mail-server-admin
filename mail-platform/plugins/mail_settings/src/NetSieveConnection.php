<?php
declare(strict_types=1);
namespace MiSystem\MailSettings;

/** Keep authentication on the configured, verified loopback endpoint. */
final class FixedEndpointSieve extends \Net_Sieve
{
    public function _handleConnectAndLogin()
    {
        return new \PEAR_Error('referral_denied');
    }
}

/** SPDX-License-Identifier: MIT. Calls the separately installed Net_Sieve API. */
final class NetSieveConnection implements ScriptSetConnection
{
    private \Net_Sieve $client;

    public function __construct(string $owner, #[\SensitiveParameter] string $password, string $peer)
    {
        if (!filter_var($owner, FILTER_VALIDATE_EMAIL) || $password === '' || strlen($password) > 4096
            || !preg_match('/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/D', $peer)) throw new \DomainException('not_authorized');
        $this->client = new FixedEndpointSieve();
        $options = ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true,
            'allow_self_signed' => false, 'peer_name' => $peer, 'SNI_enabled' => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLS_CLIENT]];
        $this->ok($this->client->connect('127.0.0.1', 4190, $options, false));
        $this->ok($this->client->_sock->setTimeout(5));
        // Net_Sieve's optional STARTTLS is insufficient. Require it before LOGIN.
        $this->ok($this->client->_startTLS());
        $this->ok($this->client->login($owner, $password, 'PLAIN'));
    }

    private function ok(mixed $result): mixed
    {
        if ($result instanceof \PEAR_Error || $result === false) throw new \DomainException('sieve_unavailable');
        return $result;
    }

    public function scripts(): array
    {
        $active = null;
        $names = $this->ok($this->client->listScripts($active));
        if (!is_array($names) || count($names) > 256 || ($active !== null && !in_array($active, $names, true))) {
            throw new \DomainException('sieve_unavailable');
        }
        $extensions = $this->ok($this->client->getExtensions());
        if (!is_array($extensions)) throw new \DomainException('sieve_unavailable');
        $extensions = array_map('strtolower', $extensions);
        return ['names' => $names, 'active' => $active, 'extensions' => $extensions];
    }

    public function read(string $name): string
    {
        $source = $this->ok($this->client->getScript($name));
        // Net_Sieve reads the literal length plus the protocol's final CRLF.
        if (!is_string($source) || !str_ends_with($source, "\r\n")) throw new \DomainException('sieve_unavailable');
        return substr($source, 0, -2);
    }

    public function put(string $name, string $source): void
    {
        try { $this->ok($this->client->installScript($name, $source, false)); }
        catch (\Throwable) { throw new \DomainException('save_unverified'); }
    }

    public function activate(string $name): void
    {
        try { $this->ok($this->client->setActive($name)); }
        catch (\Throwable) { throw new \DomainException('save_unverified'); }
    }

    public function delete(string $name): void
    {
        try { $this->ok($this->client->removeScript($name)); }
        catch (\Throwable) { throw new \DomainException('save_unverified'); }
    }

    public function rename(string $oldName, string $newName): void
    {
        try {
            $this->ok($this->client->_doCmd('RENAMESCRIPT ' . $this->client->_escape($oldName) . ' ' . $this->client->_escape($newName)));
        } catch (\Throwable) { throw new \DomainException('save_unverified'); }
    }

    public function __destruct()
    {
        if (isset($this->client)) $this->client->disconnect(false);
    }
}
