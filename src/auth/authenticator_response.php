<?php

namespace Authenticator;

use Exception;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

class AuthenticatorResponse
{
    private string $payload;
    private string $signature;
    private PublicKey $key;
    private int $flags;

    /**
     * AuthenticatorResponse constructor.
     * @param string $payload
     * @param string|null $signature
     * @param PublicKey|null $key
     * @param int $flags
     */
    public function __construct(string $payload, ?string $signature, ?PublicKey $key, int $flags)
    {
        $this->payload = $payload;
        if (!empty($signature)) {
            $this->signature = $signature;
        }
        if (!empty($key)) {
            $this->key = $key;
        }
        $this->flags = $flags;
    }


    /**
     * @return string
     */
    public function getPayload(): string
    {
        return $this->payload;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return PublicKey
     */
    public function getKey(): PublicKey
    {
        return $this->key;
    }

    /**
     * @return int
     */
    public function getFlags(): int
    {
        return $this->flags;
    }

    /**
     * @throws Exception
     */
    public function verify(): bool
    {
        if (empty($this->signature))
        {
            return false;
        }

        if ($this->key instanceof RSA)
        {
            $hash = "sha256";

            if ($this->flags == 4)
            {
                $hash = "sha512";
            }

            $local = $this->key->withPadding(RSA::SIGNATURE_PKCS1)->withHash($hash);
            /** @noinspection PhpPossiblePolymorphicInvocationInspection */
            return $local->verify($this->payload, $this->signature);
        }
        elseif ($this->key instanceof EC)
        {
            $local = $this->key->withHash("sha512");
            /** @noinspection PhpPossiblePolymorphicInvocationInspection */
            return $local->verify($this->payload, $this->signature);
        }

        return $this->key->verify($this->payload, $this->signature);

    }

}