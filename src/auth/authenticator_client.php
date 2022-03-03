<?php

namespace Authenticator;

use ArrayObject;
use Exception;
use Logger\AppLogger;
use Logger\LoggerService;
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use RemoteService\RemoteService;
use Util\Util;

class AuthenticatorClient
{
    private LoggerService $logger;
    private RemoteService $remoteService;

    private string $remoteName = "LogonBox Authenticator API";
    private string $promptText = "{principal} wants to authenticate from {remoteName} using your {hostname} credentials.";
    private string $authorizeText = "Authorize";

    /**
     * AuthenticatorClient constructor.
     * @param RemoteService $remoteService
     * @param LoggerService|null $logger
     */
    public function __construct(RemoteService $remoteService, LoggerService $logger = null)
    {
        if (empty($logger))
        {
            $this->logger = new AppLogger();
        }
        else
        {
            $this->logger = $logger;
        }

        $this->remoteService = $remoteService;
    }

    /**
     * @return string
     */
    public function getRemoteName(): string
    {
        return $this->remoteName;
    }

    /**
     * @param string $remoteName
     */
    public function setRemoteName(string $remoteName): void
    {
        $this->remoteName = $remoteName;
    }

    /**
     * @return string
     */
    public function getPromptText(): string
    {
        return $this->promptText;
    }

    /**
     * @param string $promptText
     */
    public function setPromptText(string $promptText): void
    {
        $this->promptText = $promptText;
    }

    /**
     * @return string
     */
    public function getAuthorizeText(): string
    {
        return $this->authorizeText;
    }

    /**
     * @param string $authorizeText
     */
    public function setAuthorizeText(string $authorizeText): void
    {
        $this->authorizeText = $authorizeText;
    }

    /**
     * @param bool $debug
     */
    public function debug(bool $debug)
    {
        $this->logger->enableDebug($debug);
    }

    /**
     * @return RemoteService
     */
    public function getRemoteService(): RemoteService
    {
        return $this->remoteService;
    }


    public function getUserKeys(string $principal): array
    {
        try
        {
            $body = $this->remoteService->keys($principal);

            if ($this->logger->isDebug())
            {
                $this->logger->info($body);
            }

            $keys = preg_split("/\r\n?|\n/", $body);

            if ($this->logger->isDebug())
            {
                $this->logger->info(implode(",", $keys));
            }

            $filtered = array_filter($keys, function ($item) {
                return substr( trim($item), 0, 1 ) != "#";
            });

            return array_map(function ($item) {

                if ($this->logger->isDebug())
                {
                    $this->logger->info("Parsing key " . $item);
                }

                $ssh = PublicKeyLoader::load($item);

                if ($this->logger->isDebug())
                {
                    $this->logger->info("Decoded " . $ssh->getHash() . " public key.");
                }

                return $ssh;
            }, $filtered);
        }
        catch (Exception $e)
        {
            $this->logger->error("Problem in fetching keys.", $e);
        }

        return array();
    }

    /**
     * @throws Exception
     */
    function authenticate(string $principal): AuthenticatorResponse
    {
        $payload = random_bytes(128);
        return $this->authenticateWithPayload($principal, $payload);
    }

    function authenticateWithPayload(string $principal, string $payload): AuthenticatorResponse
    {
        $keys = $this->getUserKeys($principal);

        $obj = new ArrayObject( $keys );
        $it = $obj->getIterator();

        while ($it->valid())
        {
            try
            {
                $key = $it->current();
                $it->next();
                return $this->signPayload($principal, $key,
                    $this->replaceVariables($this->promptText, $principal),
                    $this->authorizeText, $payload);
            }
            catch (Exception $e)
            {
                $this->logger->error("Problem in signing payload.", $e);
            }
        }

        return new AuthenticatorResponse($payload, null, null, 0);

    }

    /**
     * @throws Exception
     */
    function processResponse(string $payload, string $signature) : AuthenticatorResponse
    {
        $success = Strings::unpackSSH2("b", $signature);

        if ($success[0])
        {
            $buffer = Strings::unpackSSH2("ssNs", $signature);
            $username = $buffer[0];
            $fingerprint = $buffer[1];
            $flags = $buffer[2];
            $signature = $buffer[3];

            $key = $this->getUserKey($username, $fingerprint);

            return new AuthenticatorResponse($payload, $signature, $key, $flags);
        }
        else
        {
            $buffer = Strings::unpackSSH2("s", $signature);
            $message = $buffer[0];

            throw new Exception($message);
        }
    }

    /**
     * @throws Exception
     */
    function generateRequest(string $principal, string $redirectURL): AuthenticatorRequest
    {
        $key = $this->getDefaultKey($principal);
        $fingerprint = Util::getPublicKeyFingerprint($key);
        $flags = $this->getFlags($key);
        $noise = random_bytes(16);
        $nonce = random_int(PHP_INT_MIN, PHP_INT_MAX);

        $request = Strings::packSSH2("sssssNNs",
            $principal,
            $fingerprint,
            $this->remoteName,
            $this->promptText,
            $this->authorizeText,
            $flags,
            $nonce,
            $redirectURL
        );

        $request .= Strings::packSSH2("CCCCCCCCCCCCCCCC", ...unpack("C*",$noise));

        $encoded = Util::base64url_encode($request);

        return new AuthenticatorRequest($this, $encoded);
    }

    function getDefaultKey(string $principal) : ?PublicKey
    {
        $keys = $this->getUserKeys($principal);

        $defaultKey = array_filter($keys, function ($item) {
            return !($item instanceof RSA);
        });

        if (count($defaultKey) == 0)
        {
            $defaultKey = array_filter($keys, function ($item) {
                return $item instanceof RSA;
            });
        }

        if (count($defaultKey) == 0)
        {
            return null;
        }

        return array_pop($defaultKey);
    }

    /**
     * @throws Exception
     */
    function getUserKey(string $principal, string $fingerprint) : ?PublicKey
    {
        $hash = strtolower(substr( trim($fingerprint), 0, 6));

        if ($hash != "sha256")
        {
            throw new Exception("Fingerprint in sha256 supported.");
        }

        $keys = $this->getUserKeys($principal);

        $key = array_filter($keys, function ($item) use ($fingerprint) {
            return Util::getPublicKeyFingerprint($item) == $fingerprint;
        });

        if (count($key) == 0)
        {
            return null;
        }

        return array_pop($key);
    }

    function getFlags(PublicKey $key): int
    {
        if ($key instanceof RSA)
        {
            return 4;
        }

        return 0;
    }

    /**
     * @throws Exception
     */
    private function signPayload(string $principal, PublicKey $key, string $text, string $buttonText,
                                 string $payload): AuthenticatorResponse
    {
        $fingerprint = Util::getPublicKeyFingerprint($key);

        if ($this->logger->isDebug())
        {
            $this->logger->info("Key fingerprint is " . $fingerprint);
        }

        $encodedPayload = Util::base64url_encode($payload);

        $flags = 0;

        if ($key instanceof RSA)
        {
            $flags = 4;
        }

        $signature = $this->requestSignature($principal, $fingerprint, $text, $buttonText, $encodedPayload, $flags);

        return new AuthenticatorResponse($payload, $signature, $key, $flags);
    }

    /**
     * @throws Exception
     */
    private function requestSignature(string $principal, string $fingerprint, string $text, string $buttonText,
                                      string $encodedPayload, int $flags)
    {
        $body = $this->remoteService->signPayload($principal, $this->remoteName, $fingerprint,
            $text, $buttonText, $encodedPayload, $flags);

        if ($this->logger->isDebug())
        {
            $this->logger->info("The response is " . strval($body));
        }

        $success = $body->isSuccess();
        $message = $body->getMessage();
        $signature = $body->getSignature();
        $response = $body->getResponse();

        if (!$success)
        {
            throw new Exception($message);
        }

        if (trim($signature) == "")
        {
            $data = Util::base64url_decode($response);

            $success = Strings::unpackSSH2("b", $data);

            if (!$success[0])
            {
                throw new Exception("The server did not respond with a valid response!");
            }

        }

        return Util::base64url_decode($signature);
    }

    private function replaceVariables(string $promptText, string $principal)
    {
        $rp = str_replace("{principal}", $principal, $promptText);
        $rrn = str_replace("{remoteName}", $this->remoteName, $rp);
        return str_replace("{hostname}", $this->remoteService->hostname(), $rrn);
    }
}