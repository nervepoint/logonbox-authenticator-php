<?php

namespace Authenticator;

use Exception;
use Logger\LoggerService;
use Logger\AppLogger;
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use RemoteService\RemoteService;

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
        if ($logger == null)
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

    public function debug(bool $debug)
    {
        $this->logger->enableDebug($debug);
    }

    public function getUserKeys(string $principal)
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
    function authenticate(string $principal)
    {
        $payload = random_bytes(128);
        $payloadBytes = unpack("C*", $payload);
        $this->authenticateWithPayload($principal, $payloadBytes);
    }

    function authenticateWithPayload(string $principal, array $payload)
    {
        $sshKeys = $this->getUserKeys($principal);
        $length = count($sshKeys);
        for ($i = 0; $i < $length; ++$i)
        {
            try
            {
                $sshKey = $sshKeys[$i];
            }
            catch (Exception $e)
            {

            }
        }
    }

    /**
     * @throws Exception
     */
    private function signPayload(string $principal, AsymmetricKey $key, string $text, string $buttonText,
                                 array $payload)
    {
        $fingerprint = Util::getPublicKeyFingerprint($key);

        if ($this->debug())
        {
            $this->logger->info("Key fingerprint is " . $fingerprint);
        }

        $encodedPayload = Util::base64url_encode($payload);

        $flags = 0;

        if ($key instanceof RSA)
        {
            $flags = 4;
        }

        $sig = $this->requestSignature($principal, $fingerprint, $text, $buttonText, $encodedPayload, $flags);

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
            $this->logger->info(strval($body));
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

            if (!$success)
            {
                throw new Exception("The server did not respond with a valid response!");
            }

        }

        return Util::base64url_decode($signature);
    }

}

class SignatureResponse
{
    private bool $success;
    private string $message;
    private string $signature;
    private string $response;

    /**
     * SignatureResponse constructor.
     * @param bool $success
     * @param string $message
     * @param string $signature
     * @param string $response
     */
    public function __construct(bool $success, string $message, string $signature, string $response)
    {
        $this->success = $success;
        $this->message = $message;
        $this->signature = $signature;
        $this->response = $response;
    }

    /**
     * @return bool
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * @param bool $success
     */
    public function setSuccess(bool $success): void
    {
        $this->success = $success;
    }

    /**
     * @return string
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * @param string $message
     */
    public function setMessage(string $message): void
    {
        $this->message = $message;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @param string $signature
     */
    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    /**
     * @return string
     */
    public function getResponse(): string
    {
        return $this->response;
    }

    /**
     * @param string $response
     */
    public function setResponse(string $response): void
    {
        $this->response = $response;
    }

    public function __toString()
    {
        return $this->success . " " . $this->message . " " . $this->signature . " " . $this->response;
    }

}

class AuthenticatorResponse
{

}

class Util
{
    /**
     * Encode data to Base64URL
     * @param string $data
     * @return boolean|string
     */
    static function base64url_encode($data)
    {
        // First of all you should encode $data to Base64 string
        $b64 = base64_encode($data);

        // Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
        if ($b64 === false) {
            return false;
        }

        // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
        $url = strtr($b64, '+/', '-_');

        // Remove padding character from the end of line and return the Base64URL result
        return rtrim($url, '=');
    }

    /**
     * Decode data from Base64URL
     * @param string $data
     * @param boolean $strict
     * @return boolean|string
     */
    static function base64url_decode($data, $strict = false)
    {
        // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
        $b64 = strtr($data, '-_', '+/');

        // Decode Base64 string and return the original data
        return base64_decode($b64, $strict);
    }

    static function getPublicKeyFingerprint($key)
    {
        return "SHA256:" . $key->getFingerprint("sha256");
    }
}