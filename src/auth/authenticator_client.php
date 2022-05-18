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
use RandomGenerator\AppRandomGenerator;
use RandomGenerator\RandomGenerator;
use RemoteService\RemoteService;
use Util\Util;

class AuthenticatorClient
{
    private $logger;
    private $remoteService;
    private $randomGenerator;

    private $remoteName = "LogonBox Authenticator API";
    private $promptText = "{principal} wants to authenticate from {remoteName} using your {hostname} credentials.";
    private $authorizeText = "Authorize";

    /**
     * AuthenticatorClient constructor.
     * @param RemoteService $remoteService
     * @param LoggerService|null $logger
     * @param RandomGenerator|null $randomGenerator
     */
    public function __construct($remoteService, $logger = null, $randomGenerator = null)
    {
        if (empty($logger))
        {
            $this->logger = new AppLogger();
        }
        else
        {
            $this->logger = $logger;
        }

        if (empty($randomGenerator))
        {
            $this->randomGenerator = new AppRandomGenerator();
        }
        else
        {
            $this->randomGenerator = $randomGenerator;
        }

        $this->remoteService = $remoteService;
    }

    /**
     * @return string
     */
    public function getRemoteName()
    {
        return $this->remoteName;
    }

    /**
     * @param string $remoteName
     */
    public function setRemoteName($remoteName)
    {
        $this->remoteName = $remoteName;
    }

    /**
     * @return string
     */
    public function getPromptText()
    {
        return $this->promptText;
    }

    /**
     * @param string $promptText
     */
    public function setPromptText($promptText)
    {
        $this->promptText = $promptText;
    }

    /**
     * @return string
     */
    public function getAuthorizeText()
    {
        return $this->authorizeText;
    }

    /**
     * @param string $authorizeText
     */
    public function setAuthorizeText($authorizeText)
    {
        $this->authorizeText = $authorizeText;
    }

    /**
     * @param bool $debug
     */
    public function debug($debug)
    {
        $this->logger->enableDebug($debug);
    }

    /**
     * @return RemoteService
     */
    public function getRemoteService()
    {
        return $this->remoteService;
    }


    public function getUserKeys($principal)
    {
        try
        {
            $body = $this->remoteService->keys($principal);

            if ($this->logger->isDebug())
            {
                $this->logger->info($body);
            }

            if (strpos($body, "# Authorized") === false) {
                $hostname = $this->remoteService->hostname();
                throw new Exception("Unable to list users authorized keys ${hostname}.");
            }

            $keys = preg_split("/\r\n?|\n/", $body);

            if ($this->logger->isDebug())
            {
                $this->logger->info(implode(",", $keys));
            }

            $filtered = array_filter($keys, function ($item) {
                return substr( trim($item), 0, 1 ) != "#" && strlen(trim($item))  > 0;
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
    function authenticate($principal)
    {
        $payload = $this->randomGenerator->random_bytes(128);
        return $this->authenticateWithPayload($principal, $payload);
    }

    function authenticateWithPayload($principal, $payload)
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
    function processResponse($payload, $signature)
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
    function generateRequest($principal, $redirectURL)
    {
        $key = $this->getDefaultKey($principal);

        if ($key == null)
        {
            throw new Exception("No key found for $principal.");
        }
        $fingerprint = Util::getPublicKeyFingerprint($key);
        $flags = $this->getFlags($key);
        $noise = $this->randomGenerator->random_bytes(16);
        $nonce = $this->randomGenerator->random_bytes(4);

        $request = Strings::packSSH2("sssssN",
            $principal,
            $fingerprint,
            $this->remoteName,
            $this->promptText,
            $this->authorizeText,
            $flags
        );

        $request .= Strings::packSSH2("CCCC", ...unpack("C*",$nonce));

        $request .= Strings::packSSH2("s", $redirectURL);

        $request .= Strings::packSSH2("CCCCCCCCCCCCCCCC", ...unpack("C*",$noise));

        $encoded = Util::base64url_encode($request);

        return new AuthenticatorRequest($this, $encoded);
    }

    function getDefaultKey($principal)
    {
        $keys = $this->getUserKeys($principal);

        if (count($keys) == 0)
        {
            return null;
        }

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
    function getUserKey($principal, $fingerprint)
    {
        $hash = strtolower(substr( trim($fingerprint), 0, 6));

        if ($hash != "sha256")
        {
            throw new Exception("Fingerprint in sha256 supported.");
        }

        $keys = $this->getUserKeys($principal);

        if (count($keys) == 0)
        {
            return null;
        }

        $key = array_filter($keys, function ($item) use ($fingerprint) {
            return Util::getPublicKeyFingerprint($item) == $fingerprint;
        });

        if (count($key) == 0)
        {
            return null;
        }

        return array_pop($key);
    }

    function getFlags($key)
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
    private function signPayload($principal, $key, $text, $buttonText,
                                 $payload)
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
    private function requestSignature($principal, $fingerprint, $text, $buttonText,
                                      $encodedPayload, $flags)
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

            $success = Strings::unpackSSH2("bs", $data);

            if (!$success[0])
            {
                throw new Exception("The server did not respond with a valid response!");
            }

        }

        return Util::base64url_decode($signature);
    }

    private function replaceVariables($promptText, $principal)
    {
        $rp = str_replace("{principal}", $principal, $promptText);
        $rrn = str_replace("{remoteName}", $this->remoteName, $rp);
        $text=  str_replace("{hostname}", $this->remoteService->hostname(), $rrn);

        if ($this->logger->isDebug())
        {
                $this->logger->info("The replacement text found as " . $text);
        }

        return $text;
    }
}
