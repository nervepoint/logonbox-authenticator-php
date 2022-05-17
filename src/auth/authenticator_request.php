<?php

namespace Authenticator;

use Exception;
use Util\Util;

class AuthenticatorRequest
{
    private $authenticatorClient;
    private $encodedPayload;

    /**
     * AuthenticatorRequest constructor.
     * @param AuthenticatorClient $authenticatorClient
     * @param string $encodedPayload
     */
    public function __construct($authenticatorClient, $encodedPayload)
    {
        $this->authenticatorClient = $authenticatorClient;
        $this->encodedPayload = $encodedPayload;
    }

    /**
     * @return AuthenticatorClient
     */
    public function getAuthenticatorClient()
    {
        return $this->authenticatorClient;
    }

    /**
     * @return string
     */
    public function getEncodedPayload()
    {
        return $this->encodedPayload;
    }


    /**
     * @throws Exception
     */
    function processResponse($response)
    {
        $payload = Util::base64url_decode($this->encodedPayload);
        $signature = Util::base64url_decode($response);

        return $this->authenticatorClient->processResponse($payload, $signature);
    }

    function getSignUrl()
    {
        return $this->authenticatorClient->getRemoteService()->getSignUrl($this->encodedPayload);
    }
}