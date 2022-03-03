<?php

namespace Authenticator;

use Exception;
use Util\Util;

class AuthenticatorRequest
{
    private AuthenticatorClient $authenticatorClient;
    private string $encodedPayload;

    /**
     * AuthenticatorRequest constructor.
     * @param AuthenticatorClient $authenticatorClient
     * @param string $encodedPayload
     */
    public function __construct(AuthenticatorClient $authenticatorClient, string $encodedPayload)
    {
        $this->authenticatorClient = $authenticatorClient;
        $this->encodedPayload = $encodedPayload;
    }

    /**
     * @return AuthenticatorClient
     */
    public function getAuthenticatorClient(): AuthenticatorClient
    {
        return $this->authenticatorClient;
    }

    /**
     * @return string
     */
    public function getEncodedPayload(): string
    {
        return $this->encodedPayload;
    }


    /**
     * @throws Exception
     */
    function processResponse(string $response): AuthenticatorResponse
    {
        $payload = Util::base64url_decode($this->encodedPayload);
        $signature = Util::base64url_decode($response);

        return $this->authenticatorClient->processResponse($payload, $signature);
    }

    function getSignUrl() : string
    {
        return $this->authenticatorClient->getRemoteService()->getSignUrl($this->encodedPayload);
    }
}