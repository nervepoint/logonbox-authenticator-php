<?php

namespace RemoteService;

use Authenticator\SignatureResponse;
use Httpful\Exception\ConnectionErrorException;
use Httpful\Mime;
use Httpful\Request;
use Logger\AppLogger;
use Logger\LoggerService;


interface RemoteService
{
    public function keys($principal);
    public function signPayload($principal, $remoteName, $fingerprint, $text,
            $buttonText, $encodedPayload, $flags);
    public function getSignUrl($encodedPayload);
    public function hostname();
    public function port();
}

class RemoteServiceImpl implements RemoteService
{
    private $hostname;
    private $port;
    private $logger;

    /**
     * RemoteServiceImpl constructor.
     * @param string $hostname
     * @param int $port
     * @param LoggerService|null $logger
     */
    public function __construct(string $hostname, $port = 443, $logger = null)
    {
        $this->hostname = $hostname;
        $this->port = $port;
        if (empty($logger))
        {
            $this->logger = new AppLogger();
        }
        else
        {
            $this->logger = $logger;
        }

    }

    /**
     * @return string
     */
    public function hostname()
    {
        return $this->hostname;
    }

    /**
     * @return int
     */
    public function port()
    {
        return $this->port;
    }

    /**
     * @return AppLogger|LoggerService
     */
    public function logger()
    {
        return $this->logger;
    }

    /**
     * @throws ConnectionErrorException
     */
    public function keys($principal)
    {
        $url = "https://" . $this->hostname() . ":" . $this->port() . "/app/api/authenticator/keys/" . $principal;
        $response = Request::get($url)->expectsText()->send();
        return $response->body;
    }

    /**
     * @throws ConnectionErrorException
     */
    public function signPayload($principal, $remoteName, $fingerprint, $text,
                                $buttonText, $encodedPayload, $flags)
    {
        $url = "https://" . $this->hostname() . ":" . $this->port() . "/app/api/authenticator/signPayload";

        $payload = array(
            "username" => $principal,
            "fingerprint" => $fingerprint,
            "remoteName" => $remoteName,
            "text" => $text,
            "authorizeText" => $buttonText,
            "flags" => $flags,
            "payload" => $encodedPayload
        );

        $response = Request::post($url, $payload, Mime::FORM)
                        ->expectsJson()
                        ->send();

        $json = $response->body;

        return new SignatureResponse($json->success, $json->message, $json->signature, $json->response);
    }

    public function getSignUrl($encodedPayload)
    {
        return "https://" . $this->hostname() . ":" . $this->port() . "/authenticator/sign/" . $encodedPayload;
    }

    public function __toString()
    {
        return $this->hostname() . " " . $this->port();
    }
}