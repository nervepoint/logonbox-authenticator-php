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
    public function keys(string $principal);
    public function signPayload(string $principal, string $remoteName, string $fingerprint, string $text,
            string $buttonText, string $encodedPayload, int $flags): SignatureResponse;
    public function getSignUrl(string $encodedPayload): string;
    public function hostname(): string;
    public function port(): int;
}

class RemoteServiceImpl implements RemoteService
{
    private string $hostname;
    private int $port;
    private LoggerService $logger;

    /**
     * RemoteServiceImpl constructor.
     * @param string $hostname
     * @param int $port
     * @param LoggerService|null $logger
     */
    public function __construct(string $hostname, int $port = 443, LoggerService $logger = null)
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
    public function hostname(): string
    {
        return $this->hostname;
    }

    /**
     * @return int
     */
    public function port(): int
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
    public function keys(string $principal)
    {
        $url = "https://" . $this->hostname() . ":" . $this->port() . "/app/api/authenticator/keys/" . $principal;
        $response = Request::get($url)->expectsText()->send();
        return $response->body;
    }

    /**
     * @throws ConnectionErrorException
     */
    public function signPayload(string $principal, string $remoteName, string $fingerprint, string $text,
                                string $buttonText, string $encodedPayload, int $flags): SignatureResponse
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

    public function getSignUrl(string $encodedPayload): string
    {
        return "https://" . $this->hostname() . ":" . $this->port() . "/authenticator/sign/" . $encodedPayload;
    }

    public function __toString()
    {
        return $this->hostname() . " " . $this->port();
    }
}