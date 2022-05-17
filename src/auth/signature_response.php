<?php

namespace Authenticator;

class SignatureResponse
{
    private $success;
    private $message;
    private $signature;
    private $response;

    /**
     * SignatureResponse constructor.
     * @param bool $success
     * @param string $message
     * @param string $signature
     * @param string $response
     */
    public function __construct($success, $message, $signature, $response)
    {
        $this->success = $success;
        $this->message = $message;
        $this->signature = $signature;
        $this->response = $response;
    }

    /**
     * @return bool
     */
    public function isSuccess()
    {
        return $this->success;
    }

    /**
     * @param bool $success
     */
    public function setSuccess($success)
    {
        $this->success = $success;
    }

    /**
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * @param string $message
     */
    public function setMessage($message)
    {
        $this->message = $message;
    }

    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @param string $signature
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    /**
     * @return string
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @param string $response
     */
    public function setResponse($response)
    {
        $this->response = $response;
    }

    public function __toString()
    {
        return $this->success . " " . $this->message . " " . $this->signature . " " . $this->response;
    }

}