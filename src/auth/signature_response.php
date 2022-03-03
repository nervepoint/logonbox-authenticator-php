<?php

namespace Authenticator;

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