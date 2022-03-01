<?php
namespace Logger;

use Exception;

interface LoggerService
{
    public function info(string $message);
    public function error(string $message, Exception $exception);
    public function enableDebug(bool $debug);
    public function isDebug(): bool;
}

class AppLogger implements LoggerService
{

    private bool $debug = false;

    public function info(string $message)
    {
        echo $message . PHP_EOL;;
    }

    public function error(string $message, Exception $exception)
    {
        echo $message . " ". $exception . PHP_EOL;
    }

    public function enableDebug(bool $debug)
    {
        $this->debug = $debug;
    }

    public function isDebug(): bool
    {
        return $this->debug;
    }
}

