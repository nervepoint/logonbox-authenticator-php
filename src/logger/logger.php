<?php
namespace Logger;

use Exception;

interface LoggerService
{
    public function info($message);
    public function error($message, $exception);
    public function enableDebug($debug);
    public function isDebug();
}

class AppLogger implements LoggerService
{

    private $debug = false;

    public function info($message)
    {
        echo $message . PHP_EOL;;
    }

    public function error($message, $exception)
    {
        echo $message . " ". $exception . PHP_EOL;
    }

    public function enableDebug($debug)
    {
        $this->debug = $debug;
    }

    public function isDebug()
    {
        return $this->debug;
    }
}

