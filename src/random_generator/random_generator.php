<?php

namespace RandomGenerator;

use Exception;

interface RandomGenerator
{
    function random_bytes (int $length): string;
}

class AppRandomGenerator implements RandomGenerator
{

    /**
     * @throws Exception
     */
    function random_bytes(int $length): string
    {
        return random_bytes($length);
    }
}