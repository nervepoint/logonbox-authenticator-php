<?php

namespace RandomGenerator;

use Exception;

interface RandomGenerator
{
    function random_bytes ($length);
}

class AppRandomGenerator implements RandomGenerator
{

    /**
     * @throws Exception
     */
    function random_bytes($length)
    {
        return random_bytes($length);
    }
}