<?php

use Authenticator\AuthenticatorClient;
use Logger\AppLogger;
use RemoteService\RemoteServiceImpl;


require_once __DIR__ . '/../../../vendor/autoload.php';

try {

    $remoteService = new RemoteServiceImpl("some.directory", 443, new AppLogger());
    $authenticatorClient = new AuthenticatorClient($remoteService);
    $authenticatorClient->debug(true);

    $principal = "some@mail.com";

    $response = $authenticatorClient->authenticate($principal);
    $result = $response->verify();

    echo  $result ? "Verified ....." : "Rejected ......" . PHP_EOL;

} catch (Exception $e) {
    echo $e;
}