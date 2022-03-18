<?php

use Authenticator\AuthenticatorClient;
use RemoteService\RemoteServiceImpl;


require_once __DIR__ . '/../../../vendor/autoload.php';

try {

    $remoteService = new RemoteServiceImpl("some.directory");
    $authenticatorClient = new AuthenticatorClient($remoteService);
    $authenticatorClient->debug(true);

    $principal = "user@user.com";

    $response = $authenticatorClient->authenticate($principal);
    $result = $response->verify();

    echo  $result ? "Verified ....." : "Rejected ......" . PHP_EOL;

} catch (Exception $e) {
    echo $e;
}
