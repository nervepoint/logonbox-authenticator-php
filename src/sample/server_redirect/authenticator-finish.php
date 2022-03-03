<?php

use Authenticator\AuthenticatorClient;
use Authenticator\AuthenticatorRequest;
use Logger\AppLogger;
use RemoteService\RemoteServiceImpl;

require '../../../vendor/autoload.php';

if(session_status() == PHP_SESSION_NONE) {
    session_start();
}

try {
    $response = $_GET["response"];

    $encodedPayload = $_SESSION["encodedPayload"];

    $remoteService = new RemoteServiceImpl("some.directory", 443, new AppLogger());
    $authenticatorClient = new AuthenticatorClient($remoteService);

    $authenticatorRequest = new AuthenticatorRequest($authenticatorClient, $encodedPayload);
    $authenticatorResponse = $authenticatorRequest->processResponse($response);

    echo "The verification result => " . $authenticatorResponse->verify();

} catch (Exception $e) {
    echo $e . PHP_EOL;
}