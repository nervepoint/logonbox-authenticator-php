<?php

use Authenticator\AuthenticatorClient;
use Logger\AppLogger;
use RemoteService\RemoteServiceImpl;

require '../../../vendor/autoload.php';

if(session_status() == PHP_SESSION_NONE) {
    session_start();
}

try {

    $remoteService = new RemoteServiceImpl("some.directory", 443, new AppLogger());
    $authenticatorClient = new AuthenticatorClient($remoteService);

    $user = $_POST["user"];

    $authenticatorRequest = $authenticatorClient
        ->generateRequest($user, "http://localhost/src/sample/server_redirect/authenticator-finish.php?response={response}");

    $_SESSION["encodedPayload"] = $authenticatorRequest->getEncodedPayload();

    header("Location: " . $authenticatorRequest->getSignUrl(), true, 302);
} catch (Exception $e) {
    echo $e;
}