# logonbox-authenticator-php

An API for using the LogonBox Authenticator from PHP applications

## Usage

**Direct Signing**

If you are using a different protocol and cannot redirect the user via a web browser, or want to provide your own user interface, you can perform authentication exclusively through the API.

```php
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
```

**Server Redirect**

If you are logging a user into a web application, you can create a request, and redirect the user to a URL on the credential server where they are prompted to authorize the request on their device. This eliminates the need for you to create your own user interface and provides a modern, clean authentication flow.

When authentication completes, the server redirects back to your web application with an authentication response which you pass into the API for verification.

**login.php** (This HTML response will ask you to provide id of user whose key will be used for authentication)

```php
<?php
echo '
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
<form method="post" action="start.php">
  <input type="text" name="user" value="" />
  <button type="submit" name="submit">Submit</button>
</form>
</body>
</html>
    ';
```

**start.php** (This file will use user id submitted by end user to start the authentication process, this also sets up redirect url to which authenticating server will redirect to)

```php
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
```

**authenticator-finish.php** (This file will receive the signed response from authenticating server which is verified)

```php
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
```

## Debugging

A simple Logger interface is used that will output using `echo` by default. You can enable this after you have created the client object.

```php
$authenticatorClient->debug(true);
```

This should be sufficient for testing. To integrate logging into your wider application just provide an implementation of `LoggerService` to the `constructor` of `AuthenticatorClient`.

```php
<?php

use Authenticator\AuthenticatorClient;
use Logger\MyAppLogger;
use RemoteService\RemoteServiceImpl;


require_once __DIR__ . '/../../../vendor/autoload.php';

try {

    $remoteService = new RemoteServiceImpl("some.directory", 443, new MyAppLogger());
    $authenticatorClient = new AuthenticatorClient($remoteService);

    // ..... logic TODO
} catch (Exception $e) {
    echo $e;
}
```

## Minimum Requirements

Current stable release tested with `PHP 7.4.3`.