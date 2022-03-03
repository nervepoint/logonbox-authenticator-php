<?php

namespace Authenticator;

use Exception;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use PHPUnit\Framework\TestCase;
use RemoteService\RemoteService;
use Util\Util;

class AuthenticatorClientTest extends TestCase
{

    private static PrivateKey $privateKey;
    private static PublicKey $publicKey;
    private static string $sshPublicKeyInOpenSsh;

    /**
     * @beforeClass
     */
    static function setUpTestingKeys()
    {
        AuthenticatorClientTest::$privateKey = EC::createKey('Ed25519');
        AuthenticatorClientTest::$publicKey = AuthenticatorClientTest::$privateKey->getPublicKey();
        AuthenticatorClientTest::$sshPublicKeyInOpenSsh = AuthenticatorClientTest::$publicKey->toString("OpenSSH");
    }

    private function sshKeysFormatted(string $principal): string
    {
        $key = AuthenticatorClientTest::$sshPublicKeyInOpenSsh;
        return "# Testing keys for principal ${principal} ........." . PHP_EOL . "${key}";
    }

    function testShouldFetchListOfSshKeys()
    {

        $principal = "some.user@directory.com";
        // Create a mock for the RemoteService class,
        $remoteService = $this->createMock(RemoteService::class);

        // Set up the expectation for the keys method
        // to be called only once and with the string value for variable $principal
        // as its parameter and return list of open ssh keys.
        $remoteService->expects($this->once())
            ->method("keys")
            ->with($this->equalTo($principal))
            ->willReturn($this->sshKeysFormatted($principal));

        $authenticatorClient = new AuthenticatorClient($remoteService);
        $authenticatorClient->debug(true);

        $keys = $authenticatorClient->getUserKeys($principal);

        $this->assertCount(1, $keys);

        $keyFingerPrint = Util::getPublicKeyFingerprint(array_pop($keys));
        $toCompareSshKeyFingerprint = Util::getPublicKeyFingerprint(AuthenticatorClientTest::$publicKey);

        $this->assertEquals($keyFingerPrint, $toCompareSshKeyFingerprint);
    }

    /**
     * @throws Exception
     */
    function testItShouldSignPayload()
    {
        $payload = random_bytes(128);

        $principal = "some.user@directory.com";
        // Create a mock for the RemoteService class,
        $remoteService = $this->createMock(RemoteService::class);

        // Set up the expectation for the keys method
        // to be called only once and with the string value for variable $principal
        // as its parameter and return list of open ssh keys.
        $remoteService->expects($this->once())
            ->method("keys")
            ->with($this->equalTo($principal))
            ->willReturn($this->sshKeysFormatted($principal));

        $remoteService->method("hostname")
            ->willReturn("some.directory.org");

        $remoteService->method("port")
            ->willReturn(443);

        $remoteService->expects($this->once())
            ->method("signPayload")
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturnCallback(function () use ($payload) {
                $signature = Util::base64url_encode(AuthenticatorClientTest::$privateKey->withSignatureFormat('ASN1')->sign($payload));
                return (new SignatureResponse(true, "", $signature, ""));
            });


        $authenticatorClient = new AuthenticatorClient($remoteService);
        $authenticatorClient->debug(true);

        $response = $authenticatorClient->authenticateWithPayload($principal, $payload);
        $verify = $response->verify();
        $this->assertTrue($verify);

    }

    /**
     * @throws Exception
     */
    function testItShouldThrowErrorIfRemoteResponseDoesNotReturnSignature()
    {
        $principal = "some.user@directory.com";
        // Create a mock for the RemoteService class,
        $remoteService = $this->createMock(RemoteService::class);

        // Set up the expectation for the keys method
        // to be called only once and with the string value for variable $principal
        // as its parameter and return list of open ssh keys.
        $remoteService->expects($this->once())
            ->method("keys")
            ->with($this->equalTo($principal))
            ->willReturn($this->sshKeysFormatted($principal));

        $remoteService->method("hostname")
            ->willReturn("some.directory.org");

        $remoteService->method("port")
            ->willReturn(443);

        $remoteService->expects($this->once())
            ->method("signPayload")
            ->with(
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturnCallback(function () {
                return (new SignatureResponse(false, "", "", ""));
            });


        $authenticatorClient = new AuthenticatorClient($remoteService);
        $authenticatorClient->debug(true);

        $response = $authenticatorClient->authenticate($principal);
        $this->assertFalse($response->verify());
    }
}