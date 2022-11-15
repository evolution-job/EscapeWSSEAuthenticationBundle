<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\EntryPoint;

use Symfony\Component\HttpFoundation\Response;
use Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

class EntryPointTest extends TestCase
{
    protected function setUp(): void
    {
        if(!interface_exists(LoggerInterface::class))
        {
            $this->markTestSkipped('Interface "Psr\Log\LoggerInterface" is not available');
        }

        if(!class_exists(Request::class))
        {
            $this->markTestSkipped('The "HttpFoundation" component is not available');
        }
    }

    public function testStart(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $request = $this->createMock(Request::class);
        $realm = 'TheRealm';
        $profile = 'TheProfile';

        $authenticationException = new AuthenticationException('TheAuthenticationExceptionMessage');

        $entryPoint = new EntryPoint($logger,$realm,$profile);
        $response = $entryPoint->start($request, $authenticationException);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        $this->assertRegExp(
            sprintf(
                '/^WSSE realm="%s", profile="%s"$/',
                $realm,
                $profile
            ),
            $response->headers->get('WWW-Authenticate')
        );
    }

    public function testStartWithNoException(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $request = $this->createMock(Request::class);
        $realm = 'TheRealm';
        $profile = 'TheProfile';

        $entryPoint = new EntryPoint($logger,$realm,$profile);
        $response = $entryPoint->start($request);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        $this->assertRegExp(
            sprintf(
                '/^WSSE realm="%s", profile="%s"$/',
                $realm,
                $profile
            ),
            $response->headers->get('WWW-Authenticate')
        );
    }
}