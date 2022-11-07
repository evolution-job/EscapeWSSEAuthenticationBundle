<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\Firewall;

use Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint;
use Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class ListenerTest extends TestCase
{
    /**
     * @var MockObject $requestEvent
     */
    private $requestEvent;

    /**
     * @var MockObject
     */
    private $request;

    /**
     * @var MockObject
     */
    private $securityContext;

    /**
     * @var MockObject
     */
    private $authenticationManager;

    /**
     * @var MockObject
     */
    private $authenticationEntryPoint;

    protected function setUp(): void
    {
        $this->authenticationEntryPoint = new EntryPoint();
        $this->authenticationManager = $this->createMock(AuthenticationManagerInterface::class);
        $this->request = $this->getMockForAbstractClass(Request::class);

        $kernel = $this->createMock(HttpKernelInterface::class);
        $response = $this->getMockForAbstractClass(Response::class);
        $this->requestEvent = new RequestEvent($kernel, $this->request, HttpKernelInterface::MAIN_REQUEST, $response);

        $this->securityContext = $this->createMock(TokenStorageInterface::class);
    }

    public function testAutheticateReturnToken()
    {
        $token = new Token('someuser', 'somedigest', 'someproviderkey');
        $token->setAttribute('nonce', 'somenonce');
        $token->setAttribute('created', '2010-12-12 20:00:00');

        $tokenMock2 = $this->createMock(TokenInterface::class);
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->willReturn($tokenMock2);
        $this->securityContext->expects($this->once())->method('setToken')->with($tokenMock2);
        $this->request->headers->add(['X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"']);

        $listener = new Listener($this->securityContext, $this->authenticationManager, 'someproviderkey', $this->authenticationEntryPoint);

        self::assertInstanceOf(TokenInterface::class, $listener->authenticate($this->requestEvent));
        self::assertNull($this->requestEvent->getResponse());
    }

    public function testAutheticateReturnBadResponse(): void
    {
        $token = new Token('someuser', 'somedigest', 'someproviderkey');
        $token->setAttribute('nonce', 'somenonce');
        $token->setAttribute('created', '2010-12-12 20:00:00');

        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->willReturn($this->requestEvent->getResponse());
        $this->request->headers->add(['X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"']);

        $listener = new Listener($this->securityContext, $this->authenticationManager, 'someproviderkey', $this->authenticationEntryPoint);

        $listener->authenticate($this->requestEvent);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $this->requestEvent->getResponse()->getStatusCode());
    }
}