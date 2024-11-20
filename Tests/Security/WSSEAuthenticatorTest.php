<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security;

use PHPUnit\Framework\TestCase;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\Psr16Adapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class WSSEAuthenticatorTest extends TestCase
{
    private $eventDispatcher;
    private MessageDigestPasswordHasher $hasher;
    private AbstractAdapter $nonceCache;
    private UserInterface $user;
    private $userChecker;
    private $userProvider;

    /**
     * @return array[]
     */
    public static function dataProviderSupports(): array
    {
        $request = new Request();
        $request->headers->add(['X-WSSE' => 'somedatainwsseheader']);

        return [
            [$request, true],
            [new Request(), false]
        ];
    }

    /**
     * @return array[]
     */
    public static function dataProviderValidateDigest(): iterable
    {
        $created = date(DATE_ATOM);

        $hasher = new MessageDigestPasswordHasher('sha1', true, 1);

        $digest = $hasher->hash(
            sprintf(
                '%s%s%s',
                'somenonce',
                $created,
                'somesecret'
            ),
            ''
        );

        $nonce = base64_encode('somenonce');

        $user = new InMemoryUser('test.wsse', 'somesecret', ['ROLE_ADMIN'], true);

        // Normal Case
        yield 'ValidDigest #1' => [$created, $nonce, $digest, 'test.wsse', $user, true];

        // Digest with Slashes

        $digest_slash = $hasher->hash(
            sprintf(
                '%s%s%s',
                's/o/m/e/n/o/n/c/e',
                $created,
                'somesecret'
            ),
            ''
        );

        yield 'ValidDigest #2' => [$created, base64_encode('s/o/m/e/n/o/n/c/e'), $digest_slash, 'test.wsse', $user, true];

        // Bad Password
        $userBadPassword = new InMemoryUser(
            'test.wsse',
            'someothersecret',
            ['ROLE_ADMIN'],
            true
        );

        yield 'ValidDigest #3' => [$created, $nonce, $digest, 'test.wsse', $userBadPassword, false];

        // Bad Username
        $userBadUsername = new InMemoryUser(
            'test.wsse.other',
            'someothersecret',
            ['ROLE_ADMIN'],
            true
        );

        yield 'ValidDigest #4' => [$created, $nonce, $digest, 'test.wsse', $userBadUsername, false];

        // Bad Nonce
        yield 'ValidDigest #5' => [$created, base64_encode('somewrongnonce'), $digest, 'test.wsse', $user, false];

        // Bad Digest
        yield 'ValidDigest #6' => [$created, $nonce, $digest . '9', 'test.wsse', $user, false];
    }

    /**
     * @depends testValidateDigestWithNonceDirExpectedException
     * @depends testValidateDigestWithNonceDir
     * @depends testValidateDigestWithoutNonceDir
     * @depends testValidateDigestExpireTime
     */
    public function testAuthenticate(): void
    {
        self::assertEquals('somesecret', $this->user->getPassword());
        self::assertEquals(['ROLE_ADMIN'], $this->user->getRoles());

        $this->userProvider->expects($this->once())->method('loadUserByIdentifier')->willReturn($this->user);

        $created = date(DATE_ATOM);

        $hasher = new MessageDigestPasswordHasher('sha1', true, 1);
        $passwordDigest = $hasher->hash(
            sprintf(
                '%s%s%s',
                'somenonce',
                $created,
                'somesecret'
            )
        );

        $request = new Request();

        $request->headers->add([
            'X-WSSE' => sprintf('UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"',
                $this->user->getUserIdentifier(),
                $passwordDigest,
                base64_encode('somenonce'),
                $created
            )
        ]);

        $expectedPassport = new SelfValidatingPassport(new UserBadge($this->user->getUserIdentifier()));

        $authenticator = $this->getWSSEAuthenticator();

        $passport = $authenticator->authenticate($request);

        self::assertEquals($expectedPassport, $passport);
    }

    /**
     * @depends testValidateDigestWithNonceDirExpectedException
     * @depends testValidateDigestWithNonceDir
     * @depends testValidateDigestWithoutNonceDir
     * @depends testValidateDigestExpireTime
     */
    public function testAuthenticateExpectedException(): void
    {
        $this->expectException(AuthenticationException::class);

        $authenticator = $this->getWSSEAuthenticator();

        $request = new Request();

        $authenticator->authenticate($request);
    }

    /**
     * @dataProvider dataProviderSupports
     */
    public function testAuthenticator(Request $request, $expected): void
    {
        $authenticator = $this->getWSSEAuthenticator();

        self::assertEquals($expected, $authenticator->supports($request));
    }

    public function testValidateDigestExpireTime(): void
    {
        $this->expectException(CredentialsExpiredException::class);

        $authenticator = $this->getWSSEAuthenticator();

        $wsseHeader = [
            'Created'        => date(DATE_ATOM, (time() - 86400)),
            'Nonce'          => 'somenonce',
            'PasswordDigest' => 'somepassword',
            'Username'       => 'wsse.test'
        ];

        $authenticator->validateDigest($wsseHeader, $this->user);
    }

    /**
     * @dataProvider dataProviderValidateDigest
     * @throws InvalidArgumentException
     */
    public function testValidateDigestWithNonceDir(
        string $created,
        string $nonce,
        string $passwordDigest,
        string $username,
        UserInterface $user,
        bool $expected
    ): void {

        $authenticator = $this->getWSSEAuthenticator();

        $wsseHeader = [
            'Created'        => $created,
            'Nonce'          => $nonce,
            'PasswordDigest' => $passwordDigest,
            'Username'       => $username
        ];

        $result = $authenticator->validateDigest($wsseHeader, $user);

        self::assertEquals($expected, $result);
        self::assertTrue($this->nonceCache->hasItem($nonce));

        try {
            $authenticator->validateDigest($wsseHeader, $user);
            self::fail('CredentialsExpiredException expected');
        } catch (CredentialsExpiredException) {
            $this->nonceCache->deleteItem($nonce);
        }
    }

    /**
     * @dataProvider dataProviderValidateDigest
     *
     * @throws InvalidArgumentException
     */
    public function testValidateDigestWithNonceDirExpectedException(
        string $created,
        string $nonce,
        string $passwordDigest,
        string $username,
        UserInterface $user
    ): void {

        $this->expectException(CredentialsExpiredException::class);

        $authenticator = $this->getWSSEAuthenticator();

        $item = $this->nonceCache->getItem($nonce);
        $item
            ->expiresAfter(time() - 123)
            ->set($nonce);
        $this->nonceCache->save($item);

        $wsseHeader = [
            'Created'        => $created,
            'Nonce'          => $nonce,
            'PasswordDigest' => $passwordDigest,
            'Username'       => $username
        ];

        $authenticator->validateDigest($wsseHeader, $user);

        $this->nonceCache->deleteItem($nonce);
    }

    /**
     * @dataProvider dataProviderValidateDigest
     */
    public function testValidateDigestWithoutNonceDir(
        string $created,
        string $nonce,
        string $passwordDigest,
        string $username,
        UserInterface $user,
        bool $expected
    ): void {
        $authenticator = $this->getWSSEAuthenticator();

        $wsseHeader = [
            'Created'        => $created,
            'Nonce'          => $nonce,
            'PasswordDigest' => $passwordDigest,
            'Username'       => $username
        ];

        $result = $authenticator->validateDigest($wsseHeader, $user);

        self::assertEquals($expected, $result);
    }

    protected function setUp(): void
    {
        $kernel = $this->createMock(HttpKernelInterface::class);
        $response = $this->createMock(Response::class);

        $this->eventDispatcher = $this->createMock(EventDispatcher::class);
        $this->hasher = new MessageDigestPasswordHasher('sha1', true, 1);
        $this->nonceCache = new Psr16Adapter(new Psr16Cache(new ArrayAdapter()), 'wsse_nonce', 300);
        $this->nonceCache->clear();
        $request = $this->createMock(Request::class);
        $requestEvent = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        $requestEvent->setResponse($response);
        $this->user = new InMemoryUser('test.wsse', 'somesecret', ['ROLE_ADMIN'], true);
        $this->userChecker = $this->createMock(UserCheckerInterface::class);
        $this->userProvider = $this->createMock(UserProviderInterface::class);
    }

    /**
     * @return WSSEAuthenticator
     */
    private function getWSSEAuthenticator(): WSSEAuthenticator
    {
        return new WSSEAuthenticator(
            $this->userChecker,
            $this->userProvider,
            $this->eventDispatcher,
            $this->nonceCache,
            $this->hasher
        );
    }
}
