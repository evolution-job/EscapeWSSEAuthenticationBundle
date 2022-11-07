<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider;
use PHPUnit\Framework\TestCase;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\Psr16Adapter;
use Symfony\Component\Cache\CacheItem;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class CustomProvider extends Provider
{
    // Open up scope for protected Provider's validateDigest-method
    public function validateDigest($digest, $nonce, $created, $secret, $salt): bool
    {
        return parent::validateDigest($digest, $nonce, $created, $secret, $salt);
    }
}

class ProviderTest extends TestCase
{
    private PasswordEncoderInterface $hasher;
    private AbstractAdapter $nonceCache;
    private string $providerKey;
    private UserInterface $user;
    private $userChecker;
    private $userProvider;

    /**
     * @return array[]
     */
    public function dataProviderSupports(): array
    {
        $tokenWithoutAttributes = new Token(new User('someuser', 'somesecret'), 'somesecret', 'someproviderkey');

        $tokenWithAttributes = new Token(new User('someuser', 'somesecret'), 'somesecret', 'someproviderkey');
        $tokenWithAttributes->setAttribute('nonce', base64_encode('somenonce'));
        $tokenWithAttributes->setAttribute('created', date(DATE_ATOM));

        return [
            [$tokenWithoutAttributes, false],
            [$tokenWithAttributes, true],
            [$this->createMock(TokenInterface::class), false]
        ];
    }

    /**
     * @return array[]
     */
    public function dataProviderValidateDigest(): array
    {
        $time = date(DATE_ATOM);

        $hasher = new MessageDigestPasswordEncoder('sha1', true, 1);

        $digest = $hasher->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $digest_slash = $hasher->encodePassword(
            sprintf(
                '%s%s%s',
                's/o/m/e/n/o/n/c/e',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        return [
            [$digest, base64_encode('somenonce'), $time, 'somesecret', 'somesalt', true],
            [$digest, base64_encode('somenonce'), $time, 'somewrongsecret', 'somesalt', false],
            [$digest, base64_encode('somenonce'), $time, 'somesecret', 'somewrongsalt', false],
            [$digest, base64_encode('somewrongnonce'), $time, 'somesecret', 'somesalt', false],
            [$digest . '9', base64_encode('somenonce'), $time, 'somesecret', 'somesalt', false],
            [$digest_slash, base64_encode('s/o/m/e/n/o/n/c/e'), $time, 'somesecret', 'somesalt', true]
        ];
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
        self::assertEquals([], $this->user->getRoles());
        $this->userProvider->expects($this->once())->method('loadUserByUsername')->willReturn($this->user);

        $hasher = new MessageDigestPasswordEncoder('sha1', true, 1);
        $time = date(DATE_ATOM);

        $digest = $hasher->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            null
        );

        $expected = new Token($this->user, $digest, $this->providerKey);

        $time = date(DATE_ATOM);

        $digest = $hasher->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            null
        );

        $token = new Token($this->user, $digest, $this->providerKey);
        $token->setAttribute('nonce', base64_encode('somenonce'));
        $token->setAttribute('created', $time);

        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);
        $result = $provider->authenticate($token);

        self::assertEquals($expected, $result);
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
        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);

        $token = new Token($this->user, '', $this->providerKey);
        $token->setAttribute('nonce', base64_encode('somenonce'));
        $token->setAttribute('created', date(DATE_ATOM));

        $provider->authenticate($token);
    }

    /**
     * @dataProvider dataProviderSupports
     *
     * @param $token
     * @param $expected
     */
    public function testProvider($token, $expected): void
    {
        $provider = new Provider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);
        self::assertEquals($expected, $provider->supports($token));
    }

    public function testValidateDigestExpireTime(): void
    {
        $this->expectException(CredentialsExpiredException::class);
        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);
        $provider->validateDigest(null, null, date(DATE_ATOM, (time() - 86400)), null, null);
    }

    /**
     * @dataProvider dataProviderValidateDigest
     *
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     * @param $salt
     * @param $expected
     * @return void
     * @throws InvalidArgumentException
     */
    public function testValidateDigestWithNonceDir($digest, $nonce, $created, $secret, $salt, $expected): void
    {
        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);
        $result = $provider->validateDigest($digest, $nonce, $created, $secret, $salt);

        self::assertEquals($expected, $result);
        self::assertTrue($this->nonceCache->hasItem($nonce));

        try {
            $provider->validateDigest($digest, $nonce, $created, $secret, $salt);
            self::fail('CredentialsExpiredException expected');
        } catch (CredentialsExpiredException $e) {
            $this->nonceCache->deleteItem($nonce);
        }
    }

    /**
     * @dataProvider dataProviderValidateDigest
     *
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     * @param $salt
     * @return void
     * @throws InvalidArgumentException
     */
    public function testValidateDigestWithNonceDirExpectedException($digest, $nonce, $created, $secret, $salt): void
    {
        $this->expectException(CredentialsExpiredException::class);

        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);

        /** @var CacheItem $item */
        $item = $this->nonceCache->getItem($nonce);
        $item
            ->expiresAfter(time() - 123)
            ->set($nonce);
        $this->nonceCache->save($item);

        $provider->validateDigest($digest, $nonce, $created, $secret, $salt);

        $this->nonceCache->deleteItem($nonce);
    }

    /**
     * @dataProvider dataProviderValidateDigest
     *
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     * @param $salt
     * @param $expected
     */
    public function testValidateDigestWithoutNonceDir($digest, $nonce, $created, $secret, $salt, $expected): void
    {
        $provider = new CustomProvider($this->userChecker, $this->userProvider, $this->providerKey, $this->hasher, $this->nonceCache);
        $result = $provider->validateDigest($digest, $nonce, $created, $secret, $salt);
        self::assertEquals($expected, $result);
    }

    protected function setUp(): void
    {
        $this->hasher = new MessageDigestPasswordEncoder('sha1', true, 1);
        $this->nonceCache = new Psr16Adapter(new Psr16Cache(new ArrayAdapter()), 'wsse_nonce', 300);
        $this->providerKey = 'someproviderkey';
        $this->user = new User('someuser', 'somesecret');
        $this->userChecker = $this->createMock(UserCheckerInterface::class);
        $this->userProvider = $this->createMock(UserProviderInterface::class);

        $this->nonceCache->clear();
    }
}
