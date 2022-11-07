<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider;

use InvalidArgumentException;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\Psr16Adapter;
use Symfony\Component\Cache\CacheItem;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class Provider implements AuthenticationProviderInterface
{
    private string $dateFormat;
    private PasswordEncoderInterface $hasher;
    private int $lifetime;
    private AbstractAdapter $nonceCache;
    private string $providerKey;
    private UserCheckerInterface $userChecker;
    private UserProviderInterface $userProvider;

    /**
     * @param UserCheckerInterface $userChecker A UserCheckerInterface instance
     * @param UserProviderInterface $userProvider An UserProviderInterface instance
     * @param string $providerKey The provider key
     * @param PasswordEncoderInterface $hasher
     * @param AbstractAdapter $nonceCache The nonce cache
     * @param int $lifetime The lifetime
     * @param string $dateFormat The date format
     */
    public function __construct(
        UserCheckerInterface $userChecker,
        UserProviderInterface $userProvider,
        string $providerKey,
        PasswordEncoderInterface $hasher,
        AbstractAdapter $nonceCache,
        int $lifetime = 300,
        string $dateFormat = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
    ) {
        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->dateFormat = $dateFormat;
        $this->hasher = $hasher;
        $this->lifetime = $lifetime;
        $this->nonceCache = $nonceCache;
        $this->providerKey = $providerKey;
        $this->userChecker = $userChecker;
        $this->userProvider = $userProvider;
    }

    /**
     * @param TokenInterface $token
     * @return TokenInterface|null
     */
    public function authenticate(TokenInterface $token): ?TokenInterface
    {
        if (!$this->supports($token)) {
            return null;
        }

        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if (!$user) {
            throw new AuthenticationException('WSSE authentication failed: bad username');
        }

        $this->userChecker->checkPreAuth($user);

        if ($this->validateDigest(
            $token->getCredentials(),
            $token->getAttribute('nonce'),
            $token->getAttribute('created'),
            $this->getSecret($user),
            $this->getSalt($user)
        )) {
            $this->userChecker->checkPostAuth($user);

            return new Token(
                $user,
                $token->getCredentials(),
                $this->providerKey,
                $user->getRoles()
            );
        }

        throw new AuthenticationException('WSSE authentication failed: bad secret');
    }

    public function getDateFormat(): string
    {
        return $this->dateFormat;
    }

    public function getHasher(): PasswordEncoderInterface
    {
        return $this->hasher;
    }

    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    public function getNonceCache(): AbstractAdapter
    {
        return $this->nonceCache;
    }

    public function getUserProvider(): UserProviderInterface
    {
        return $this->userProvider;
    }

    public function setCachedNonce()
    {
        $cache = new Psr16Adapter(new Psr16Cache(new ArrayAdapter()), 'some_namespace', 0);
        $item = $cache->getItem('my_key');
        $item->set('someValue');
        $cache->save($item);
    }

    public function supports(TokenInterface $token): bool
    {
        return $token instanceof Token && $token->hasAttribute('nonce') && $token->hasAttribute('created') && $this->providerKey === $token->getProviderKey();
    }

    protected function isFormattedCorrectly($created)
    {
        return preg_match($this->getDateFormat(), $created);
    }

    protected function isTokenFromFuture($created): bool
    {
        return strtotime($created) > strtotime($this->getCurrentTime());
    }

    protected function getSecret(UserInterface $user): ?string
    {
        return $user->getPassword();
    }

    protected function getSalt(UserInterface $user): ?string
    {
        return $user->getSalt();
    }

    protected function isTokenExpired($created): bool
    {
        return !($this->lifetime === -1) && strtotime($this->getCurrentTime()) - strtotime($created) > $this->lifetime;
    }

    protected function validateDigest($digest, $nonce, $created, $secret, $salt): bool
    {
        // Check whether timestamp is formatted correctly
        if (!$this->isFormattedCorrectly($created)) {
            throw new BadCredentialsException('Incorrectly formatted "created" in token.');
        }

        // Check whether timestamp is not in the future
        if ($this->isTokenFromFuture($created)) {
            throw new BadCredentialsException('Future token detected.');
        }

        // Expire timestamp after specified lifetime
        if ($this->isTokenExpired($created)) {
            throw new CredentialsExpiredException('Token has expired.');
        }

        /** @var CacheItem $item */
        $item = $this->nonceCache->getItem($nonce);

        // Validate that nonce is unique within specified lifetime
        // If it is not, this could be a replay attack
        if ($item->get() !== null) {
            throw new CredentialsExpiredException('Previously used nonce detected.');
        }

        $item
            ->expiresAfter($this->lifetime)
            ->set($nonce);
        $this->nonceCache->save($item);

        // Validate secret
        $expected = $this->hasher->encodePassword(
            sprintf(
                '%s%s%s',
                base64_decode($nonce),
                $created,
                $secret
            ),
            $salt
        );

        return hash_equals($expected, $digest);
    }

    protected function getCurrentTime()
    {
        return gmdate(DATE_ATOM);
    }
}
