<?php

namespace Escape\WSSEAuthenticationBundle\Security;

use Exception;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\CacheItem;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

class WSSEAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        protected UserCheckerInterface $userChecker,
        protected UserProviderInterface $userProvider,
        protected EventDispatcherInterface $eventDispatcher,
        protected AbstractAdapter $nonceCache,
        protected MessageDigestPasswordHasher $hasher,
        protected int $lifetime = 300,
        protected string $dateFormat = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
    ) {}

    public function authenticate(Request $request): Passport
    {
        $wsseHeader = $request->headers->get('X-WSSE');

        if (null === $wsseHeader) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException('No WSSE header provided');
        }

        $wsseHeaderInfo = $this->parseHeader($wsseHeader);

        // Resolve User
        try {
            $user = $this->userProvider->loadUserByIdentifier($wsseHeaderInfo['Username']);
        } catch (UserNotFoundException) {
            throw new CustomUserMessageAuthenticationException('WSSE authentication failed: bad username');
        }

        $this->userChecker->checkPreAuth($user);

        if ($this->validateDigest($wsseHeaderInfo, $user)) {

            $this->userChecker->checkPostAuth($user);

            // Workaround to avoid duplicate requests
            try {
                $wait = random_int(5_000, 25_000);
                usleep($wait);
            } catch (Exception) {
            }

            return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier()));
        }

        throw new CustomUserMessageAuthenticationException('WSSE authentication failed: bad secret');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Fire the login event
        $this->eventDispatcher->dispatch(new InteractiveLoginEvent($request, $token), SecurityEvents::INTERACTIVE_LOGIN);

        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [// you may want to customize or obfuscate the message first
                 'message' => strtr($exception->getMessageKey(), $exception->getMessageData())];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supports(Request $request): ?bool
    {
        if ($request->headers->has('X-WSSE')) {

            return true;
        }

        return null; // Returning null means authenticate() can be called lazily when accessing the token storage.
    }

    protected function getCurrentTime(): string
    {
        return gmdate(DATE_ATOM);
    }

    protected function getSalt(UserInterface $user): string
    {
        if (method_exists($user, 'getSalt')) {

            return (string)$user->getSalt();
        }

        return '';
    }

    protected function getSecret(UserInterface $user): string
    {
        if (method_exists($user, 'getSecret')) {

            return $user->getSecret();
        }

        if (method_exists($user, 'getPassword')) {

            return $user->getPassword();
        }

        throw new CustomUserMessageAuthenticationException('WSSE authentication process error');
    }

    protected function isFormattedCorrectly(string $created): bool|int
    {
        return preg_match($this->dateFormat, $created);
    }

    protected function isTokenExpired(string $created): bool
    {
        return !($this->lifetime === -1) && strtotime($this->getCurrentTime()) - strtotime($created) > $this->lifetime;
    }

    protected function isTokenFromFuture(string $created): bool
    {
        // Adding 3seconds to avoid difference between servers
        return strtotime($created) > strtotime($this->getCurrentTime()) + 3;
    }

    protected function validateDigest(array $wsseHeader, UserInterface $user): bool
    {
        // Check whether timestamp is formatted correctly
        if (!$this->isFormattedCorrectly($wsseHeader['Created'])) {
            throw new CustomUserMessageAuthenticationException('Incorrectly formatted "Created" in token.');
        }

        // Check whether timestamp is not in the future
        if ($this->isTokenFromFuture($wsseHeader['Created'])) {
            throw new CustomUserMessageAuthenticationException('Future token detected.');
        }

        // Expire timestamp after specified lifetime
        if ($this->isTokenExpired($wsseHeader['Created'])) {
            throw new CredentialsExpiredException('Token has expired.');
        }

        /** @var CacheItem $item */
        try {
            $item = $this->nonceCache->getItem($wsseHeader['Nonce']);
        } catch (InvalidArgumentException) {
            $item = null;
        }

        // Validate that nonce is unique within specified lifetime
        // If it is not, this could be a replay attack
        if ($item?->get() !== null) {
            throw new CredentialsExpiredException('Previously used nonce detected.');
        }

        $item->expiresAfter($this->lifetime)->set($wsseHeader['Nonce']);
        $this->nonceCache->save($item);

        // Hash
        $expected = $this->hasher->hash(
            sprintf('%s%s%s',
                base64_decode($wsseHeader['Nonce']),
                $wsseHeader['Created'],
                $this->getSecret($user)
            ),
            $this->getSalt($user)
        );

        return hash_equals($expected, $wsseHeader['PasswordDigest']);
    }

    /**
     * This method parses the X-WSSE header
     *
     * If Username, PasswordDigest, Nonce and Created exist then it returns their value.
     *
     * @param string $wsseHeader
     * @return array
     */
    private function parseHeader(string $wsseHeader): array
    {
        $result['Username'] = $this->parseValue($wsseHeader, 'Username');
        $result['PasswordDigest'] = $this->parseValue($wsseHeader, 'PasswordDigest');
        $result['Nonce'] = $this->parseValue($wsseHeader, 'Nonce');
        $result['Created'] = $this->parseValue($wsseHeader, 'Created');

        return $result;
    }

    /**
     * This method returns the value of a bit header by the key
     *
     * @param string $data
     * @param string $key
     * @return string
     */
    private function parseValue(string $data, string $key): string
    {
        if (!preg_match('/' . $key . '="([^"]+)"/', $data, $matches)) {
            throw new CustomUserMessageAuthenticationException(sprintf('The key %s was not found in header', $key));
        }

        return $matches[1];
    }
}