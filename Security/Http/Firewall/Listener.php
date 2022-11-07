<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Firewall;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use UnexpectedValueException;

class Listener extends AbstractListener
{
    /**
     * @var TokenStorageInterface
     */
    protected TokenStorageInterface $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    protected AuthenticationManagerInterface $authenticationManager;

    /**
     * @var string Uniquely identifies the secured area
     */
    protected string $providerKey;

    /**
     * @var AuthenticationEntryPointInterface
     */
    protected AuthenticationEntryPointInterface $authenticationEntryPoint;

    /**
     * @var string WSSE header
     */
    private string $wsseHeader;

    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        string $providerKey,
        AuthenticationEntryPointInterface $authenticationEntryPoint
    ) {
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @param RequestEvent $event
     * @return TokenInterface|null
     */
    public function authenticate(RequestEvent $event): ?TokenInterface
    {
        $request = $event->getRequest();

        // Find out if the current request contains any information by which the user might be authenticated
        if (!$request->headers->has('X-WSSE')) {
            return null;
        }

        $this->wsseHeader = $request->headers->get('X-WSSE');
        $wsseHeaderInfo = $this->parseHeader();

        if ($wsseHeaderInfo !== false) {
            $token = new Token(
                $wsseHeaderInfo['Username'],
                $wsseHeaderInfo['PasswordDigest'],
                $this->providerKey
            );

            $token->setAttribute('nonce', $wsseHeaderInfo['Nonce']);
            $token->setAttribute('created', $wsseHeaderInfo['Created']);

            $auth = $this->authenticationManager->authenticate($token);
            if ($auth instanceof TokenInterface) {
                $this->tokenStorage->setToken($auth);

                return $auth;
            }

            $event->setResponse($this->authenticationEntryPoint->start($request, new AuthenticationException()));
        }

        return null;
    }

    /**
     * @param Request $request
     * @return bool|null
     */
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-WSSE');
    }

    /**
     * This method parses the X-WSSE header
     *
     * If Username, PasswordDigest, Nonce and Created exist then it returns their value,
     * otherwise the method returns false.
     *
     * @return array|bool
     */
    private function parseHeader()
    {
        $result = [];

        try {
            $result['Username'] = $this->parseValue('Username');
            $result['PasswordDigest'] = $this->parseValue('PasswordDigest');
            $result['Nonce'] = $this->parseValue('Nonce');
            $result['Created'] = $this->parseValue('Created');
        } catch (UnexpectedValueException $e) {
            return false;
        }

        return $result;
    }

    /**
     * This method returns the value of a bit header by the key
     *
     * @param $key
     * @return mixed
     * @throws UnexpectedValueException
     */
    private function parseValue($key)
    {
        if (!preg_match('/' . $key . '="([^"]+)"/', $this->wsseHeader, $matches)) {
            throw new UnexpectedValueException('The string was not found');
        }

        return $matches[1];
    }
}