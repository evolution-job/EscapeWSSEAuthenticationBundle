<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Firewall;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use UnexpectedValueException;

class Listener extends AbstractListener
{
    /**
     * @var string WSSE header
     */
    private $wsseHeader;

    /**
     * @var SecurityContextInterface|TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var string Uniquely identifies the secured area
     */
    protected $providerKey;

    /**
     * @var AuthenticationEntryPointInterface
     */
    protected $authenticationEntryPoint;

    public function __construct(
        $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        $providerKey,
        AuthenticationEntryPointInterface $authenticationEntryPoint
    ) {
        if (!$tokenStorage instanceof TokenStorageInterface && !$tokenStorage instanceof SecurityContextInterface) {
            throw new InvalidArgumentException('Argument 1 should be an instance of Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface or Symfony\Component\Security\Core\SecurityContextInterface');
        }

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-WSSE');
    }

    public function authenticate(RequestEvent $event)
    {
        $request = $event->getRequest();

        //find out if the current request contains any information by which the user might be authenticated
        if (!$request->headers->has('X-WSSE')) {
            return;
        }

        $ae_message = null;
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

            try {
                $returnValue = $this->authenticationManager->authenticate($token);

                if ($returnValue instanceof TokenInterface) {
                    return $this->tokenStorage->setToken($returnValue);
                }

                if ($returnValue instanceof Response) {
                    return $event->setResponse($returnValue);
                }
            } catch (AuthenticationException $ae) {
                $event->setResponse($this->authenticationEntryPoint->start($request, $ae));
            }
        }
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
}