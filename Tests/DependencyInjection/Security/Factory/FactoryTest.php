<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection\Security\Factory;

use Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class FactoryTest extends TestCase
{
    public function testPosition(): void
    {
        $factory = new Factory();
        $result = $factory->getPriority();
        $this->assertEquals(1, $result);
    }

    public function testKey(): void
    {
        $factory = new Factory();
        $result = $factory->getKey();
        $this->assertEquals('wsse', $result);
        $this->assertEquals('wsse', $this->getFactory()->getKey());
    }

    protected function getFactory(): MockObject|Factory
    {
        return new Factory();
    }

    public function testCreate(): void
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('escape_wsse_authentication.authenticator');

        $realm = 'somerealm';
        $profile = 'someprofile';
        $lifetime = 300;
        $date_format = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

        $algorithm = 'sha1';
        $iterations = 1;

        $hasher = [
            'algorithm'          => $algorithm,
            'encodeHashAsBase64' => true,
            'iterations'         => $iterations
        ];

        $authProviderId = $factory->createAuthenticator(
            $container,
            'foo',
            [
                'realm'       => $realm,
                'profile'     => $profile,
                'hasher'      => $hasher,
                'lifetime'    => $lifetime,
                'date_format' => $date_format
            ],
            'user_provider'
        )[0];

        // Hasher
        $hasherId = $factory->getHasherId();

        $this->assertEquals('escape_wsse_authentication.hasher.foo', $hasherId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.hasher.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.hasher.foo');
        $this->assertEquals(
            [
                'index_0' => $algorithm,
                'index_1' => true,
                'index_2' => $iterations
            ],
            $definition->getArguments()
        );

        // Nonce cache
        $nonceCacheId = $factory->getNonceCacheId();

        $this->assertEquals('escape_wsse_authentication.nonce_cache.foo', $nonceCacheId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.nonce_cache.foo'));

        // Authenticator
        $this->assertEquals('escape_wsse_authentication.authenticator.foo', $authProviderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.authenticator.foo'));
        $definition = $container->getDefinition('escape_wsse_authentication.authenticator.foo');

        $this->assertEquals(
            [
                '$userChecker'     => new Reference('security.user_checker.foo'),
                '$userProvider'    => new Reference('user_provider'),
                '$eventDispatcher' => new Reference('event_dispatcher'),
                '$nonceCache'      => new Reference($nonceCacheId),
                '$hasher'          => new Reference($hasherId),
                '$lifetime'        => $lifetime,
                '$dateFormat'      => $date_format
            ],
            $definition->getArguments()
        );
    }
}
