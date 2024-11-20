<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class Factory implements AuthenticatorFactoryInterface
{
    private string $hasherId;
    private string $nonceCacheId;

    public function createAuthenticator(ContainerBuilder $container, $firewallName, $config, string $userProviderId): array
    {
        $this->hasherId = 'escape_wsse_authentication.hasher.' . $firewallName;

        $container->setDefinition($this->hasherId, new ChildDefinition('escape_wsse_authentication.hasher'));

        if (isset($config['hasher']['algorithm'])) {
            $container->getDefinition($this->hasherId)->replaceArgument(0, $config['hasher']['algorithm']);
        }

        if (isset($config['hasher']['encodeHashAsBase64'])) {
            $container->getDefinition($this->hasherId)->replaceArgument(1, $config['hasher']['encodeHashAsBase64']);
        }

        if (isset($config['hasher']['iterations'])) {
            $container->getDefinition($this->hasherId)->replaceArgument(2, $config['hasher']['iterations']);
        }

        if (isset($config['nonce_cache_service_id'])) {
            $this->nonceCacheId = $config['nonce_cache_service_id'];
        } else {
            $this->nonceCacheId = 'escape_wsse_authentication.nonce_cache.' . $firewallName;

            $container->setDefinition($this->nonceCacheId, new ChildDefinition('escape_wsse_authentication.nonce_cache'));
        }

        $authenticatorId = 'escape_wsse_authentication.authenticator.' . $firewallName;

        $container->setDefinition($authenticatorId, new ChildDefinition('escape_wsse_authentication.authenticator'))
            ->replaceArgument('$userChecker', new Reference('security.user_checker.' . $firewallName))
            ->replaceArgument('$userProvider', new Reference($userProviderId))
            ->replaceArgument('$eventDispatcher', new Reference('event_dispatcher'))
            ->replaceArgument('$nonceCache', new Reference($this->nonceCacheId))
            ->replaceArgument('$hasher', new Reference($this->hasherId))
            ->replaceArgument('$lifetime', $config['lifetime'])
            ->replaceArgument('$dateFormat', $config['date_format']);

        return [$authenticatorId];
    }

    public function getPriority(): int
    {
        return 1;
    }

    public function getKey(): string
    {
        return 'wsse';
    }

    public function getHasherId(): string
    {
        return $this->hasherId;
    }

    public function getNonceCacheId(): string
    {
        return $this->nonceCacheId;
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
            ->scalarNode('authenticator')->end()
            ->scalarNode('realm')->defaultValue(null)->end()
            ->scalarNode('profile')->defaultValue('UsernameToken')->end()
            ->scalarNode('lifetime')->defaultValue(300)->end()
            ->scalarNode('date_format')->defaultValue(
                '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
            )->end()
            ->arrayNode('hasher')
            ->children()
            ->scalarNode('algorithm')->end()
            ->scalarNode('encodeHashAsBase64')->end()
            ->scalarNode('iterations')->end()
            ->end()
            ->end()
            ->scalarNode('nonce_cache_service_id')->defaultValue(null)->end()
            ->end();
    }
}
