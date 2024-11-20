<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection;

use Escape\WSSEAuthenticationBundle\Security\WSSEAuthenticator;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('escape_wsse_authentication');
        $treeBuilder
            ->getRootNode()
            ->children()
                ->scalarNode('authentication_authenticator_class')->defaultValue(WSSEAuthenticator::class)->end()
                ->scalarNode('authentication_hasher_class')->defaultValue(MessageDigestPasswordHasher::class)->end()
                ->scalarNode('authentication_nonce_cache_class')->defaultValue(FilesystemAdapter::class)->end()
            ->end();

        return $treeBuilder;
    }
}
