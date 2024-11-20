<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class EscapeWSSEAuthenticationExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');

        $container->setParameter('escape_wsse_authentication.authenticator.class', $config['authentication_authenticator_class']);
        $container->setParameter('escape_wsse_authentication.hasher.class', $config['authentication_hasher_class']);
        $container->setParameter('escape_wsse_authentication.nonce_cache.class', $config['authentication_nonce_cache_class']);
    }

    public function getAlias(): string
    {
        return 'escape_wsse_authentication';
    }
}