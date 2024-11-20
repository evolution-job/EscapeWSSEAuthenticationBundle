<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security;

use Escape\WSSEAuthenticationBundle\Security\WSSEAuthenticator as OriginalWSSEAuthenticator;
use Symfony\Component\Security\Core\User\UserInterface;

class WSSEAuthenticator extends OriginalWSSEAuthenticator
{
    // Open up scope for protected Authenticator's validateDigest-method
    public function validateDigest(array $wsseHeader, UserInterface $user): bool
    {
        return parent::validateDigest($wsseHeader, $user);
    }
}