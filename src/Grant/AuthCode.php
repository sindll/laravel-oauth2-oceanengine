<?php

namespace Sindll\OAuth2\Client\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;

class AuthCode extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'auth_code';
    }

    /**
     * @inheritdoc
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'auth_code',
        ];
    }
}
