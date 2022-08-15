<?php

namespace Sindll\OAuth2\Client\OptionProvider;

use League\OAuth2\Client\OptionProvider\OptionProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Tool\QueryBuilderTrait;

class PostAuthOptionProvider implements OptionProviderInterface
{
    use QueryBuilderTrait;

    /**
     * @inheritdoc
     */
    public function getAccessTokenOptions($method, array $params)
    {
        $options = ['headers' => ['content-type' => 'application/json']];

        if ($method === AbstractProvider::METHOD_POST) {
            $options['body'] = $this->getAccessTokenBody($params);
        }

        return $options;
    }

    /**
     * Returns the request body for requesting an access token.
     *
     * @param  array $params
     * @return string
     */
    protected function getAccessTokenBody(array $params)
    {
        return json_encode($params);
    }

    /**
     * @inheritdoc
     */
    public function getRefreshTokenOptions($method, array $params)
    {
        $options = ['headers' => ['content-type' => 'application/json']];

        if ($method === AbstractProvider::METHOD_POST) {
            $options['body'] = $this->getRefreshTokenBody($params);
        }

        return $options;
    }

    /**
     * Returns the request body for requesting an Refresh token.
     *
     * @param  array $params
     * @return string
     */
    protected function getRefreshTokenBody(array $params)
    {
        return json_encode($params);
    }
}
