<?php

namespace Sindll\OAuth2\Client\Provider;

use UnexpectedValueException;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use League\OAuth2\Client\Grant\GrantFactory;
use Sindll\OAuth2\Client\Grant\AuthCode;
use Sindll\OAuth2\Client\OptionProvider\PostAuthOptionProvider;

class Oceanengine extends AbstractProvider
{
    use QueryBuilderTrait;

    /**
     * @var string
     */
    private $urlAuthorize = 'https://open.oceanengine.com/audit/oauth.html';

    /**
     * @var string
     */
    private $urlAccessToken = 'https://ad.oceanengine.com/open_api/oauth2/access_token/';

    /**
     * @var string
     */
    private $urlResourceOwnerDetails = 'https://ad.oceanengine.com/open_api/2/user/info/';

    /**
     * @var string
     */
    private $urlRefreshToken = 'https://ad.oceanengine.com/open_api/oauth2/refresh_token/';

    /**
     * @var string
     */
    private $urlRequestPrefix = 'https://ad.oceanengine.com/';

    public function __construct(array $options = [], array $collaborators = [])
    {
        $collaborators['grantFactory'] = new GrantFactory();
        $collaborators['grantFactory']->setGrant('auth_code', new AuthCode());

        $collaborators['optionProvider'] = new PostAuthOptionProvider();

        parent::__construct($options, $collaborators);
    }

    /**
     * @inheritdoc
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->urlAuthorize;
    }

    protected function getAuthorizationParameters(array $options)
    {
        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }

        if (empty($options['scope'])) {
            $options['scope'] = $this->getDefaultScopes();
        }

        if (is_array($options['scope'])) {
            $separator = $this->getScopeSeparator();
            $options['scope'] = implode($separator, $options['scope']);
        }

        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];

        // Business code layer might set a different redirect_uri parameter
        // depending on the context, leave it as-is
        if (!isset($options['redirect_uri'])) {
            $options['redirect_uri'] = $this->redirectUri;
        }

        $options['app_id'] = $this->clientId;

        return $options;
    }

    /**
     * @inheritdoc
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->urlAccessToken;
    }

    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);

        $params = [
            'app_id' => $this->clientId,
            'secret' => $this->clientSecret,
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        if ($grant->__toString() == 'auth_code') {
            $request  = $this->getAccessTokenRequest($params);
        }
        if ($grant->__toString() == 'refresh_token') {
            $request  = $this->getRefreshTokenRequest($params);
        }

        $response = $this->getParsedResponse($request);
        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }
        $prepared = $this->prepareAccessTokenResponse($response['data']);
        $token    = $this->createAccessToken($prepared, $grant);

        return $token;
    }

    /**
     * @inheritdoc
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->urlResourceOwnerDetails;
    }

    /**
     * @inheritdoc
     */
    public function getDefaultScopes()
    {

    }

    protected function getDefaultHeaders()
    {
    	return [
    		'Content-Type' => 'application/json',
    	];
    }

    protected function getAuthorizationHeaders($token = null)
    {
        if ($token) {
            return [
                'Access-Token' => $token->getToken(),
            ];
        }
        return [];
    }

    /**
     * @inheritdoc
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        Log::info('Response data: ', $data);

        if ($data['code'] != 0) {
            $code  = $data['code'];
            $error = $data['message'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response['data'], 'id');
    }

    /**
     * @inheritdoc
     */
    public function getBaseRefreshTokenUrl(array $params)
    {
        return $this->urlRefreshToken;
    }


    protected function getRefreshTokenQuery(array $params)
    {
        return $this->buildQueryString($params);
    }

    protected function getRefreshTokenMethod()
    {
        return self::METHOD_POST;
    }

    protected function getRefreshTokenUrl(array $params)
    {
        $url = $this->getBaseRefreshTokenUrl($params);

        if ($this->getRefreshTokenMethod() === self::METHOD_GET) {
            $query = $this->getRefreshTokenQuery($params);
            return $this->appendQuery($url, $query);
        }

        return $url;
    }

    protected function getRefreshTokenRequest(array $params)
    {
        $method  = $this->getRefreshTokenMethod();
        $url     = $this->getRefreshTokenUrl($params);
        $options = $this->optionProvider->getRefreshTokenOptions($this->getRefreshTokenMethod(), $params);

        return $this->getRequest($method, $url, $options);
    }

    public function getBaseRquestPrefixUrl()
    {
        return $this->urlRequestPrefix;
    }

    protected function getRequestUrl($url)
    {
        if (substr($url, 0, 4) == 'http') {
            return $url;
        }

        return sprintf('%s/%s', trim($this->getBaseRquestPrefixUrl(), '/'), trim($url, '/'));
    }

    protected function getRequestQuery($params)
    {
        return $this->buildQueryString($params);
    }

    public function requestWithToken($method, $url, $token, array $params = [], array $headers = [])
    {
        $url = $this->getRequestUrl($url);

        if ($method === self::METHOD_GET) {
            $query = $this->getRequestQuery($params);
            $url = $this->appendQuery($url, $query);
        }

        $options = [];
        if ($headers) {
            $options['headers'] = $headers;
        }
        if ($method === self::METHOD_POST) {
        	$options['body'] = json_encode($params);
        }

        $request = $this->getAuthenticatedRequest($method, $url, $token, $options);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }
}
