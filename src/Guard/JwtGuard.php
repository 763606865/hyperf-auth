<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Guard;

use Hyperf\Engine\Contract\Http\V2\RequestInterface;
use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;
use Junlin\HyperfAuth\Contract\Auth\GuardInterface;
use Junlin\HyperfAuth\Contract\Auth\UserProviderInterface;
use Junlin\HyperfAuth\Contract\Guard\GuardHelpers;
use Junlin\HyperfAuth\Jwt;
use Psr\EventDispatcher\EventDispatcherInterface;

class JwtGuard implements GuardInterface
{
    use GuardHelpers;

    protected $jwt;

    protected $options;

    protected $name;

    protected $request;

    /**
     * @var \Psr\EventDispatcher\EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * Create a new authentication guard.
     *
     * @param UserProviderInterface $provider
     * @param RequestInterface $request
     * @param EventDispatcherInterface $eventDispatcher
     * @param string $name
     * @param array $options
     */
    public function __construct(
        UserProviderInterface  $provider,
        RequestInterface $request,
        EventDispatcherInterface $eventDispatcher,
        string                 $name,
        array                  $options = [])
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->options = $options;
        $this->eventDispatcher = $eventDispatcher;
        $this->name = $name;
        $this->jwt = new Jwt($this->options['secret'] ?? '');
    }

    /**
     * Get the currently authenticated user.
     *
     * @return AuthenticatableInterface|null
     */
    public function user(): ?AuthenticatableInterface
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (! empty($token)) {
            $identifier = $this->jwt->verify($token);
            if ($user = $this->provider->retrieveById($identifier)) {
            }
        }

        return $this->user = $user;
    }

    /**
     * Get the token for the current request.
     *
     * @return string
     */
    public function getTokenForRequest()
    {
        return $this->getBearerToken($this->request);
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        if ($this->provider->retrieveByCredentials($credentials)) {
            return true;
        }

        return false;
    }

    /**
     * Set the current request instance.
     *
     * @param RequestInterface $request
     * @return $this
     */
    public function setRequest(RequestInterface $request)
    {
        $this->request = $request;

        return $this;
    }

    public function login()
    {
        if (is_null($this->user)) {
            return null;
        }

        if ($token = $this->jwt->generate((string)$this->user->getAuthIdentifier())) {

        }

        return $token;
    }

    /**
     * Get the bearer token from the request headers.
     *
     * @return string|null
     */
    protected function getBearerToken(RequestInterface $request)
    {
        $header = $request->getHeaders()['Authorization'];

        $position = strrpos($header, 'Bearer ');

        if ($position !== false) {
            $header = substr($header, $position + 7);

            return str_contains($header, ',') ? strstr($header, ',', true) : $header;
        }

        return null;
    }
}
