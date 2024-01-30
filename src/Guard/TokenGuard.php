<?php

declare(strict_types=1);

namespace App\Libs\Foundation\Auth;

use App\Libs\Foundation\Contract\Auth\AuthenticatableInterface;
use App\Libs\Foundation\Contract\Auth\GuardInterface;
use App\Libs\Foundation\Contract\Auth\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenGuard implements GuardInterface
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * The name of the query string item from the request containing the API token.
     *
     * @var string
     */
    protected $inputKey;

    /**
     * The name of the token "column" in persistent storage.
     *
     * @var string
     */
    protected $storageKey;

    /**
     * Indicates if the API token is hashed in storage.
     *
     * @var bool
     */
    protected $hash = false;

    /**
     * Create a new authentication guard.
     *
     * @param UserProviderInterface $provider
     * @param ServerRequestInterface $request
     * @param string $name
     * @param array $options
     * @return void
     */
    public function __construct(
        UserProviderInterface  $provider,
        ServerRequestInterface $request,
        string                 $name,
        array                  $options = [])
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->inputKey = $options['input_key'] ?? 'api_token';
        $this->storageKey = $options['storage_key'] ?? 'api_token';
        $this->hash = $options['hash'] ?? false;
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
            $user = $this->provider->retrieveByCredentials([
                $this->storageKey => $this->hash ? hash('sha256', $token) : $token,
            ]);
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
        $token = $this->request->query($this->inputKey);

        if (empty($token)) {
            $token = $this->request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $this->getBearerToken($this->request);
        }

        if (empty($token)) {
            $token = $this->request->getHeaderLine('PHP_AUTH_PW');
        }

        return $token;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        if (empty($credentials[$this->inputKey])) {
            return false;
        }

        $credentials = [$this->storageKey => $credentials[$this->inputKey]];

        if ($this->provider->retrieveByCredentials($credentials)) {
            return true;
        }

        return false;
    }

    /**
     * Set the current request instance.
     *
     * @param ServerRequestInterface $request
     * @return $this
     */
    public function setRequest(ServerRequestInterface $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the bearer token from the request headers.
     *
     * @return string|null
     */
    protected function getBearerToken(ServerRequestInterface $request)
    {
        $header = $request->getHeaderLine('Authorization', '');

        $position = strrpos($header, 'Bearer ');

        if ($position !== false) {
            $header = substr($header, $position + 7);

            return str_contains($header, ',') ? strstr($header, ',', true) : $header;
        }

        return null;
    }
}