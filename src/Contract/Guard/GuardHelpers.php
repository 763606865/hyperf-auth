<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Contract\Guard;


use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;
use Junlin\HyperfAuth\Contract\Auth\UserProviderInterface;
use Junlin\HyperfAuth\Exception\AuthenticationException;

trait GuardHelpers
{
    /**
     * The currently authenticated user.
     *
     * @var AuthenticatableInterface|null
     */
    protected $user;

    /**
     * The user provider implementation.
     *
     * @var UserProviderInterface
     */
    protected $provider;

    /**
     * Determine if the current user is authenticated. If not, throw an exception.
     *
     * @return AuthenticatableInterface
     *
     * @throws AuthenticationException
     */
    public function authenticate()
    {
        if (! is_null($user = $this->user())) {
            return $user;
        }

        throw new AuthenticationException;
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser(): bool
    {
        return ! is_null($this->user);
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check(): bool
    {
        return ! is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }
    }

    /**
     * Set the current user.
     *
     * @param  AuthenticatableInterface  $user
     * @return $this
     */
    public function setUser(AuthenticatableInterface $user)
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Forget the current user.
     *
     * @return $this
     */
    public function forgetUser()
    {
        $this->user = null;

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @return UserProviderInterface
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param  UserProviderInterface  $provider
     * @return void
     */
    public function setProvider(UserProviderInterface $provider)
    {
        $this->provider = $provider;
    }
}
