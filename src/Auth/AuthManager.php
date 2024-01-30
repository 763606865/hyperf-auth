<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Auth;

use Hyperf\Contract\ConfigInterface;
use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;
use Junlin\HyperfAuth\Contract\Auth\AuthManagerInterface;
use Junlin\HyperfAuth\Contract\Auth\GuardInterface;
use Closure;
use InvalidArgumentException;

/**
 * Class AuthManager.
 * @method login(AuthenticatableInterface $user)
 * @method null|AuthenticatableInterface user($token = null)
 * @method bool check($token = null)
 * @method logout()
 * @method string getName()
 * @method bool guest()
 * @method getProvider()
 * @method id($token = null)
 * @mixin GuardInterface
 */
class AuthManager implements AuthManagerInterface
{
    public function __construct(protected ConfigInterface $config)
    {
        $this->resolveUsersUsing($this->getUserResolverClosure());
    }

    /**
     * Dynamically call the default driver instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        return $this->guard()->{$method}(...$parameters);
    }

    /**
     * Attempt to get the guard from the local cache.
     *
     * @param string|null  $name
     * @return GuardInterface
     */
    public function guard(?string $name = null): GuardInterface
    {
        $name = $name ?? $this->getDefaultDriver();
        $id = 'guards.' . $name;
        return $this->getContext($id) ?: $this->setContext($id, $this->resolve($name));
    }

    /**
     * Get the user resolver callback.
     *
     * @return Closure
     */
    public function userResolver()
    {
        return $this->getContext('userResolver');
    }

    /**
     * Set the callback to be used to resolve users.
     *
     * @return $this
     */
    public function resolveUsersUsing(Closure $userResolver)
    {
        $this->setContext('userResolver', $userResolver);

        return $this;
    }

    /**
     * Get the default authentication driver name.
     *
     * @return string
     */
    public function getDefaultDriver(): string
    {
        return $this->getContext('defaults.guard', $this->setContext('defaults.guard', $this->config->get('auth.defaults.guard')));
    }

    /**
     * Set the default guard driver the factory should serve.
     *
     * @param  ?string  $name
     * @return void
     */
    public function shouldUse(?string $name): void
    {
        $name = $name ?: $this->getDefaultDriver();

        $this->setDefaultDriver($name);

        $this->resolveUsersUsing($this->getUserResolverClosure());
    }

    /**
     * Set the default authentication driver name.
     *
     * @param  string  $name
     * @return void
     */
    public function setDefaultDriver(string $name)
    {
        $this->setContext('defaults.guard', $name);
    }

    /**
     * Resolve the given guard.
     *
     * @param string $name
     * @return GuardInterface
     * @throws InvalidArgumentException
     */
    protected function resolve(string $name)
    {
        $config = $this->getConfig($name);

        $driver = $config['driver'] ?? null;
        if (empty($driver)) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }

        $provider = $this->createUserProvider($config['provider']);
        $options = $config['options'] ?? [];
        $driver = '\\' . ltrim($driver, '\\');
        return make($driver, compact('provider', 'name', 'options'));
    }

    /**
     * Get user resolver closure.
     *
     * @return Closure
     */
    protected function getUserResolverClosure()
    {
        return fn ($name = null) => $this->guard($name)->user();
    }

    /**
     * Get the guard configuration.
     *
     * @param  string  $name
     * @return array
     */
    protected function getConfig(string $name)
    {
        return $this->config->get("auth.guards.{$name}");
    }
}
