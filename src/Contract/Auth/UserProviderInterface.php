<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Contract\Auth;

interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     *
     * @param mixed $identifier
     * @return AuthenticatableInterface|null
     */
    public function retrieveById($identifier): AuthenticatableInterface|null;

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return AuthenticatableInterface|null
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface;

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  AuthenticatableInterface  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void;

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return AuthenticatableInterface|null
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface;

    /**
     * Validate a user against the given credentials.
     *
     * @param  AuthenticatableInterface  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool;
}
