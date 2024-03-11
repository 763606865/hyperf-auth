<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Contract\Guard;

use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;
use Junlin\HyperfAuth\Events\Attempting;
use Junlin\HyperfAuth\Events\Authenticated;
use Junlin\HyperfAuth\Events\CurrentDeviceLogout;
use Junlin\HyperfAuth\Events\Failed;
use Junlin\HyperfAuth\Events\Login;
use Junlin\HyperfAuth\Events\Logout;
use Junlin\HyperfAuth\Events\OtherDeviceLogout;
use Junlin\HyperfAuth\Events\Validated;

trait EventHelpers
{
    /**
     * Fire the attempt event with the arguments.
     */
    protected function dispatchAttemptingEvent(array $credentials, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Attempting(
            $this->name,
            $credentials,
            $remember
        ));
    }

    /**
     * Fires the validated event if the dispatcher is set.
     */
    protected function dispatchValidatedEvent(AuthenticatableInterface $user)
    {
        $this->eventDispatcher->dispatch(new Validated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the login event if the dispatcher is set.
     */
    protected function dispatchLoginEvent(AuthenticatableInterface $user, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     */
    protected function dispatchAuthenticatedEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Authenticated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the logout event if the dispatcher is set.
     */
    protected function dispatchLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Logout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the current device logout event if the dispatcher is set.
     */
    protected function dispatchCurrentDeviceLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new CurrentDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the other device logout event if the dispatcher is set.
     */
    protected function dispatchOtherDeviceLogoutEvent(AuthenticatableInterface $user): void
    {
        $this->eventDispatcher->dispatch(new OtherDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     */
    protected function dispatchFailedEvent(?AuthenticatableInterface $user, array $credentials): void
    {
        $this->eventDispatcher->dispatch(new Failed(
            $this->name,
            $user,
            $credentials
        ));
    }
}
