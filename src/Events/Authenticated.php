<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Events;

use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;

class Authenticated
{
    /**
     * Create a new event instance.
     *
     * @param  string  $guard The authentication guard name.
     * @param AuthenticatableInterface $user The authenticated user.
     * @return void
     */
    public function __construct(public string $guard, public AuthenticatableInterface $user)
    {
    }
}
