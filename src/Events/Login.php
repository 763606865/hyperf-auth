<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Events;

use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;

class Login
{
    /**
     * Create a new event instance.
     *
     * @param  string  $guard The authentication guard name.
     * @param AuthenticatableInterface $user The authenticated user.
     * @param  bool  $remember Indicates if the user should be “remembered”.
     * @return void
     */
    public function __construct(public string $guard, public AuthenticatableInterface $user, public bool $remember)
    {
    }
}
