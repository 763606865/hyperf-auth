<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Events;

use Junlin\HyperfAuth\Contract\Auth\AuthenticatableInterface;

class Failed
{
    /**
     * Create a new event instance.
     *
     * @param  string  $guard The authentication guard name.
     * @param AuthenticatableInterface|null  $user The user the attempter was trying to authenticate as.
     * @param  array  $credentials The credentials provided by the attempter.
     * @return void
     */
    public function __construct(public string $guard, public ?AuthenticatableInterface $user, public array $credentials)
    {
    }
}
