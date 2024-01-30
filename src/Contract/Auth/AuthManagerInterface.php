<?php

declare(strict_types=1);

namespace Junlin\HyperfAuth\Contract\Auth;

interface AuthManagerInterface
{
    /**
     * Get a guard instance by name.
     *
     * @return GuardInterface
     */
    public function guard(?string $name = null): GuardInterface;

    /**
     * Set the default guard the factory should serve.
     */
    public function shouldUse(?string $name): void;
}
