<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use stdClass;

use function preg_match;

final class EmailMatchTokenConstraint implements TokenConstraintInterface
{
    public string $name { get => 'email_match'; }

    public function __construct(
        public readonly string $expect,
    ) {
    }

    public function matches(stdClass $payload): bool
    {
        if (!is_string($payload->email ?? null)) {
            return false;
        }

        return (bool) preg_match($this->expect, $payload->email);
    }
}
