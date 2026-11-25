<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use stdClass;

final class MatchAnyTokenConstraint implements TokenConstraintInterface
{
    public string $name { get => 'any'; }

    public function matches(stdClass $payload): true
    {
        return true;
    }
}
