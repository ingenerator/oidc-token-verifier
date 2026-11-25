<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use stdClass;

final class AudienceExactTokenConstraint implements TokenConstraintInterface
{
    public string $name { get => 'audience_exact'; }

    public function __construct(
        public readonly string $expect,
    ) {
    }

    public function matches(stdClass $payload): bool
    {
        return $this->expect === ($payload->aud ?? null);
    }
}
