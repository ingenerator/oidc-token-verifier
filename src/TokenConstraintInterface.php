<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier;

use stdClass;

interface TokenConstraintInterface
{
    public string $name { get; }

    public function matches(stdClass $payload): bool;
}
