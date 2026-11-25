<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use stdClass;

use function array_values;
use function in_array;

final class EmailExactTokenConstraint implements TokenConstraintInterface
{
    public string $name { get => 'email_exact'; }

    /**
     * @var list<string>
     */
    public readonly array $expect;

    public function __construct(string ...$expect)
    {
        $this->expect = array_values($expect);
    }

    public function matches(stdClass $payload): bool
    {
        return in_array($payload->email ?? null, $this->expect, true);
    }
}
