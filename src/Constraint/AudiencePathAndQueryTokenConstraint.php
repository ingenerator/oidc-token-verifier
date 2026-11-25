<?php

declare(strict_types=1);

namespace Ingenerator\OIDCTokenVerifier\Constraint;

use Ingenerator\OIDCTokenVerifier\TokenConstraintInterface;
use stdClass;

use function parse_url;

final class AudiencePathAndQueryTokenConstraint implements TokenConstraintInterface
{
    public string $name { get => 'audience_path_and_query'; }

    public function __construct(
        public readonly string $expect,
    ) {
    }

    public function matches(stdClass $payload): bool
    {
        if (!is_string($payload->aud ?? null)) {
            return false;
        }

        return $this->parseUrlPathAndQuery($payload->aud) === $this->parseUrlPathAndQuery($this->expect);
    }

    private function parseUrlPathAndQuery(string $url): string
    {
        $parts = parse_url($url);

        return ($parts['path'] ?? null).'?'.($parts['query'] ?? null);
    }
}
