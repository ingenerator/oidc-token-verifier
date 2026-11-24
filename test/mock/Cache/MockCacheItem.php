<?php

declare(strict_types=1);

namespace test\mock\Ingenerator\OIDCTokenVerifier\Cache;

use BadMethodCallException;
use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use PHPUnit\Framework\Assert;
use Psr\Cache\CacheItemInterface;

final class MockCacheItem implements CacheItemInterface
{
    private ?DateTimeImmutable $expires_at = null;

    public static function createHit(string $key, mixed $value): MockCacheItem
    {
        return new self($key, $value, true);
    }

    public static function createMiss(string $key): MockCacheItem
    {
        return new self($key, null, false);
    }

    private function __construct(
        private readonly string $key,
        private mixed $value,
        private bool $is_hit,
    ) {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->value;
    }

    public function isHit(): bool
    {
        return $this->is_hit;
    }

    public function set(mixed $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function expiresAt(?DateTimeInterface $expiration): static
    {
        if ($expiration instanceof DateTimeInterface) {
            Assert::assertInstanceOf(DateTimeImmutable::class, $expiration);
        }
        $this->expires_at = $expiration;

        return $this;
    }

    public function expiresAfter(int|DateInterval|null $time): static
    {
        throw new BadMethodCallException();
    }

    public function markAsCacheHit(): void
    {
        $this->is_hit = true;
    }

    public function getExpiresAt(): ?DateTimeImmutable
    {
        return $this->expires_at;
    }
}
