<?php

namespace test\mock\Ingenerator\OIDCTokenVerifier\Cache;

use BadMethodCallException;
use DateTimeImmutable;
use PHPUnit\Framework\Assert;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

final class MockCacheItemPool implements CacheItemPoolInterface
{
    /**
     * @var MockCacheItem[]
     */
    private array $items = [];

    public static function empty(): MockCacheItemPool
    {
        return new self();
    }

    public function getItem(string $key): CacheItemInterface
    {
        if ($this->hasItem($key)) {
            $item = $this->items[$key];
            $item->markAsCacheHit();

            return $item;
        }

        return MockCacheItem::createMiss($key);
    }

    /**
     * @param list<string> $keys
     *
     * @return iterable<string, CacheItemInterface>
     */
    public function getItems(array $keys = []): iterable
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    public function hasItem(string $key): bool
    {
        if (!isset($this->items[$key])) {
            return false;
        }

        $expires = $this->items[$key]->getExpiresAt();
        if ($expires === null) {
            return true;
        }

        return $expires > new DateTimeImmutable();
    }

    public function clear(): bool
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    public function deleteItem(string $key): bool
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    public function deleteItems(array $keys): bool
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    public function save(CacheItemInterface $item): bool
    {
        Assert::assertInstanceOf(MockCacheItem::class, $item);
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    public function commit(): bool
    {
        throw new BadMethodCallException(__METHOD__.' not mocked');
    }

    /**
     * @return list<string>
     */
    public function listSavedKeys(): array
    {
        return array_keys($this->items);
    }

    public function getOnlyItem(): MockCacheItem
    {
        Assert::assertCount(1, $this->items);
        $key = array_key_first($this->items);

        return $this->items[$key];
    }
}
