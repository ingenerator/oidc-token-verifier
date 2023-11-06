<?php


namespace test\mock\Ingenerator\OIDCTokenVerifier\Cache;


use PHPUnit\Framework\Assert;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

class MockCacheItemPool implements CacheItemPoolInterface
{

    /**
     * @var \test\mock\Ingenerator\OIDCTokenVerifier\Cache\MockCacheItem[]
     */
    protected $items = [];

    public static function empty(): MockCacheItemPool
    {
        return new static;
    }

    public function getItem(string $key): CacheItemInterface
    {
        if ($this->hasItem($key)) {
            $item = $this->items[$key];
            $item->markAsCacheHit();

            return $item;
        } else {
            return MockCacheItem::createMiss($key);
        }
    }

    public function getItems(array $keys = []): iterable
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function hasItem(string $key): bool
    {
        if ( ! isset($this->items[$key])) {
            return FALSE;
        }

        $expires = $this->items[$key]->getExpiresAt();
        if ($expires === NULL) {
            return TRUE;
        }

        return $expires > new \DateTimeImmutable;
    }

    public function clear(): bool
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function deleteItem(string $key): bool
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function deleteItems(array $keys): bool
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function save(CacheItemInterface $item): bool
    {
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function commit(): bool
    {
        throw new \BadMethodCallException(__METHOD__.' not mocked');
    }

    public function listSavedKeys()
    {
        return array_keys($this->items);
    }

    public function getOnlyItem(): MockCacheItem
    {
        Assert::assertCount(1, $this->items);
        reset($this->items);

        return \current($this->items);
    }

}
