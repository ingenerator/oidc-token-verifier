<?php


namespace test\mock\Ingenerator\OIDCTokenVerifier\Cache;


use PHPUnit\Framework\Assert;
use Psr\Cache\CacheItemInterface;

class MockCacheItem implements CacheItemInterface
{

    /**
     * @var \DateTimeImmutable|null
     */
    protected $expires_at;

    /**
     * @var string
     */
    protected $key;

    /**
     * @var mixed
     */
    protected $value;

    /**
     * @var bool
     */
    protected $is_hit;

    public static function createHit(string $key, $value): MockCacheItem
    {
        return new static($key, $value, TRUE);
    }

    public static function createMiss(string $key): MockCacheItem
    {
        return new static($key, NULL, FALSE);
    }

    protected function __construct(string $key, $value, bool $is_hit)
    {
        $this->key    = $key;
        $this->value  = $value;
        $this->is_hit = $is_hit;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function get()
    {
        return $this->value;
    }

    public function isHit()
    {
        return $this->is_hit;
    }

    public function set($value)
    {
        $this->value = $value;
    }

    public function expiresAt($expiration)
    {
        if ($expiration !== NULL) {
            Assert::assertInstanceOf(\DateTimeImmutable::class, $expiration);
        }
        $this->expires_at = $expiration;
    }

    public function expiresAfter($time)
    {
        throw new \BadMethodCallException;
    }

    public function markAsCacheHit()
    {
        $this->is_hit = TRUE;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expires_at;
    }

}
