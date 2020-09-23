<?php


namespace test\mock\Ingenerator\OIDCTokenVerifier;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use PHPUnit\Framework\Assert;

class GuzzleClientMocker
{

    protected $mock;

    /**
     * @var array
     */
    protected $history = [];

    /**
     * @var Client
     */
    protected $client;

    public static function withResponses(Response ...$responses)
    {
        return new static($responses);
    }

    public static function withNoResponses()
    {
        return new static([]);
    }

    protected function __construct(array $mock_responses)
    {
        $mock    = new MockHandler($mock_responses);
        $handler = HandlerStack::create($mock);
        $handler->push(Middleware::history($this->history));

        $this->client = new Client(['handler' => $handler]);
    }

    public function getClient(): Client
    {
        return $this->client;
    }

    public function assertNoRequestsSent()
    {
        Assert::assertCount(0, $this->history, 'Expected no requests to be sent');
    }

    public function assertExactRequestSequence(array $expect)
    {
        $requests = \array_map(function ($hist) { return $hist['request']; }, $this->history);
        $actual   = \array_map(
            function (Request $req) { return $req->getMethod().' '.$req->getUri(); },
            $requests
        );
        Assert::assertSame($expect, $actual);
    }

}
