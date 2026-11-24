<?php

namespace test\mock\Ingenerator\OIDCTokenVerifier;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Assert;

use function array_map;

final class GuzzleClientMocker
{
    private array $history = [];

    private readonly Client $client;

    public static function withResponses(Response ...$responses): static
    {
        return new self($responses);
    }

    public static function withNoResponses(): static
    {
        return new self([]);
    }

    private function __construct(
        array $mock_responses,
    ) {
        $mock = new MockHandler($mock_responses);
        $handler = HandlerStack::create($mock);
        $handler->push(Middleware::history($this->history));

        $this->client = new Client(['handler' => $handler]);
    }

    public function getClient(): Client
    {
        return $this->client;
    }

    public function assertNoRequestsSent(): void
    {
        Assert::assertCount(0, $this->history, 'Expected no requests to be sent');
    }

    public function assertExactRequestSequence(array $expect): void
    {
        $requests = array_map(fn (array $hist) => $hist['request'], $this->history);
        $actual = array_map(
            fn (Request $req): string => $req->getMethod().' '.$req->getUri(),
            $requests
        );
        Assert::assertSame($expect, $actual);
    }
}
