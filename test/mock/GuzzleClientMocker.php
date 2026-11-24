<?php

namespace test\mock\Ingenerator\OIDCTokenVerifier;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function array_map;
use function array_values;

final class GuzzleClientMocker
{
    /**
     * @var array<int, array{
     *     request: RequestInterface,
     *     response: ResponseInterface|null,
     *     error: mixed,
     *     options: array<array-key, mixed>
     * }>
     */
    private array $history = [];

    private readonly Client $client;

    public static function withResponses(Response ...$responses): static
    {
        return new self(array_values($responses));
    }

    public static function withNoResponses(): static
    {
        return new self([]);
    }

    /**
     * @param list<Response> $mock_responses
     */
    private function __construct(
        array $mock_responses,
    ) {
        $mock = new MockHandler($mock_responses);
        $handler = HandlerStack::create($mock);
        $history = [];
        $handler->push(Middleware::history($history));
        Assert::assertIsArray($history);
        $this->history = &$history;

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

    /**
     * @param list<string> $expect
     */
    public function assertExactRequestSequence(array $expect): void
    {
        $requests = array_map(fn (array $hist): RequestInterface => $hist['request'], $this->history);
        $actual = array_map(
            fn (RequestInterface $req): string => $req->getMethod().' '.$req->getUri(),
            $requests
        );
        Assert::assertSame($expect, $actual);
    }
}
