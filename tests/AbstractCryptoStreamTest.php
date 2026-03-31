<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use GuzzleHttp\Psr7\Stream;
use Infra\StreamEncryption\Stream\AbstractCryptoStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

final class AbstractCryptoStreamTest extends TestCase
{
    public function testItLazilyCreatesAndReusesTheInternalStream(): void
    {
        $stream = new CountingCryptoStream(fn (): StreamInterface => $this->createNativeStream('hello'));

        $this->assertSame(0, $stream->createdCount);
        $this->assertSame('he', $stream->read(2));
        $this->assertSame(1, $stream->createdCount);
        $this->assertSame('llo', $stream->getContents());
        $this->assertSame(1, $stream->createdCount);
    }

    public function testCloseClearsTheOwnedStreamAndAllowsRecreation(): void
    {
        $firstStream = new SpyStream('hello');
        $secondStream = new SpyStream('recreated');
        $createCount = 0;
        $stream = new CountingCryptoStream(
            static function () use ($firstStream, $secondStream, &$createCount): StreamInterface {
                $createCount++;

                return $createCount === 1 ? $firstStream : $secondStream;
            },
        );

        $this->assertSame('he', $stream->read(2));

        $stream->close();

        $this->assertTrue($firstStream->closeCalled);
        $this->assertSame('recreated', (string) $stream);
        $this->assertSame(2, $stream->createdCount);
    }

    public function testCloseBeforeInitializationIsSafe(): void
    {
        $stream = new CountingCryptoStream(fn (): StreamInterface => $this->createNativeStream('hello'));

        $stream->close();

        $this->assertSame(0, $stream->createdCount);
    }

    public function testDetachReturnsTheUnderlyingResourceClearsOwnershipAndAllowsRecreation(): void
    {
        $firstResource = fopen('php://temp', 'r+');
        fwrite($firstResource, 'hello');
        rewind($firstResource);
        $secondResource = fopen('php://temp', 'r+');
        fwrite($secondResource, 'recreated');
        rewind($secondResource);
        $createCount = 0;

        $stream = new CountingCryptoStream(
            static function () use ($firstResource, $secondResource, &$createCount): StreamInterface {
                $createCount++;

                return new Stream($createCount === 1 ? $firstResource : $secondResource);
            },
        );

        $this->assertSame('he', $stream->read(2));

        $detached = $stream->detach();

        $this->assertIsResource($detached);
        $this->assertSame('stream', get_resource_type($detached));
        $this->assertSame('llo', stream_get_contents($detached));
        $this->assertSame(1, $stream->createdCount);
        $this->assertSame('recreated', (string) $stream);
        $this->assertSame(2, $stream->createdCount);

        fclose($detached);
    }

    public function testDetachBeforeInitializationReturnsNull(): void
    {
        $stream = new CountingCryptoStream(fn (): StreamInterface => $this->createNativeStream('hello'));

        $this->assertNull($stream->detach());
        $this->assertSame(0, $stream->createdCount);
    }

    public function testAfterDetachCloseDoesNotCloseTheDetachedResource(): void
    {
        $spyStream = new SpyStream('hello');
        $stream = new CountingCryptoStream(static fn (): StreamInterface => $spyStream);

        $stream->read(1);
        $detached = $stream->detach();
        $stream->close();

        $this->assertIsResource($detached);
        $this->assertFalse($spyStream->closeCalled);

        fclose($detached);
    }

    public function testItDelegatesReadSeekAndMetadataOperations(): void
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, 'hello');
        rewind($resource);

        $stream = new CountingCryptoStream(
            static fn (): StreamInterface => new Stream($resource, ['metadata' => ['foo' => 'bar']]),
        );

        $this->assertTrue($stream->isReadable());
        $this->assertTrue($stream->isSeekable());
        $this->assertSame(5, $stream->getSize());
        $this->assertSame(0, $stream->tell());
        $this->assertSame('he', $stream->read(2));
        $this->assertSame(2, $stream->tell());
        $this->assertFalse($stream->eof());
        $stream->seek(4);
        $this->assertSame('o', $stream->read(1));
        $this->assertSame('', $stream->read(1));
        $this->assertTrue($stream->eof());
        $stream->rewind();
        $this->assertSame('hello', $stream->getContents());
        $this->assertSame('bar', $stream->getMetadata('foo'));
        $this->assertIsArray($stream->getMetadata());

        $stream->close();
    }

    public function testItIsReadOnlyWithoutForcingInitialization(): void
    {
        $stream = new CountingCryptoStream(fn (): StreamInterface => $this->createNativeStream('hello'));

        $this->assertFalse($stream->isWritable());
        $this->assertSame(0, $stream->createdCount);

        $this->expectException(RuntimeException::class);

        $stream->write('nope');
    }

    public function testToStringReturnsEmptyStringWhenCreationFails(): void
    {
        $stream = new FailingCryptoStream();

        $this->assertSame('', (string) $stream);
    }

    private function createNativeStream(string $contents): StreamInterface
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $contents);
        rewind($resource);

        return new Stream($resource);
    }
}

final class CountingCryptoStream extends AbstractCryptoStream
{
    public int $createdCount = 0;

    /**
     * @param \Closure(): StreamInterface $factory
     */
    public function __construct(
        private readonly \Closure $factory,
    ) {
    }

    protected function createInternalStream(): StreamInterface
    {
        $this->createdCount++;

        $factory = $this->factory;

        return $factory();
    }
}

final class FailingCryptoStream extends AbstractCryptoStream
{
    protected function createInternalStream(): StreamInterface
    {
        throw new RuntimeException('boom');
    }
}

final class SpyStream implements StreamInterface
{
    public bool $closeCalled = false;

    /** @var resource|null */
    private $resource;

    public function __construct(string $contents)
    {
        $this->resource = fopen('php://temp', 'r+');
        fwrite($this->resource, $contents);
        rewind($this->resource);
    }

    public function __toString(): string
    {
        if ($this->resource === null) {
            return '';
        }

        $this->rewind();

        return stream_get_contents($this->resource) ?: '';
    }

    public function close(): void
    {
        $this->closeCalled = true;

        if ($this->resource !== null) {
            fclose($this->resource);
            $this->resource = null;
        }
    }

    public function detach()
    {
        $resource = $this->resource;
        $this->resource = null;

        return $resource;
    }

    public function getSize(): ?int
    {
        if ($this->resource === null) {
            return null;
        }

        $stats = fstat($this->resource);

        return is_array($stats) ? $stats['size'] : null;
    }

    public function tell(): int
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        $position = ftell($this->resource);

        if ($position === false) {
            throw new RuntimeException('Unable to determine position');
        }

        return $position;
    }

    public function eof(): bool
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        return feof($this->resource);
    }

    public function isSeekable(): bool
    {
        return $this->resource !== null;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        if (fseek($this->resource, $offset, $whence) === -1) {
            throw new RuntimeException('Unable to seek');
        }
    }

    public function rewind(): void
    {
        $this->seek(0);
    }

    public function isWritable(): bool
    {
        return true;
    }

    public function write(string $string): int
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        $written = fwrite($this->resource, $string);

        if ($written === false) {
            throw new RuntimeException('Unable to write');
        }

        return $written;
    }

    public function isReadable(): bool
    {
        return $this->resource !== null;
    }

    public function read(int $length): string
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        $contents = fread($this->resource, $length);

        if ($contents === false) {
            throw new RuntimeException('Unable to read');
        }

        return $contents;
    }

    public function getContents(): string
    {
        if ($this->resource === null) {
            throw new RuntimeException('Stream is detached');
        }

        $contents = stream_get_contents($this->resource);

        if ($contents === false) {
            throw new RuntimeException('Unable to get contents');
        }

        return $contents;
    }

    public function getMetadata(?string $key = null)
    {
        if ($this->resource === null) {
            return $key === null ? [] : null;
        }

        $metadata = stream_get_meta_data($this->resource);

        return $key === null ? $metadata : ($metadata[$key] ?? null);
    }
}
