<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use GuzzleHttp\Psr7\NoSeekStream;
use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use Infra\StreamEncryption\Stream\EncryptingStream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class EncryptingStreamTest extends TestCase
{
    public function testItLazilyEncryptsOnceAndReusesTheMaterializedPayload(): void
    {
        $source = $this->createInstrumentedSourceStream('hello world');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::IMAGE);

        $firstRead = $stream->read(5);
        $rest = $stream->getContents();

        $this->assertNotSame('', $firstRead . $rest);
        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);

        $stream->rewind();
        $stream->getContents();

        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);
    }

    public function testItIsReadOnly(): void
    {
        $stream = new EncryptingStream(Utils::streamFor('plain'), random_bytes(32), MediaType::VIDEO);

        $this->assertFalse($stream->isWritable());

        $this->expectException(RuntimeException::class);

        $stream->write('blocked');
    }

    public function testItProducesCiphertextMacPayloadShape(): void
    {
        $plaintext = 'payload-structure-check';
        $mediaKey = random_bytes(32);
        $mediaType = MediaType::DOCUMENT;
        $encryptor = new Encryptor();
        $expected = $encryptor->encrypt($plaintext, $mediaKey, $mediaType);

        $stream = new EncryptingStream(Utils::streamFor($plaintext), $mediaKey, $mediaType, $encryptor);

        $this->assertSame($expected->ciphertext . $expected->mac, (string) $stream);
    }

    public function testItDelegatesReadSeekTellEofAndContentsToTheInternalPayloadStream(): void
    {
        $stream = new EncryptingStream(Utils::streamFor('delegation-content'), random_bytes(32), MediaType::AUDIO);

        $this->assertTrue($stream->isReadable());
        $this->assertTrue($stream->isSeekable());
        $this->assertSame(0, $stream->tell());

        $first = $stream->read(8);

        $this->assertSame(8, strlen($first));
        $this->assertSame(8, $stream->tell());

        $stream->seek(0);

        $this->assertSame(0, $stream->tell());

        $payload = $stream->getContents();

        $this->assertNotSame('', $payload);
        $this->assertTrue($stream->eof());

        $stream->rewind();

        $this->assertFalse($stream->eof());
        $this->assertNotNull($stream->getSize());
    }

    public function testCompatibilityMatrixForDelegatedMethodsInitializesOnceAndStaysStable(): void
    {
        $source = $this->createInstrumentedSourceStream('compatibility-matrix-payload');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::IMAGE);

        $this->assertSame(0, $source->rewindCalls, 'encrypting/tell precondition: no rewind before delegated calls');
        $this->assertSame(0, $source->getContentsCalls, 'encrypting/tell precondition: no source reads before delegated calls');

        $this->assertSame(0, $stream->tell(), 'encrypting/tell after first delegated call');
        $this->assertTrue($stream->isReadable(), 'encrypting/isReadable should delegate to internal stream');
        $this->assertTrue($stream->isSeekable(), 'encrypting/isSeekable should delegate to internal stream');
        $this->assertNotNull($stream->getSize(), 'encrypting/getSize should return payload size');
        $this->assertIsArray($stream->getMetadata(), 'encrypting/getMetadata should return metadata array');
        $this->assertNotNull($stream->getMetadata('uri'), 'encrypting/getMetadata(uri) should expose stream URI');

        $prefix = $stream->read(4);
        $this->assertSame(4, strlen($prefix), 'encrypting/read should return requested byte count for non-eof read');
        $this->assertSame(4, $stream->tell(), 'encrypting/tell should move after read');
        $this->assertFalse($stream->eof(), 'encrypting/eof should remain false before full consumption');

        $stream->seek(0);
        $this->assertSame(0, $stream->tell(), 'encrypting/seek should reset cursor');

        $stream->getContents();
        $this->assertTrue($stream->eof(), 'encrypting/getContents should consume remaining payload');

        $stream->rewind();
        $this->assertFalse($stream->eof(), 'encrypting/rewind should clear eof state');
        $this->assertSame(1, $source->rewindCalls, 'encrypting compatibility: source rewind should happen once');
        $this->assertSame(1, $source->getContentsCalls, 'encrypting compatibility: source read should happen once');
    }

    public function testCloseClosesSourceAndInternalStreamAndIsIdempotent(): void
    {
        $source = $this->createInstrumentedSourceStream('owned-source');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::IMAGE);

        $stream->read(1);
        $stream->close();
        $stream->close();

        $this->assertTrue($source->closeCalled);
    }

    public function testCloseBeforeInitializationStillClosesSource(): void
    {
        $source = $this->createInstrumentedSourceStream('owned-source');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::IMAGE);

        $stream->close();

        $this->assertTrue($source->closeCalled);
    }

    public function testDetachDetachesSourceAndReturnsInternalResourceWhenInitialized(): void
    {
        $source = $this->createInstrumentedSourceStream('detach-source');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::VIDEO);

        $stream->read(2);
        $detached = $stream->detach();

        $this->assertIsResource($detached);
        $this->assertSame(1, $source->detachCalls);
        $this->assertNull($stream->detach());
        $this->assertSame(2, $source->detachCalls);

        fclose($detached);
    }

    public function testDetachBeforeInitializationReturnsNullAndStillDetachesSource(): void
    {
        $source = $this->createInstrumentedSourceStream('not-initialized');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::AUDIO);

        $this->assertNull($stream->detach());
        $this->assertSame(1, $source->detachCalls);
    }

    public function testConstructorRejectsUnreadableSource(): void
    {
        $source = Utils::streamFor('unreadable');
        $source->detach();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Source stream must be readable.');

        new EncryptingStream($source, random_bytes(32), MediaType::IMAGE);
    }

    public function testItPropagatesSourceRewindFailureOnRead(): void
    {
        $source = $this->createInstrumentedSourceStream('boom');
        $source->failOnRewind = true;
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rewind failure');

        $stream->read(1);
    }

    public function testItPropagatesSourceGetContentsFailureOnGetContents(): void
    {
        $source = $this->createInstrumentedSourceStream('boom');
        $source->failOnGetContents = true;
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('getContents failure');

        $stream->getContents();
    }

    public function testToStringFallsBackToEmptyStringOnSourceFailure(): void
    {
        $source = $this->createInstrumentedSourceStream('boom');
        $source->failOnGetContents = true;
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::DOCUMENT);

        $this->assertSame('', (string) $stream);
    }

    public function testRepeatedToStringReadsReuseMaterializedPayload(): void
    {
        $source = $this->createInstrumentedSourceStream('repeatable-string-read');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::DOCUMENT);

        $first = (string) $stream;
        $second = (string) $stream;

        $this->assertSame($first, $second);
        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);
    }

    public function testItPropagatesInvalidMediaKeyExceptionsFromTheCryptoLayer(): void
    {
        $stream = new EncryptingStream(Utils::streamFor('payload'), random_bytes(16), MediaType::IMAGE);

        $this->expectException(InvalidMediaKeyException::class);

        $stream->read(1);
    }

    public function testItHandlesEmptyPlaintext(): void
    {
        $mediaKey = random_bytes(32);
        $stream = new EncryptingStream(Utils::streamFor(''), $mediaKey, MediaType::IMAGE);
        $payload = (string) $stream;

        $this->assertNotSame('', $payload);

        $decryptor = new Decryptor();

        $this->assertSame('', $decryptor->decrypt($payload, $mediaKey, MediaType::IMAGE));
    }

    public function testItHandlesBinaryPlaintextWithNullBytes(): void
    {
        $plaintext = "bin\x00ary\x00payload\x01\x02\x03";
        $mediaKey = random_bytes(32);
        $stream = new EncryptingStream(Utils::streamFor($plaintext), $mediaKey, MediaType::VIDEO);

        $decryptor = new Decryptor();

        $this->assertSame($plaintext, $decryptor->decrypt((string) $stream, $mediaKey, MediaType::VIDEO));
    }

    public function testItHandlesLargePlaintextBuffers(): void
    {
        $plaintext = random_bytes(1024 * 1024);
        $mediaKey = random_bytes(32);
        $stream = new EncryptingStream(Utils::streamFor($plaintext), $mediaKey, MediaType::AUDIO);

        $decryptor = new Decryptor();

        $this->assertSame($plaintext, $decryptor->decrypt((string) $stream, $mediaKey, MediaType::AUDIO));
    }

    public function testSeekableSourcesEncryptFromStartEvenWhenPreConsumed(): void
    {
        $plaintext = 'seekable-source-data';
        $mediaKey = random_bytes(32);
        $source = Utils::streamFor($plaintext);

        $source->read(5);

        $stream = new EncryptingStream($source, $mediaKey, MediaType::DOCUMENT);

        $decryptor = new Decryptor();

        $this->assertSame($plaintext, $decryptor->decrypt((string) $stream, $mediaKey, MediaType::DOCUMENT));
    }

    public function testGuzzleResourceBackedStreamsRemainCompatibleForEncryption(): void
    {
        $plaintext = 'resource-backed-stream-data';
        $mediaKey = random_bytes(32);
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $plaintext);
        rewind($resource);
        $source = Utils::streamFor($resource);

        $source->read(5);

        $stream = new EncryptingStream($source, $mediaKey, MediaType::VIDEO);
        $decryptor = new Decryptor();

        $this->assertSame($plaintext, $decryptor->decrypt((string) $stream, $mediaKey, MediaType::VIDEO));
    }

    public function testNonSeekableSourcesEncryptRemainingBytesFromCurrentCursor(): void
    {
        $base = Utils::streamFor('non-seekable-source-data');
        $base->read(4);
        $source = new NoSeekStream($base);
        $mediaKey = random_bytes(32);

        $stream = new EncryptingStream($source, $mediaKey, MediaType::AUDIO);

        $decryptor = new Decryptor();

        $this->assertSame('seekable-source-data', $decryptor->decrypt((string) $stream, $mediaKey, MediaType::AUDIO));
    }

    public function testPreConsumedNonSeekableSourceCanEncryptEmptyRemainder(): void
    {
        $base = Utils::streamFor('all-consumed');

        while (!$base->eof()) {
            $base->read(1024);
        }

        $source = new NoSeekStream($base);
        $mediaKey = random_bytes(32);
        $stream = new EncryptingStream($source, $mediaKey, MediaType::IMAGE);

        $decryptor = new Decryptor();

        $this->assertSame('', $decryptor->decrypt((string) $stream, $mediaKey, MediaType::IMAGE));
    }

    public function testReadAfterDetachFailsWhenSourceIsNoLongerReadable(): void
    {
        $source = $this->createInstrumentedSourceStream('detach-lifecycle-check');
        $stream = new EncryptingStream($source, random_bytes(32), MediaType::AUDIO);

        $stream->detach();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Source stream is not readable.');

        $stream->read(1);
    }

    #[DataProvider('mediaTypeAndFixtureProvider')]
    public function testEndToEndRoundTripAcrossMediaTypes(MediaType $mediaType, string $plaintext): void
    {
        $mediaKey = random_bytes(32);
        $stream = new EncryptingStream(Utils::streamFor($plaintext), $mediaKey, $mediaType);

        $decryptor = new Decryptor();

        $this->assertSame($plaintext, $decryptor->decrypt((string) $stream, $mediaKey, $mediaType));
    }

    /**
     * @return array<string, array{0: MediaType, 1: string}>
     */
    public static function mediaTypeAndFixtureProvider(): array
    {
        return [
            'image-small-binary' => [MediaType::IMAGE, "\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR"],
            'video-random-chunk' => [MediaType::VIDEO, random_bytes(128)],
            'audio-with-null-bytes' => [MediaType::AUDIO, "ID3\x00\x10\xFF\x00audio"],
            'document-utf8-and-binary' => [MediaType::DOCUMENT, "PDF\x00\x01body\n\xFF\xFE"],
        ];
    }

    private function createInstrumentedSourceStream(string $contents): InstrumentedSourceStream
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $contents);
        rewind($resource);

        return new InstrumentedSourceStream($resource);
    }
}

final class InstrumentedSourceStream extends Stream
{
    public bool $closeCalled = false;
    public int $detachCalls = 0;
    public int $rewindCalls = 0;
    public int $getContentsCalls = 0;
    public bool $failOnRewind = false;
    public bool $failOnGetContents = false;

    public function close(): void
    {
        $this->closeCalled = true;

        parent::close();
    }

    public function detach()
    {
        $this->detachCalls++;

        return parent::detach();
    }

    public function rewind(): void
    {
        $this->rewindCalls++;

        if ($this->failOnRewind) {
            throw new RuntimeException('rewind failure');
        }

        parent::rewind();
    }

    public function getContents(): string
    {
        $this->getContentsCalls++;

        if ($this->failOnGetContents) {
            throw new RuntimeException('getContents failure');
        }

        return parent::getContents();
    }
}
