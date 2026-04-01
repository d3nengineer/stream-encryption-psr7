<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use GuzzleHttp\Psr7\NoSeekStream;
use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\IntegrityException;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use Infra\StreamEncryption\Stream\DecryptingStream;
use Infra\StreamEncryption\Stream\EncryptingStream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class DecryptingStreamTest extends TestCase
{
    public function testItLazilyDecryptsOnceAndReusesTheMaterializedPlaintext(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('hello world', $mediaKey, MediaType::IMAGE);
        $source = $this->createInstrumentedSourceStream($payload);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $firstRead = $stream->read(5);
        $rest = $stream->getContents();

        $this->assertSame('hello', $firstRead);
        $this->assertSame(' world', $rest);
        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);

        $stream->rewind();
        $stream->getContents();

        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);
    }

    public function testItIsReadOnly(): void
    {
        $mediaKey = random_bytes(32);
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt('plain', $mediaKey, MediaType::VIDEO)),
            $mediaKey,
            MediaType::VIDEO,
        );

        $this->assertFalse($stream->isWritable());

        $this->expectException(RuntimeException::class);

        $stream->write('blocked');
    }

    public function testItProducesPlaintextOutput(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = "payload\x00structure\x01check";
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt($plaintext, $mediaKey, MediaType::DOCUMENT)),
            $mediaKey,
            MediaType::DOCUMENT,
        );

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testItDelegatesReadSeekTellEofAndContentsToTheInternalPlaintextStream(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'delegation-content';
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt($plaintext, $mediaKey, MediaType::AUDIO)),
            $mediaKey,
            MediaType::AUDIO,
        );

        $this->assertTrue($stream->isReadable());
        $this->assertTrue($stream->isSeekable());
        $this->assertSame(0, $stream->tell());

        $first = $stream->read(8);

        $this->assertSame(substr($plaintext, 0, 8), $first);
        $this->assertSame(8, $stream->tell());

        $stream->seek(0);

        $this->assertSame(0, $stream->tell());
        $this->assertSame($plaintext, $stream->getContents());
        $this->assertTrue($stream->eof());

        $stream->rewind();

        $this->assertFalse($stream->eof());
        $this->assertSame(strlen($plaintext), $stream->getSize());
        $this->assertIsArray($stream->getMetadata());
    }

    public function testCompatibilityMatrixForDelegatedMethodsInitializesOnceAndStaysStable(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('compatibility-matrix-plaintext', $mediaKey, MediaType::IMAGE);
        $source = $this->createInstrumentedSourceStream($payload);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $this->assertSame(0, $source->rewindCalls, 'decrypting/tell precondition: no rewind before delegated calls');
        $this->assertSame(0, $source->getContentsCalls, 'decrypting/tell precondition: no source reads before delegated calls');

        $this->assertSame(0, $stream->tell(), 'decrypting/tell after first delegated call');
        $this->assertTrue($stream->isReadable(), 'decrypting/isReadable should delegate to internal stream');
        $this->assertTrue($stream->isSeekable(), 'decrypting/isSeekable should delegate to internal stream');
        $this->assertSame(strlen('compatibility-matrix-plaintext'), $stream->getSize(), 'decrypting/getSize should match plaintext size');
        $this->assertIsArray($stream->getMetadata(), 'decrypting/getMetadata should return metadata array');
        $this->assertNotNull($stream->getMetadata('uri'), 'decrypting/getMetadata(uri) should expose stream URI');

        $prefix = $stream->read(5);
        $this->assertSame('compa', $prefix, 'decrypting/read should return expected plaintext prefix');
        $this->assertSame(5, $stream->tell(), 'decrypting/tell should move after read');
        $this->assertFalse($stream->eof(), 'decrypting/eof should remain false before full consumption');

        $stream->seek(0);
        $this->assertSame(0, $stream->tell(), 'decrypting/seek should reset cursor');

        $this->assertSame('compatibility-matrix-plaintext', $stream->getContents(), 'decrypting/getContents should return remaining plaintext');
        $this->assertTrue($stream->eof(), 'decrypting/getContents should advance to eof');

        $stream->rewind();
        $this->assertFalse($stream->eof(), 'decrypting/rewind should clear eof state');
        $this->assertSame(1, $source->rewindCalls, 'decrypting compatibility: source rewind should happen once');
        $this->assertSame(1, $source->getContentsCalls, 'decrypting compatibility: source read should happen once');
    }

    public function testCloseClosesSourceAndInternalStreamAndIsIdempotent(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('owned-source', $mediaKey, MediaType::IMAGE));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $stream->read(1);
        $stream->close();
        $stream->close();

        $this->assertTrue($source->closeCalled);
    }

    public function testCloseBeforeInitializationStillClosesSource(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('owned-source', $mediaKey, MediaType::IMAGE));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $stream->close();

        $this->assertTrue($source->closeCalled);
    }

    public function testDetachDetachesSourceAndReturnsInternalResourceWhenInitialized(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('detach-source', $mediaKey, MediaType::VIDEO));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::VIDEO);

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
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('not-initialized', $mediaKey, MediaType::AUDIO));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::AUDIO);

        $this->assertNull($stream->detach());
        $this->assertSame(1, $source->detachCalls);
    }

    public function testConstructorRejectsUnreadableSource(): void
    {
        $source = Utils::streamFor('unreadable');
        $source->detach();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Source stream must be readable.');

        new DecryptingStream($source, random_bytes(32), MediaType::IMAGE);
    }

    public function testToStringFallsBackToEmptyStringOnSourceFailure(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('boom', $mediaKey, MediaType::DOCUMENT));
        $source->failOnGetContents = true;
        $stream = new DecryptingStream($source, $mediaKey, MediaType::DOCUMENT);

        $this->assertSame('', (string) $stream);
    }

    public function testRepeatedReadCyclesReuseMaterializedPlaintext(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('repeatable-read-cycles', $mediaKey, MediaType::DOCUMENT);
        $source = $this->createInstrumentedSourceStream($payload);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::DOCUMENT);

        $firstPrefix = $stream->read(9);
        $stream->rewind();
        $secondPrefix = $stream->read(9);

        $this->assertSame($firstPrefix, $secondPrefix);
        $this->assertSame(1, $source->rewindCalls);
        $this->assertSame(1, $source->getContentsCalls);
    }

    public function testItHandlesEmptyPlaintext(): void
    {
        $mediaKey = random_bytes(32);
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt('', $mediaKey, MediaType::IMAGE)),
            $mediaKey,
            MediaType::IMAGE,
        );

        $this->assertSame('', (string) $stream);
        $this->assertSame('', $stream->read(1));
        $this->assertTrue($stream->eof());
    }

    public function testItHandlesBinaryPlaintextWithNullBytes(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = "bin\x00ary\x00payload\x01\x02\x03";
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt($plaintext, $mediaKey, MediaType::VIDEO)),
            $mediaKey,
            MediaType::VIDEO,
        );

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testItHandlesLargePayloadBuffers(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(1024 * 1024);
        $stream = new DecryptingStream(
            Utils::streamFor($this->encrypt($plaintext, $mediaKey, MediaType::AUDIO)),
            $mediaKey,
            MediaType::AUDIO,
        );

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testItPropagatesSourceRewindFailureOnRead(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('boom', $mediaKey, MediaType::VIDEO));
        $source->failOnRewind = true;
        $stream = new DecryptingStream($source, $mediaKey, MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rewind failure');

        $stream->read(1);
    }

    public function testItPropagatesSourceGetContentsFailureOnGetContents(): void
    {
        $mediaKey = random_bytes(32);
        $source = $this->createInstrumentedSourceStream($this->encrypt('boom', $mediaKey, MediaType::VIDEO));
        $source->failOnGetContents = true;
        $stream = new DecryptingStream($source, $mediaKey, MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('getContents failure');

        $stream->getContents();
    }

    public function testSeekableSourcesDecryptFromStartEvenWhenPreConsumed(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'seekable-source-data';
        $payload = $this->encrypt($plaintext, $mediaKey, MediaType::DOCUMENT);
        $source = Utils::streamFor($payload);

        $source->read(5);

        $stream = new DecryptingStream($source, $mediaKey, MediaType::DOCUMENT);

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testGuzzleResourceBackedStreamsRemainCompatibleForDecryption(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'resource-backed-decryption-stream';
        $payload = $this->encrypt($plaintext, $mediaKey, MediaType::VIDEO);
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $payload);
        rewind($resource);
        $source = Utils::streamFor($resource);

        $source->read(7);

        $stream = new DecryptingStream($source, $mediaKey, MediaType::VIDEO);

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testNonSeekableSourcesDecryptFromStartWhenCursorIsUntouched(): void
    {
        $mediaKey = random_bytes(32);
        $plaintext = 'non-seekable-compatibility';
        $payload = $this->encrypt($plaintext, $mediaKey, MediaType::AUDIO);
        $source = new NoSeekStream(Utils::streamFor($payload));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::AUDIO);

        $this->assertSame($plaintext, (string) $stream);
    }

    public function testNonSeekableSourcesDecryptRemainingBytesFromCurrentCursor(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('non-seekable-source-data', $mediaKey, MediaType::AUDIO);
        $base = Utils::streamFor($payload);
        $base->read(4);
        $source = new NoSeekStream($base);

        $stream = new DecryptingStream($source, $mediaKey, MediaType::AUDIO);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testPreConsumedNonSeekableSourceCanDecryptEmptyRemainderOnlyIfPayloadStillIntact(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('', $mediaKey, MediaType::IMAGE);
        $base = Utils::streamFor($payload);

        while (!$base->eof()) {
            $base->read(1024);
        }

        $source = new NoSeekStream($base);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesTruncatedPayloadIntegrityFailures(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('secret', $mediaKey, MediaType::AUDIO);
        $stream = new DecryptingStream(
            Utils::streamFor(substr($payload, 0, -1)),
            $mediaKey,
            MediaType::AUDIO,
        );

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesTamperedCiphertextIntegrityFailures(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('secret', $mediaKey, MediaType::IMAGE);
        $payload[0] = $payload[0] ^ "\x01";
        $stream = new DecryptingStream(Utils::streamFor($payload), $mediaKey, MediaType::IMAGE);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesTamperedCiphertextIntegrityFailuresForNoSeekSource(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('secret', $mediaKey, MediaType::IMAGE);
        $payload[0] = $payload[0] ^ "\x01";
        $source = new NoSeekStream(Utils::streamFor($payload));
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesTamperedMacIntegrityFailures(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('secret', $mediaKey, MediaType::VIDEO);
        $payload[strlen($payload) - 1] = $payload[strlen($payload) - 1] ^ "\x01";
        $stream = new DecryptingStream(Utils::streamFor($payload), $mediaKey, MediaType::VIDEO);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesWrongMediaKeyFailures(): void
    {
        $payload = $this->encrypt('secret', random_bytes(32), MediaType::DOCUMENT);
        $stream = new DecryptingStream(Utils::streamFor($payload), random_bytes(32), MediaType::DOCUMENT);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesWrongMediaTypeFailures(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('secret', $mediaKey, MediaType::IMAGE);
        $stream = new DecryptingStream(Utils::streamFor($payload), $mediaKey, MediaType::VIDEO);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    public function testItPropagatesInvalidMediaKeyExceptionsFromTheCryptoLayer(): void
    {
        $payload = $this->encrypt('payload', random_bytes(32), MediaType::IMAGE);
        $stream = new DecryptingStream(Utils::streamFor($payload), random_bytes(16), MediaType::IMAGE);

        $this->expectException(InvalidMediaKeyException::class);

        $stream->read(1);
    }

    public function testReadAfterDetachFailsWhenEncryptedSourceIsNoLongerReadable(): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('detach-lifecycle-check', $mediaKey, MediaType::IMAGE);
        $source = $this->createInstrumentedSourceStream($payload);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        $stream->detach();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Source stream is not readable.');

        $stream->read(1);
    }

    #[DataProvider('mediaTypeAndFixtureProvider')]
    public function testEndToEndRoundTripAcrossMediaTypes(MediaType $mediaType, string $plaintext): void
    {
        $mediaKey = random_bytes(32);
        $encryptingStream = new EncryptingStream(Utils::streamFor($plaintext), $mediaKey, $mediaType);
        $decryptingStream = new DecryptingStream(Utils::streamFor((string) $encryptingStream), $mediaKey, $mediaType);

        $this->assertSame($plaintext, (string) $decryptingStream);
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

    private function encrypt(string $plaintext, string $mediaKey, MediaType $mediaType): string
    {
        return (new Encryptor())->encrypt($plaintext, $mediaKey, $mediaType)->payload;
    }

    private function createInstrumentedSourceStream(string $contents): InstrumentedDecryptSourceStream
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $contents);
        rewind($resource);

        return new InstrumentedDecryptSourceStream($resource);
    }
}

final class InstrumentedDecryptSourceStream extends Stream
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
