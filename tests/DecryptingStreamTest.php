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
use Infra\StreamEncryption\Tests\Support\InstrumentedTestStream;
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

    #[DataProvider('tamperMatrixProvider')]
    public function testTamperMatrixFailsIntegrityBeforeDecrypt(
        MediaType $mediaType,
        string $sourceKind,
        string $mutationVector,
    ): void {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt('tamper-matrix-stream-payload', $mediaKey, $mediaType);
        $tamperedPayload = $this->applyTamperVector($payload, $mutationVector);
        $source = $this->buildSourceByKind($tamperedPayload, $sourceKind);
        $stream = new DecryptingStream($source, $mediaKey, $mediaType);

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

    #[DataProvider('unreadableSourceActionProvider')]
    public function testReadFailsWhenSourceBecomesUnreadableBeforeFirstRead(string $action): void
    {
        $mediaKey = random_bytes(32);
        $payload = $this->encrypt($action, $mediaKey, MediaType::IMAGE);
        $source = $action === 'external-detach'
            ? Utils::streamFor($payload)
            : $this->createInstrumentedSourceStream($payload);
        $stream = new DecryptingStream($source, $mediaKey, MediaType::IMAGE);

        match ($action) {
            'detach-lifecycle-check' => $stream->detach(),
            'closed-before-read' => $stream->close(),
            'external-detach' => $source->detach(),
        };

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

    /**
     * @return array<string, array{0: MediaType, 1: string, 2: string}>
     */
    public static function tamperMatrixProvider(): array
    {
        return [
            'DEBUG[tamper-stream/image-seekable-first-byte]' => [
                MediaType::IMAGE,
                'seekable-untouched',
                'flip_first_byte',
            ],
            'DEBUG[tamper-stream/video-seekable-middle-byte]' => [
                MediaType::VIDEO,
                'seekable-untouched',
                'flip_middle_byte',
            ],
            'DEBUG[tamper-stream/audio-noseek-untouched-mac-swap]' => [
                MediaType::AUDIO,
                'noseek-untouched',
                'swap_mac_segments',
            ],
            'DEBUG[tamper-stream/document-noseek-prefix-truncation]' => [
                MediaType::DOCUMENT,
                'noseek-untouched',
                'truncate_prefix',
            ],
            'DEBUG[tamper-stream/image-noseek-suffix-truncation]' => [
                MediaType::IMAGE,
                'noseek-untouched',
                'truncate_suffix',
            ],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function unreadableSourceActionProvider(): array
    {
        return [
            'owned-source-detached' => ['detach-lifecycle-check'],
            'owned-source-closed' => ['closed-before-read'],
            'externally-detached' => ['external-detach'],
        ];
    }

    private function buildSourceByKind(string $payload, string $sourceKind): Stream|\GuzzleHttp\Psr7\NoSeekStream
    {
        $base = Utils::streamFor($payload);

        return match ($sourceKind) {
            'seekable-untouched' => $base,
            'noseek-untouched' => new NoSeekStream($base),
            default => throw new \InvalidArgumentException(sprintf('Unsupported source kind: %s', $sourceKind)),
        };
    }

    private function applyTamperVector(string $payload, string $mutationVector): string
    {
        return match ($mutationVector) {
            'flip_first_byte' => $this->flipPayloadByte($payload, 0),
            'flip_middle_byte' => $this->flipPayloadByte($payload, max(0, intdiv(strlen($payload), 2) - 1)),
            'truncate_prefix' => substr($payload, 1),
            'truncate_suffix' => substr($payload, 0, -1),
            'swap_mac_segments' => $this->swapMacSegments($payload),
            default => throw new \InvalidArgumentException(sprintf('Unsupported mutation vector: %s', $mutationVector)),
        };
    }

    private function flipPayloadByte(string $payload, int $offset): string
    {
        $tamperedPayload = $payload;
        $tamperedPayload[$offset] = $tamperedPayload[$offset] ^ "\x01";

        return $tamperedPayload;
    }

    private function swapMacSegments(string $payload): string
    {
        $ciphertext = substr($payload, 0, -10);
        $mac = substr($payload, -10);

        return $ciphertext . substr($mac, 5) . substr($mac, 0, 5);
    }

    private function encrypt(string $plaintext, string $mediaKey, MediaType $mediaType): string
    {
        return (new Encryptor())->encrypt($plaintext, $mediaKey, $mediaType)->payload;
    }

    private function createInstrumentedSourceStream(string $contents): InstrumentedTestStream
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $contents);
        rewind($resource);

        return new InstrumentedTestStream($resource);
    }
}
