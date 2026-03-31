<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\Utils;
use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\IntegrityException;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use Infra\StreamEncryption\Stream\DecryptingStream;
use Infra\StreamEncryption\Stream\EncryptingStream;
use Infra\StreamEncryption\Stream\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;

final class StreamFactoryTest extends TestCase
{
    public function testEncryptReturnsEncryptingStreamAndIsLazyAtFactoryBoundary(): void
    {
        $source = $this->createInstrumentedStream('hello');
        $factory = new StreamFactory();

        $encrypted = $factory->encrypt($source, random_bytes(32), MediaType::IMAGE);

        $this->assertInstanceOf(EncryptingStream::class, $encrypted);
        $this->assertSame(0, $source->rewindCalls);
        $this->assertSame(0, $source->getContentsCalls);
    }

    public function testDecryptReturnsDecryptingStreamAndIsLazyAtFactoryBoundary(): void
    {
        $mediaKey = random_bytes(32);
        $payload = (new Encryptor())->encrypt('hello', $mediaKey, MediaType::VIDEO)->payload;
        $source = $this->createInstrumentedStream($payload);
        $factory = new StreamFactory();

        $decrypted = $factory->decrypt($source, $mediaKey, MediaType::VIDEO);

        $this->assertInstanceOf(DecryptingStream::class, $decrypted);
        $this->assertSame(0, $source->rewindCalls);
        $this->assertSame(0, $source->getContentsCalls);
    }

    public function testFactoryUsesDefaultCryptoServicesWhenNoneAreInjected(): void
    {
        $mediaKey = random_bytes(32);
        $factory = new StreamFactory();

        $encryptingStream = $factory->encrypt(Utils::streamFor('payload'), $mediaKey, MediaType::AUDIO);
        $decryptingStream = $factory->decrypt(
            Utils::streamFor((new Encryptor())->encrypt('payload', $mediaKey, MediaType::AUDIO)->payload),
            $mediaKey,
            MediaType::AUDIO,
        );

        $this->assertInstanceOf(Encryptor::class, $this->readPrivateProperty($encryptingStream, 'encryptor'));
        $this->assertInstanceOf(Decryptor::class, $this->readPrivateProperty($decryptingStream, 'decryptor'));
    }

    public function testFactoryPassesInjectedCryptoServiceInstancesThroughToDecorators(): void
    {
        $mediaKey = random_bytes(32);
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $factory = new StreamFactory($encryptor, $decryptor);

        $encryptingStream = $factory->encrypt(Utils::streamFor('payload'), $mediaKey, MediaType::DOCUMENT);
        $decryptingStream = $factory->decrypt(
            Utils::streamFor($encryptor->encrypt('payload', $mediaKey, MediaType::DOCUMENT)->payload),
            $mediaKey,
            MediaType::DOCUMENT,
        );

        $this->assertSame($encryptor, $this->readPrivateProperty($encryptingStream, 'encryptor'));
        $this->assertSame($decryptor, $this->readPrivateProperty($decryptingStream, 'decryptor'));
    }

    public function testReturnedEncryptingDecoratorPropagatesSourceReadFailuresOnFirstConsumption(): void
    {
        $source = $this->createInstrumentedStream('boom');
        $source->failOnGetContents = true;
        $factory = new StreamFactory();
        $stream = $factory->encrypt($source, random_bytes(32), MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('getContents failure');

        $stream->getContents();
    }

    public function testReturnedDecryptingDecoratorPropagatesSourceReadFailuresOnFirstConsumption(): void
    {
        $mediaKey = random_bytes(32);
        $payload = (new Encryptor())->encrypt('boom', $mediaKey, MediaType::VIDEO)->payload;
        $source = $this->createInstrumentedStream($payload);
        $source->failOnRewind = true;
        $factory = new StreamFactory();
        $stream = $factory->decrypt($source, $mediaKey, MediaType::VIDEO);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rewind failure');

        $stream->read(1);
    }

    public function testReturnedEncryptingDecoratorPropagatesCryptoFailuresOnFirstConsumption(): void
    {
        $factory = new StreamFactory();
        $stream = $factory->encrypt(Utils::streamFor('payload'), random_bytes(16), MediaType::IMAGE);

        $this->expectException(InvalidMediaKeyException::class);

        $stream->read(1);
    }

    public function testReturnedDecryptingDecoratorPropagatesCryptoFailuresOnFirstConsumption(): void
    {
        $mediaKey = random_bytes(32);
        $payload = (new Encryptor())->encrypt('payload', $mediaKey, MediaType::IMAGE)->payload;
        $factory = new StreamFactory();
        $stream = $factory->decrypt(Utils::streamFor($payload), random_bytes(16), MediaType::IMAGE);

        $this->expectException(InvalidMediaKeyException::class);

        $stream->getContents();
    }

    public function testReturnedDecryptingDecoratorPropagatesIntegrityFailuresOnFirstConsumption(): void
    {
        $mediaKey = random_bytes(32);
        $payload = (new Encryptor())->encrypt('payload', $mediaKey, MediaType::IMAGE)->payload;
        $payload[0] = $payload[0] ^ "\x01";

        $factory = new StreamFactory();
        $stream = $factory->decrypt(Utils::streamFor($payload), $mediaKey, MediaType::IMAGE);

        $this->expectException(IntegrityException::class);

        $stream->read(1);
    }

    #[DataProvider('mediaTypeRoundTripProvider')]
    public function testEndToEndRoundTripAcrossAllMediaTypes(MediaType $mediaType, string $plaintext): void
    {
        $mediaKey = random_bytes(32);
        $factory = new StreamFactory();

        $encryptedStream = $factory->encrypt(Utils::streamFor($plaintext), $mediaKey, $mediaType);
        $decryptedStream = $factory->decrypt(Utils::streamFor((string) $encryptedStream), $mediaKey, $mediaType);

        $this->assertSame($plaintext, (string) $decryptedStream);
    }

    /**
     * @return array<string, array{0: MediaType, 1: string}>
     */
    public static function mediaTypeRoundTripProvider(): array
    {
        return [
            'image' => [MediaType::IMAGE, "\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR"],
            'video' => [MediaType::VIDEO, random_bytes(96)],
            'audio' => [MediaType::AUDIO, "ID3\x00\x10\xFF\x00audio"],
            'document' => [MediaType::DOCUMENT, "PDF\x00\x01body\n\xFF\xFE"],
        ];
    }

    private function readPrivateProperty(object $object, string $propertyName): mixed
    {
        $property = new ReflectionProperty($object, $propertyName);

        return $property->getValue($object);
    }

    private function createInstrumentedStream(string $contents): InstrumentedFactorySourceStream
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, $contents);
        rewind($resource);

        return new InstrumentedFactorySourceStream($resource);
    }
}

final class InstrumentedFactorySourceStream extends Stream
{
    public int $rewindCalls = 0;
    public int $getContentsCalls = 0;
    public bool $failOnRewind = false;
    public bool $failOnGetContents = false;

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
