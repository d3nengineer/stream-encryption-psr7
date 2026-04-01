<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Crypto\Hmac;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\IntegrityException;
use Infra\StreamEncryption\Exception\InvalidMediaKeyException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EncryptorDecryptorTest extends TestCase
{
    #[DataProvider('mediaTypes')]
    public function testItRoundTripsForEveryMediaType(MediaType $mediaType): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $plaintext = "media-bytes-\x00" . random_bytes(64);

        $result = $encryptor->encrypt($plaintext, $mediaKey, $mediaType);

        $this->assertSame($result->ciphertext . $result->mac, $result->payload);
        $this->assertSame($plaintext, $decryptor->decrypt($result->payload, $mediaKey, $mediaType));
    }

    public function testItFailsWithTheWrongMediaType(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $result = $encryptor->encrypt('secret', $mediaKey, MediaType::IMAGE);

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($result->payload, $mediaKey, MediaType::VIDEO);
    }

    public function testItFailsWithTheWrongMediaKey(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $result = $encryptor->encrypt('secret', random_bytes(32), MediaType::DOCUMENT);

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($result->payload, random_bytes(32), MediaType::DOCUMENT);
    }

    #[DataProvider('invalidPayloadBoundaryProvider')]
    public function testItFailsForMalformedPayloadBoundaries(
        string $payload,
        MediaType $mediaType,
    ): void {
        $decryptor = new Decryptor();

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($payload, random_bytes(32), $mediaType);
    }

    #[DataProvider('tamperVectorProvider')]
    public function testItFailsForDeterministicTamperVectors(
        MediaType $mediaType,
        string $mutation,
    ): void {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $payload = $encryptor->encrypt('tamper-matrix-plaintext', $mediaKey, $mediaType)->payload;
        $tamperedPayload = $this->mutatePayload($payload, $mutation);

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($tamperedPayload, $mediaKey, $mediaType);
    }

    public function testItSupportsBinaryPayloads(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $plaintext = random_bytes(512);

        $result = $encryptor->encrypt($plaintext, $mediaKey, MediaType::AUDIO);

        $this->assertSame($plaintext, $decryptor->decrypt($result->payload, $mediaKey, MediaType::AUDIO));
    }

    #[DataProvider('invalidMediaKeyProvider')]
    public function testItRejectsInvalidMediaKeyLengthsAtPublicBoundaries(
        string $invalidMediaKey,
    ): void {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();

        $this->expectException(InvalidMediaKeyException::class);

        $payload = $encryptor->encrypt('payload', random_bytes(32), MediaType::IMAGE)->payload;
        $decryptor->decrypt($payload, $invalidMediaKey, MediaType::IMAGE);
    }

    /**
     * @return array<string, array{0: MediaType}>
     */
    public static function mediaTypes(): array
    {
        return [
            'image' => [MediaType::IMAGE],
            'video' => [MediaType::VIDEO],
            'audio' => [MediaType::AUDIO],
            'document' => [MediaType::DOCUMENT],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: MediaType}>
     */
    public static function invalidPayloadBoundaryProvider(): array
    {
        return [
            'DEBUG[payload-invalid/empty/image]' => ['', MediaType::IMAGE],
            'DEBUG[payload-invalid/mac-only-10/video]' => [
                random_bytes(Hmac::MAC_BYTES),
                MediaType::VIDEO,
            ],
            'DEBUG[payload-invalid/short-9/audio]' => [
                random_bytes(Hmac::MAC_BYTES - 1),
                MediaType::AUDIO,
            ],
        ];
    }

    /**
     * @return array<string, array{0: MediaType, 1: string}>
     */
    public static function tamperVectorProvider(): array
    {
        return [
            'DEBUG[tamper/cipher-first-byte/image]' => [MediaType::IMAGE, 'flip_first_byte'],
            'DEBUG[tamper/cipher-middle-byte/video]' => [MediaType::VIDEO, 'flip_middle_byte'],
            'DEBUG[tamper/payload-prefix-truncation/audio]' => [MediaType::AUDIO, 'truncate_prefix'],
            'DEBUG[tamper/payload-suffix-truncation/document]' => [MediaType::DOCUMENT, 'truncate_suffix'],
            'DEBUG[tamper/mac-segment-swap/image]' => [MediaType::IMAGE, 'swap_mac_segments'],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidMediaKeyProvider(): array
    {
        return [
            'DEBUG[key-invalid/short-31]' => [random_bytes(31)],
            'DEBUG[key-invalid/long-33]' => [random_bytes(33)],
        ];
    }

    private function mutatePayload(string $payload, string $mutation): string
    {
        return match ($mutation) {
            'flip_first_byte' => $this->flipByte($payload, 0),
            'flip_middle_byte' => $this->flipByte($payload, max(0, intdiv(strlen($payload), 2) - 1)),
            'truncate_prefix' => substr($payload, 1),
            'truncate_suffix' => substr($payload, 0, -1),
            'swap_mac_segments' => $this->swapMacSegments($payload),
            default => throw new \InvalidArgumentException(sprintf('Unknown mutation vector: %s', $mutation)),
        };
    }

    private function flipByte(string $payload, int $index): string
    {
        $tampered = $payload;
        $tampered[$index] = $tampered[$index] ^ "\x01";

        return $tampered;
    }

    private function swapMacSegments(string $payload): string
    {
        $ciphertext = substr($payload, 0, -Hmac::MAC_BYTES);
        $mac = substr($payload, -Hmac::MAC_BYTES);
        $firstSegment = substr($mac, 0, 5);
        $secondSegment = substr($mac, 5);

        return $ciphertext . $secondSegment . $firstSegment;
    }
}
