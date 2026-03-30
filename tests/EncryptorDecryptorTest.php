<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\Decryptor;
use Infra\StreamEncryption\Crypto\Encryptor;
use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\Exception\IntegrityException;
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

    public function testItFailsForTruncatedPayloads(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $result = $encryptor->encrypt('secret', $mediaKey, MediaType::AUDIO);

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt(substr($result->payload, 0, -1), $mediaKey, MediaType::AUDIO);
    }

    public function testItFailsForTamperedCiphertext(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $result = $encryptor->encrypt('secret', $mediaKey, MediaType::IMAGE);
        $tamperedPayload = $result->payload;
        $tamperedPayload[0] = $tamperedPayload[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($tamperedPayload, $mediaKey, MediaType::IMAGE);
    }

    public function testItFailsForTamperedMac(): void
    {
        $encryptor = new Encryptor();
        $decryptor = new Decryptor();
        $mediaKey = random_bytes(32);
        $result = $encryptor->encrypt('secret', $mediaKey, MediaType::VIDEO);
        $tamperedPayload = $result->payload;
        $tamperedPayload[strlen($tamperedPayload) - 1] = $tamperedPayload[strlen($tamperedPayload) - 1] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $decryptor->decrypt($tamperedPayload, $mediaKey, MediaType::VIDEO);
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
}
