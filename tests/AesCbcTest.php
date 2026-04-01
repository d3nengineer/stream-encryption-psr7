<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\AesCbc;
use Infra\StreamEncryption\Exception\DecryptionException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AesCbcTest extends TestCase
{
    #[DataProvider('roundTripPlaintextProvider')]
    public function testItRoundTripsSupportedPlaintexts(string $plaintext): void
    {
        $aesCbc = new AesCbc();
        $cipherKey = random_bytes(32);
        $iv = random_bytes(16);

        $ciphertext = $aesCbc->encrypt($plaintext, $cipherKey, $iv);

        $this->assertSame($plaintext, $aesCbc->decrypt($ciphertext, $cipherKey, $iv));
    }

    #[DataProvider('malformedCiphertextProvider')]
    public function testItThrowsOnMalformedCiphertextBoundaries(string $scenarioId, string $ciphertext): void
    {
        $aesCbc = new AesCbc();

        $this->expectException(DecryptionException::class);

        $aesCbc->decrypt($ciphertext, random_bytes(32), random_bytes(16));
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function malformedCiphertextProvider(): array
    {
        return [
            'DEBUG[aescbc-invalid/ascii-junk]' => ['aescbc-invalid/ascii-junk', 'not-a-valid-ciphertext'],
            'DEBUG[aescbc-invalid/truncated-single-byte]' => ['aescbc-invalid/truncated-single-byte', "\x01"],
            'DEBUG[aescbc-invalid/non-block-len-17]' => ['aescbc-invalid/non-block-len-17', random_bytes(17)],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function roundTripPlaintextProvider(): array
    {
        return [
            'text-with-null-byte' => ["hello\x00world"],
            'empty-string' => [''],
            'binary-128-bytes' => [random_bytes(128)],
        ];
    }
}
