<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\AesCbc;
use Infra\StreamEncryption\Exception\DecryptionException;
use PHPUnit\Framework\TestCase;

final class AesCbcTest extends TestCase
{
    public function testItRoundTripsPlaintext(): void
    {
        $aesCbc = new AesCbc();
        $cipherKey = random_bytes(32);
        $iv = random_bytes(16);
        $plaintext = "hello\x00world";

        $ciphertext = $aesCbc->encrypt($plaintext, $cipherKey, $iv);

        $this->assertSame($plaintext, $aesCbc->decrypt($ciphertext, $cipherKey, $iv));
    }

    public function testItSupportsEmptyStringsAndBinaryPayloads(): void
    {
        $aesCbc = new AesCbc();
        $cipherKey = random_bytes(32);
        $iv = random_bytes(16);
        $plaintext = '';

        $emptyCiphertext = $aesCbc->encrypt($plaintext, $cipherKey, $iv);
        $this->assertSame($plaintext, $aesCbc->decrypt($emptyCiphertext, $cipherKey, $iv));

        $binaryPlaintext = random_bytes(128);
        $binaryCiphertext = $aesCbc->encrypt($binaryPlaintext, $cipherKey, $iv);
        $this->assertSame($binaryPlaintext, $aesCbc->decrypt($binaryCiphertext, $cipherKey, $iv));
    }

    public function testItThrowsOnInvalidCiphertext(): void
    {
        $aesCbc = new AesCbc();

        $this->expectException(DecryptionException::class);

        $aesCbc->decrypt('not-a-valid-ciphertext', random_bytes(32), random_bytes(16));
    }
}
