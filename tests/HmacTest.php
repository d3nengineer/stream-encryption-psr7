<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\Hmac;
use Infra\StreamEncryption\Exception\IntegrityException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HmacTest extends TestCase
{
    public function testItSignsAndVerifiesIvAndCiphertext(): void
    {
        $hmac = new Hmac();
        $iv = random_bytes(16);
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($iv, $ciphertext, $macKey);

        $this->assertSame(Hmac::MAC_BYTES, strlen($mac));

        $hmac->verify($iv, $ciphertext, $mac, $macKey);
    }

    public function testItFailsForTamperedCiphertext(): void
    {
        $hmac = new Hmac();
        $iv = random_bytes(16);
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($iv, $ciphertext, $macKey);
        $tamperedCiphertext = $ciphertext;
        $tamperedCiphertext[0] = $tamperedCiphertext[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $hmac->verify($iv, $tamperedCiphertext, $mac, $macKey);
    }

    public function testItFailsForTamperedIv(): void
    {
        $hmac = new Hmac();
        $iv = random_bytes(16);
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($iv, $ciphertext, $macKey);
        $tamperedIv = $iv;
        $tamperedIv[0] = $tamperedIv[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $hmac->verify($tamperedIv, $ciphertext, $mac, $macKey);
    }

    public function testItFailsForTamperedMac(): void
    {
        $hmac = new Hmac();
        $iv = random_bytes(16);
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($iv, $ciphertext, $macKey);
        $tamperedMac = $mac;
        $tamperedMac[0] = $tamperedMac[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $hmac->verify($iv, $ciphertext, $tamperedMac, $macKey);
    }

    #[DataProvider('invalidVerifyBoundariesProvider')]
    public function testItFailsForMalformedMacBoundaries(
        string $iv,
        string $ciphertext,
        string $mac,
        string $macKey,
    ): void {
        $hmac = new Hmac();

        $this->expectException(IntegrityException::class);

        $hmac->verify($iv, $ciphertext, $mac, $macKey);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string, 3: string}>
     */
    public static function invalidVerifyBoundariesProvider(): array
    {
        $iv = random_bytes(16);
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $validMac = (new Hmac())->sign($iv, $ciphertext, $macKey);

        return [
            'mac-empty' => [
                $iv,
                $ciphertext,
                '',
                $macKey,
            ],
            'mac-truncated-9' => [
                $iv,
                $ciphertext,
                substr($validMac, 0, Hmac::MAC_BYTES - 1),
                $macKey,
            ],
            'wrong-key-size-16' => [
                $iv,
                $ciphertext,
                $validMac,
                random_bytes(16),
            ],
        ];
    }
}
