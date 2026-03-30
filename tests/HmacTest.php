<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests;

use Infra\StreamEncryption\Crypto\Hmac;
use Infra\StreamEncryption\Exception\IntegrityException;
use PHPUnit\Framework\TestCase;

final class HmacTest extends TestCase
{
    public function testItSignsAndVerifiesCiphertext(): void
    {
        $hmac = new Hmac();
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($ciphertext, $macKey);

        $this->assertSame(32, strlen($mac));

        $hmac->verify($ciphertext, $mac, $macKey);
        $this->assertTrue(true);
    }

    public function testItFailsForTamperedCiphertext(): void
    {
        $hmac = new Hmac();
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($ciphertext, $macKey);
        $tamperedCiphertext = $ciphertext;
        $tamperedCiphertext[0] = $tamperedCiphertext[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $hmac->verify($tamperedCiphertext, $mac, $macKey);
    }

    public function testItFailsForTamperedMac(): void
    {
        $hmac = new Hmac();
        $ciphertext = random_bytes(64);
        $macKey = random_bytes(32);
        $mac = $hmac->sign($ciphertext, $macKey);
        $tamperedMac = $mac;
        $tamperedMac[0] = $tamperedMac[0] ^ "\x01";

        $this->expectException(IntegrityException::class);

        $hmac->verify($ciphertext, $tamperedMac, $macKey);
    }
}
