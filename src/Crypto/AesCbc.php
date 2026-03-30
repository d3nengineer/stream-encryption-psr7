<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Exception\DecryptionException;

final class AesCbc
{
    private const CIPHER = 'aes-256-cbc';

    public function encrypt(string $plaintext, string $cipherKey, string $iv): string
    {
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($ciphertext === false) {
            throw new DecryptionException('OpenSSL failed to encrypt the payload.');
        }

        return $ciphertext;
    }

    public function decrypt(string $ciphertext, string $cipherKey, string $iv): string
    {
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv,
        );

        if ($plaintext === false) {
            throw new DecryptionException('OpenSSL failed to decrypt the payload.');
        }

        return $plaintext;
    }
}
