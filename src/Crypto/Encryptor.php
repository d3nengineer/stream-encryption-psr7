<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Crypto;

use Infra\StreamEncryption\Enum\MediaType;
use Infra\StreamEncryption\ValueObject\EncryptionResult;

final class Encryptor
{
    public function __construct(
        private readonly MediaKeyExpander $mediaKeyExpander = new MediaKeyExpander(),
        private readonly AesCbc $aesCbc = new AesCbc(),
        private readonly Hmac $hmac = new Hmac(),
    ) {
    }

    public function encrypt(string $plaintext, string $mediaKey, MediaType $mediaType): EncryptionResult
    {
        $expandedKey = $this->mediaKeyExpander->expand($mediaKey, $mediaType);
        $ciphertext = $this->aesCbc->encrypt($plaintext, $expandedKey->cipherKey, $expandedKey->iv);
        $mac = $this->hmac->sign($ciphertext, $expandedKey->macKey);

        return new EncryptionResult($ciphertext, $mac);
    }
}
