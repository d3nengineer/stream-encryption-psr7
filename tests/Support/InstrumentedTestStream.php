<?php

declare(strict_types=1);

namespace Infra\StreamEncryption\Tests\Support;

use GuzzleHttp\Psr7\Stream;
use RuntimeException;

final class InstrumentedTestStream extends Stream
{
    public bool $closeCalled = false;
    public int $detachCalls = 0;
    public int $rewindCalls = 0;
    public int $getContentsCalls = 0;
    public bool $failOnRewind = false;
    public bool $failOnGetContents = false;

    public function close(): void
    {
        $this->closeCalled = true;

        parent::close();
    }

    public function detach()
    {
        $this->detachCalls++;

        return parent::detach();
    }

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
