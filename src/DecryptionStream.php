<?php

namespace WhatsAppStreamEncryption;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

class DecryptionStream implements StreamInterface
{
    private $stream;
    private $mediaKey;
    private $mediaType;
    private $keys;
    private $position;
    private $eof;
    private $decryptedData;
    private $curIv;
    private $lastPart;
    private $hashCtx;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->keys = StreamHelper::expandMediaKey($mediaKey, $mediaType);
        $this->position = 0;
        $this->eof = false;
        $this->decryptedData = '';
        $this->lastPart = '';
        $this->curIv = $this->keys['iv'];
        $this->hashCtx = StreamHelper::initHashCtx($this->keys['macKey'], $this->keys['iv']);
    }

    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (\Exception $e) {
            return '';
        }
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        $this->decryptedData = '';
        $this->lastPart = '';
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        // нельзя получить реальный размер данных до их расшифровки,
        // т.к. в последнем блоке может содержаться padding,
        if (!$this->eof) {
            return null;
        }
        return strlen($this->position);
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->eof;
    }

    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    public function seek($offset, $whence = SEEK_SET): void
    {  
        if (!$this->isSeekable()) {
            throw new RuntimeException('DecryptionStream not seekable');
        }

        if ($offset === 0 && $whence === SEEK_SET) {
            $this->position = 0;
            $this->eof = false;
            $this->curIv = $this->keys['iv'];
            $this->decryptedData = '';
            $this->lastPart = '';
            $this->stream->seek(0, $whence);
        } else {
            throw new RuntimeException('DecryptionStream only support being rewound, not arbitrary seeking.');
        }
    }

    public function rewind(): void
    {
        $this->seek(0, SEEK_SET);
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new RuntimeException('DecryptionStream is not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        if (strlen($this->decryptedData) >= $length) {
            $data = substr($this->decryptedData, 0, $length);
            $this->decryptedData = substr($this->decryptedData, $length);
            $this->position += $length;
            return $data;
        }

        $lengthToRead = StreamHelper::calcBlocksLength($length - strlen($this->decryptedData));
        $newData = $this->lastPart . $this->stream->read($lengthToRead);

        if ($newData === '') {
            $this->eof = true;
            $data = $this->decryptedData;
            $this->decryptedData = '';
            $this->position += strlen($data);
            return $data;
        }

        $remainder = strlen($newData) % StreamHelper::BLOCK_SIZE;
        if ($remainder > 0) {
            $this->lastPart = substr($newData,-$remainder);
            $newData = substr($newData, 0, -$remainder);
        } else {
            $this->lastPart = $this->stream->read(StreamHelper::BLOCK_SIZE);
        }

        hash_update($this->hashCtx, $newData);

        $zeroPadding = OPENSSL_ZERO_PADDING;
        if(strlen($this->lastPart) < StreamHelper::BLOCK_SIZE) {
            if (!hash_equals($this->lastPart, StreamHelper::calculateMac($this->hashCtx))) {
                throw new RuntimeException('DecryptionStream not valid');
            }
            $this->lastPart = '';
            $zeroPadding = 0;
        }

        $decrypted = openssl_decrypt(
            $newData,
            'aes-256-cbc',
            $this->keys['cipherKey'],
            OPENSSL_RAW_DATA | $zeroPadding,
            $this->curIv
        );

        $this->decryptedData .= $decrypted;
        $this->curIv = substr($newData, -StreamHelper::BLOCK_SIZE);
    
        return $this->read($length);
    }

    public function getContents(): string
    {
        $data = '';
        while(!$this->eof) {
            $data .= $this->read(StreamHelper::READ_CONTENT_BLOCK_SIZE);
        }
        return $data;
    }

    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }
}
