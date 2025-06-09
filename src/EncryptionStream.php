<?php

namespace WhatsAppStreamEncryption;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
    
class EncryptionStream implements StreamInterface
{
    private $stream;
    private $mediaKey;
    private $mediaType;
    private $keys;
    private $position;
    private $eof;
    private $encryptedData;
    private $curIv;
    private $hashCtx;
    private $lastPart;

    public function __construct(StreamInterface $stream, string $mediaKey, string $mediaType)
    {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->keys = StreamHelper::expandMediaKey($mediaKey, $mediaType);
        $this->position = 0;
        $this->eof = false;
        $this->encryptedData = '';
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
        $this->encryptedData = '';
        return $this->stream->detach();
    }

    public function getSize(): ?int
    {
        if ($this->eof) {
            $size = $this->position;
        } else {
            $size = (1 + floor($this->stream->getSize() / StreamHelper::BLOCK_SIZE)) * StreamHelper::BLOCK_SIZE;
            $size += StreamHelper::MAC_SIZE;
        }
        return $size;
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
            throw new RuntimeException('EncryptionStream not seekable');
        }

        if ($offset === 0 && $whence === SEEK_SET) {
            $this->position = 0;
            $this->eof = false;
            $this->curIv = $this->keys['iv'];
            $this->encryptedData = '';
            $this->lastPart = '';
            $this->stream->seek(0, $whence);
        } else {
            throw new RuntimeException('EcryptionStream only support being rewound, not arbitrary seeking.');
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
        throw new RuntimeException('EncryptionStream is not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        if (strlen($this->encryptedData) >= $length) {
            $data = substr($this->encryptedData, 0, $length);
            $this->encryptedData = substr($this->encryptedData, $length);
            $this->position += $length;
            return $data;
        }

        $lengthToRead = StreamHelper::calcBlocksLength($length - strlen($this->encryptedData));
        $newData = $this->lastPart . $this->stream->read($lengthToRead);

        if($newData === '') {
            $this->encryptedData .= StreamHelper::calculateMac($this->hashCtx);
            $this->eof = true;
            $data = $this->encryptedData;
            $this->encryptedData = '';
            $this->position += strlen($data);
            return $data;
        }

        $this->lastPart = $this->stream->read(StreamHelper::BLOCK_SIZE);

        $zeroPadding = $this->lastPart === '' ? 0 : OPENSSL_ZERO_PADDING;

        $encrypted = openssl_encrypt(
            $newData,
            'aes-256-cbc',
            $this->keys['cipherKey'],
            OPENSSL_RAW_DATA | $zeroPadding,
            $this->curIv
        );

        $this->encryptedData .= $encrypted;
        hash_update($this->hashCtx, $encrypted);

        $this->curIv = substr($encrypted, -StreamHelper::BLOCK_SIZE);

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
