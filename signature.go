// Package filedelta implements file-level incremental backup:
// block signatures of a baseline, signature-only diff, and delta apply.
package filedelta

import (
	"crypto/sha256"
	"io"
)

// BlockSize is the fixed chunk size for baseline blocks.
const BlockSize = 64 * 1024

// Block describes one baseline chunk.
type Block struct {
	Index  int
	Offset int64
	Length int
	Roll   uint64 // weak rolling checksum, used only as a prefilter
	Sum    [sha256.Size]byte
}

// Signature is the ordered list of baseline block signatures.
type Signature struct {
	Blocks []Block
}

// NewSignature reads base sequentially, splits it into BlockSize chunks
// (the final chunk keeps its actual length; an empty file has no blocks),
// and returns the block signatures.
func NewSignature(base io.Reader) (*Signature, error) {
	sig := &Signature{}
	buf := make([]byte, BlockSize)
	var offset int64
	for {
		// Fill the buffer completely; a short read is not EOF.
		n, err := io.ReadFull(base, buf)
		if err == io.EOF {
			break // no more data at all
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		roll := newRolling(n)
		roll.compute(buf[:n])
		sig.Blocks = append(sig.Blocks, Block{
			Index:  len(sig.Blocks),
			Offset: offset,
			Length: n,
			Roll:   roll.h,
			Sum:    sha256.Sum256(buf[:n]),
		})
		offset += int64(n)
		if err == io.ErrUnexpectedEOF {
			break // final short block
		}
	}
	return sig, nil
}
