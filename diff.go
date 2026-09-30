package filedelta

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// Delta op kinds.
const (
	opLiteral = byte('L')
	opCopy    = byte('C')
)

// rollBase is the polynomial base of the rolling prefilter hash.
const rollBase = 1099511628211

// rolling is a polynomial rolling hash over a fixed-length window.
// It only selects candidates; every match is confirmed with SHA-256.
type rolling struct {
	pow uint64 // rollBase^(n-1)
	h   uint64
}

func newRolling(n int) *rolling {
	pow := uint64(1)
	for i := 0; i < n-1; i++ {
		pow *= rollBase
	}
	return &rolling{pow: pow}
}

func (r *rolling) compute(b []byte) {
	r.h = 0
	for _, c := range b {
		r.h = r.h*rollBase + uint64(c)
	}
}

func (r *rolling) roll(out, in byte) {
	r.h = (r.h-uint64(out)*r.pow)*rollBase + uint64(in)
}

// Diff generates a delta from newer using only the baseline signature,
// and streams COPY(offset,length) / LITERAL(bytes) ops to out.
func Diff(sig *Signature, newer io.Reader, out io.Writer) error {
	// Index full-length blocks by rolling hash; keep the short final
	// block apart. Candidate lists stay in baseline offset order.
	full := make(map[uint64][]Block)
	var tail *Block
	for _, b := range sig.Blocks {
		if b.Length == BlockSize {
			full[b.Roll] = append(full[b.Roll], b)
		} else {
			t := b
			tail = &t
		}
	}

	w := &deltaWriter{out: out}
	var buf []byte // unconsumed bytes of newer
	eof := false
	fill := func() error {
		for !eof && len(buf) < BlockSize {
			chunk := make([]byte, BlockSize-len(buf))
			// A short read is legal and is not end of file.
			n, err := io.ReadFull(newer, chunk)
			buf = append(buf, chunk[:n]...)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				eof = true
			} else if err != nil {
				return err
			}
		}
		return nil
	}

	hFull := newRolling(BlockSize)
	fullValid := false
	var hTail *rolling
	tailValid := false
	tailLen := 0
	if tail != nil {
		tailLen = tail.Length
		hTail = newRolling(tailLen)
	}

	for {
		if err := fill(); err != nil {
			return err
		}
		if len(buf) == 0 {
			break
		}

		// Longest match wins; ties go to the smallest baseline offset.
		bestLen := 0
		var bestOff int64
		if len(buf) >= BlockSize {
			if !fullValid {
				hFull.compute(buf[:BlockSize])
				fullValid = true
			}
			if cands, ok := full[hFull.h]; ok {
				sum := sha256.Sum256(buf[:BlockSize])
				for _, c := range cands {
					if c.Sum == sum {
						bestLen = BlockSize
						bestOff = c.Offset
						break
					}
				}
			}
		}
		if tail != nil && bestLen == 0 && len(buf) >= tailLen {
			if !tailValid {
				hTail.compute(buf[:tailLen])
				tailValid = true
			}
			if hTail.h == tail.Roll &&
				sha256.Sum256(buf[:tailLen]) == tail.Sum {
				bestLen = tailLen
				bestOff = tail.Offset
			}
		}

		if bestLen > 0 {
			if err := w.flushLiteral(); err != nil {
				return err
			}
			if err := w.copy(bestOff, bestLen); err != nil {
				return err
			}
			buf = buf[bestLen:]
			fullValid, tailValid = false, false
		} else {
			w.literal = append(w.literal, buf[0])
			if len(w.literal) >= BlockSize {
				// Keep literal buffering bounded; adjacent
				// LITERAL ops are equivalent to one merged op.
				if err := w.flushLiteral(); err != nil {
					return err
				}
			}
			outByte := buf[0]
			buf = buf[1:]
			if err := fill(); err != nil {
				return err
			}
			if fullValid && len(buf) >= BlockSize {
				hFull.roll(outByte, buf[BlockSize-1])
			} else {
				fullValid = false
			}
			if tailValid && len(buf) >= tailLen {
				hTail.roll(outByte, buf[tailLen-1])
			} else {
				tailValid = false
			}
		}
	}
	return w.flushLiteral()
}

// deltaWriter accumulates literal bytes and encodes ops.
type deltaWriter struct {
	out     io.Writer
	literal []byte
}

func (w *deltaWriter) flushLiteral() error {
	if len(w.literal) == 0 {
		return nil
	}
	head := append([]byte{opLiteral}, binary.AppendUvarint(nil, uint64(len(w.literal)))...)
	if _, err := w.out.Write(head); err != nil {
		return err
	}
	if _, err := w.out.Write(w.literal); err != nil {
		return err
	}
	w.literal = w.literal[:0]
	return nil
}

func (w *deltaWriter) copy(offset int64, length int) error {
	head := append([]byte{opCopy}, binary.AppendUvarint(nil, uint64(offset))...)
	head = binary.AppendUvarint(head, uint64(length))
	_, err := w.out.Write(head)
	return err
}
