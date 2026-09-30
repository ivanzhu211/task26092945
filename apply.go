package filedelta

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Apply streams the delta against base and writes the reconstructed
// new file to out.
func Apply(base io.ReaderAt, delta io.Reader, out io.Writer) error {
	r := bufio.NewReader(delta)
	for {
		op, err := r.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch op {
		case opCopy:
			offset, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("delta: copy offset: %w", err)
			}
			length, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("delta: copy length: %w", err)
			}
			src := io.NewSectionReader(base, int64(offset), int64(length))
			if _, err := io.CopyN(out, src, int64(length)); err != nil {
				return fmt.Errorf("delta: copy data: %w", err)
			}
		case opLiteral:
			length, err := binary.ReadUvarint(r)
			if err != nil {
				return fmt.Errorf("delta: literal length: %w", err)
			}
			if _, err := io.CopyN(out, r, int64(length)); err != nil {
				return fmt.Errorf("delta: literal data: %w", err)
			}
		default:
			return fmt.Errorf("delta: unknown op %q", op)
		}
	}
}
