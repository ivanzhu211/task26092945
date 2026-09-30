package filedelta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

// testOp is one decoded delta operation.
type testOp struct {
	kind   byte
	offset int64
	data   []byte // literal payload; length for COPY is len(data)? no: use length field
	length int
}

// naiveDiff is the small-sample reference implementation: it scans every
// baseline block at every position of newer and applies the same rules
// (longest match, then smallest baseline offset; otherwise one literal byte).
func naiveDiff(base, newer []byte) []testOp {
	type blk struct {
		off int64
		buf []byte
	}
	var blocks []blk
	for off := 0; off < len(base); off += BlockSize {
		end := off + BlockSize
		if end > len(base) {
			end = len(base)
		}
		blocks = append(blocks, blk{int64(off), base[off:end]})
	}

	var ops []testOp
	for pos := 0; pos < len(newer); {
		bestLen := 0
		var bestOff int64
		for _, b := range blocks { // offset order keeps ties at smallest offset
			if len(b.buf) > bestLen && pos+len(b.buf) <= len(newer) &&
				bytes.Equal(newer[pos:pos+len(b.buf)], b.buf) {
				bestLen = len(b.buf)
				bestOff = b.off
			}
		}
		if bestLen > 0 {
			ops = append(ops, testOp{kind: opCopy, offset: bestOff, length: bestLen})
			pos += bestLen
		} else {
			ops = append(ops, testOp{kind: opLiteral, data: newer[pos : pos+1]})
			pos++
		}
	}
	return mergeLiterals(ops)
}

// mergeLiterals merges adjacent literal ops, as the library is allowed to do.
func mergeLiterals(ops []testOp) []testOp {
	var out []testOp
	for _, op := range ops {
		if op.kind == opLiteral && len(out) > 0 && out[len(out)-1].kind == opLiteral {
			out[len(out)-1].data = append(out[len(out)-1].data, op.data...)
			continue
		}
		out = append(out, op)
	}
	return out
}

// parseDelta decodes the library's delta encoding into ops.
func parseDelta(t *testing.T, delta []byte) []testOp {
	t.Helper()
	r := bytes.NewReader(delta)
	var ops []testOp
	for r.Len() > 0 {
		kind, err := r.ReadByte()
		if err != nil {
			t.Fatalf("read op: %v", err)
		}
		switch kind {
		case opCopy:
			off, err := binary.ReadUvarint(r)
			if err != nil {
				t.Fatalf("read copy offset: %v", err)
			}
			length, err := binary.ReadUvarint(r)
			if err != nil {
				t.Fatalf("read copy length: %v", err)
			}
			ops = append(ops, testOp{kind: opCopy, offset: int64(off), length: int(length)})
		case opLiteral:
			length, err := binary.ReadUvarint(r)
			if err != nil {
				t.Fatalf("read literal length: %v", err)
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(r, data); err != nil {
				t.Fatalf("read literal data: %v", err)
			}
			ops = append(ops, testOp{kind: opLiteral, data: data})
		default:
			t.Fatalf("unknown op %q", kind)
		}
	}
	return ops
}

func opsEqual(a, b []testOp) error {
	if len(a) != len(b) {
		return fmt.Errorf("op count: got %d, want %d", len(a), len(b))
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.kind != y.kind {
			return fmt.Errorf("op %d kind: got %q, want %q", i, x.kind, y.kind)
		}
		if x.kind == opCopy {
			if x.offset != y.offset || x.length != y.length {
				return fmt.Errorf("op %d: got COPY(%d,%d), want COPY(%d,%d)",
					i, x.offset, x.length, y.offset, y.length)
			}
		} else if !bytes.Equal(x.data, y.data) {
			return fmt.Errorf("op %d: literal mismatch (%d vs %d bytes)", i, len(x.data), len(y.data))
		}
	}
	return nil
}

// roundTrip runs the library pipeline and checks ops against the naive
// reference and the Apply output against newer.
func roundTrip(t *testing.T, base, newer []byte, newReader func(io.Reader) io.Reader) {
	t.Helper()

	sig, err := NewSignature(newReader(bytes.NewReader(base)))
	if err != nil {
		t.Fatalf("NewSignature: %v", err)
	}
	var delta bytes.Buffer
	if err := Diff(sig, newReader(bytes.NewReader(newer)), &delta); err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if err := opsEqual(mergeLiterals(parseDelta(t, delta.Bytes())), naiveDiff(base, newer)); err != nil {
		t.Fatalf("ops mismatch: %v\nbase=%dB newer=%dB", err, len(base), len(newer))
	}

	var out bytes.Buffer
	if err := Apply(bytes.NewReader(base), newReader(&delta), &out); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(out.Bytes(), newer) {
		t.Fatalf("Apply output mismatch: got %d bytes, want %d", out.Len(), len(newer))
	}
}

// makeBase builds a baseline with repeated blocks and a short final block.
func makeBase(rng *rand.Rand, fullBlocks int, tailLen int) []byte {
	dict := make([][]byte, 4)
	for i := range dict {
		dict[i] = randomBytes(rng, BlockSize)
	}
	var base []byte
	for i := 0; i < fullBlocks; i++ {
		base = append(base, dict[rng.Intn(len(dict))]...)
	}
	base = append(base, randomBytes(rng, tailLen)...)
	return base
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// mutate applies random insertions, deletions and overwrites, some of which
// cross block boundaries or land at unaligned offsets.
func mutate(rng *rand.Rand, data []byte, edits int) []byte {
	for i := 0; i < edits; i++ {
		if len(data) == 0 {
			data = randomBytes(rng, 1+rng.Intn(64))
			continue
		}
		pos := rng.Intn(len(data) + 1)
		n := 1 + rng.Intn(200)
		switch rng.Intn(3) {
		case 0: // insert
			data = append(data[:pos], append(randomBytes(rng, n), data[pos:]...)...)
		case 1: // delete
			if pos+n > len(data) {
				n = len(data) - pos
			}
			data = append(data[:pos], data[pos+n:]...)
		default: // overwrite
			if pos+n > len(data) {
				n = len(data) - pos
			}
			copy(data[pos:pos+n], randomBytes(rng, n))
		}
	}
	return data
}

func TestRandomEdits(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			base := makeBase(rng, 1+rng.Intn(6), rng.Intn(BlockSize))
			newer := mutate(rng, append([]byte(nil), base...), 1+rng.Intn(6))
			roundTrip(t, base, newer, func(r io.Reader) io.Reader { return r })
		})
	}
}

func TestEdgeCases(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	cases := []struct {
		name  string
		base  []byte
		newer []byte
	}{
		{"both-empty", nil, nil},
		{"empty-base", nil, randomBytes(rng, 1000)},
		{"empty-newer", randomBytes(rng, 1000), nil},
		{"exact-block-multiple", randomBytes(rng, 3*BlockSize), nil},
		{"tail-only-base", randomBytes(rng, 100), randomBytes(rng, 100)},
		{"unaligned-tail-match", nil, nil}, // filled below
	}
	// newer = garbage prefix + base's short tail at an unaligned offset.
	base := append(randomBytes(rng, BlockSize), randomBytes(rng, 77)...)
	cases[5].base = base
	cases[5].newer = append(randomBytes(rng, 13), base[BlockSize:]...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roundTrip(t, tc.base, tc.newer, func(r io.Reader) io.Reader { return r })
		})
	}
}

// shortReader returns at most max bytes per Read, exercising legal short reads.
type shortReader struct {
	r   io.Reader
	rng *rand.Rand
	max int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if n := 1 + s.rng.Intn(s.max); n < len(p) {
		p = p[:n]
	}
	return s.r.Read(p)
}

func TestShortReads(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 30; i++ {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			base := makeBase(rng, 2+rng.Intn(3), 1+rng.Intn(BlockSize-1))
			newer := mutate(rng, append([]byte(nil), base...), 1+rng.Intn(4))
			wrap := func(r io.Reader) io.Reader {
				return &shortReader{r: r, rng: rand.New(rand.NewSource(int64(i + 100))), max: 7}
			}
			roundTrip(t, base, newer, wrap)
		})
	}
}

func TestSignatureFields(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	full := randomBytes(rng, BlockSize)
	tail := randomBytes(rng, 10)
	sig, err := NewSignature(bytes.NewReader(append(full, tail...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Blocks) != 2 {
		t.Fatalf("got %d blocks, want 2", len(sig.Blocks))
	}
	for i, want := range []struct {
		off int64
		len int
		buf []byte
	}{{0, BlockSize, full}, {BlockSize, 10, tail}} {
		b := sig.Blocks[i]
		if b.Index != i || b.Offset != want.off || b.Length != want.len {
			t.Fatalf("block %d: got {%d %d %d}, want {%d %d %d}",
				i, b.Index, b.Offset, b.Length, i, want.off, want.len)
		}
		if b.Sum != sha256.Sum256(want.buf) {
			t.Fatalf("block %d: digest mismatch", i)
		}
	}
}
