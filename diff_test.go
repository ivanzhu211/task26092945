package filedelta

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

// expectOp 是参照实现产出的一条期望指令。
type expectOp struct {
	isCopy  bool
	offset  int64
	length  int
	literal []byte
}

// naiveOps 是小样本朴素参照实现：在每个位置直接逐字节比较所有基线块，
// 选择最长匹配，并列时取基线偏移最小者；无匹配则累积 LITERAL。
func naiveOps(base, newer []byte) []expectOp {
	type blk struct {
		off  int64
		data []byte
	}
	var blocks []blk
	for off := int64(0); off < int64(len(base)); {
		n := BlockSize
		if rem := len(base) - int(off); rem < n {
			n = rem
		}
		blocks = append(blocks, blk{off: off, data: base[off : off+int64(n)]})
		off += int64(n)
	}
	var ops []expectOp
	var lit []byte
	flush := func() {
		if len(lit) > 0 {
			ops = append(ops, expectOp{length: len(lit), literal: append([]byte(nil), lit...)})
			lit = lit[:0]
		}
	}
	pos := 0
	for pos < len(newer) {
		bestLen, bestOff := 0, int64(-1)
		for _, b := range blocks {
			l := len(b.data)
			if pos+l > len(newer) {
				continue
			}
			if !bytes.Equal(newer[pos:pos+l], b.data) {
				continue
			}
			if l > bestLen || (l == bestLen && (bestOff < 0 || b.off < bestOff)) {
				bestLen, bestOff = l, b.off
			}
		}
		if bestOff >= 0 {
			flush()
			ops = append(ops, expectOp{isCopy: true, offset: bestOff, length: bestLen})
			pos += bestLen
		} else {
			lit = append(lit, newer[pos])
			pos++
		}
	}
	flush()
	return ops
}

// runDiffOps 用被测实现生成差分并解析回指令序列。
func runDiffOps(t *testing.T, sig *Signature, newer []byte) ([]expectOp, []byte) {
	t.Helper()
	var delta bytes.Buffer
	if err := Diff(sig, bytes.NewReader(newer), &delta); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var ops []expectOp
	r := bytes.NewReader(delta.Bytes())
	for {
		o, err := readOp(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("readOp: %v", err)
		}
		ops = append(ops, expectOp{isCopy: o.isCopy, offset: o.offset, length: o.length, literal: o.literal})
	}
	return ops, delta.Bytes()
}

func compareOps(t *testing.T, want, got []expectOp) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("op count: want %d, got %d\nwant=%v\ngot=%v", len(want), len(got), want, got)
	}
	for i := range want {
		w, g := want[i], got[i]
		if w.isCopy != g.isCopy || w.offset != g.offset || w.length != g.length {
			t.Fatalf("op %d: want %+v, got %+v", i, w, g)
		}
		if !w.isCopy && !bytes.Equal(w.literal, g.literal) {
			t.Fatalf("op %d literal mismatch: want %d bytes, got %d bytes", i, len(w.literal), len(g.literal))
		}
	}
}

// makeBaseline 构造包含重复块与短末块的基线。
func makeBaseline(rng *rand.Rand) []byte {
	// 用少量种子块拼接，制造大量重复内容。
	var seeds [][]byte
	for i := 0; i < 4; i++ {
		s := make([]byte, 1024)
		rng.Read(s)
		seeds = append(seeds, s)
	}
	total := 2*BlockSize + BlockSize/2 + 1000 // 2.5 块 + 短末块
	base := make([]byte, 0, total)
	for len(base) < total {
		base = append(base, seeds[rng.Intn(len(seeds))]...)
	}
	return base[:total]
}

// randomEdit 对 base 做随机插入、删除与覆盖，产生新文件。
func randomEdit(rng *rand.Rand, base []byte) []byte {
	newer := append([]byte(nil), base...)
	edits := 1 + rng.Intn(6)
	for i := 0; i < edits; i++ {
		if len(newer) == 0 {
			break
		}
		pos := rng.Intn(len(newer) + 1)
		switch rng.Intn(3) {
		case 0: // 插入随机字节或基线片段
			var ins []byte
			if rng.Intn(2) == 0 && len(base) > 0 {
				s := rng.Intn(len(base))
				e := s + rng.Intn(min(4096, len(base)-s)+1)
				ins = base[s:e]
			} else {
				ins = make([]byte, rng.Intn(2048)+1)
				rng.Read(ins)
			}
			newer = append(newer[:pos], append(ins, newer[pos:]...)...)
		case 1: // 删除一段
			if pos < len(newer) {
				n := rng.Intn(min(4096, len(newer)-pos) + 1)
				newer = append(newer[:pos], newer[pos+n:]...)
			}
		case 2: // 覆盖一段
			if pos < len(newer) {
				n := rng.Intn(min(2048, len(newer)-pos) + 1)
				rng.Read(newer[pos : pos+n])
			}
		}
	}
	return newer
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestDiffAgainstNaive 对随机编辑后的新文件，比较被测实现与朴素参照的
// 匹配选择、LITERAL 内容，并验证 Apply 还原结果逐字节一致。
func TestDiffAgainstNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 30; iter++ {
		base := makeBaseline(rng)
		newer := randomEdit(rng, base)
		sig, err := BuildSignature(bytes.NewReader(base))
		if err != nil {
			t.Fatalf("BuildSignature: %v", err)
		}
		got, delta := runDiffOps(t, sig, newer)
		compareOps(t, naiveOps(base, newer), got)

		var restored bytes.Buffer
		if err := Apply(bytes.NewReader(base), bytes.NewReader(delta), &restored); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !bytes.Equal(restored.Bytes(), newer) {
			t.Fatalf("iter %d: restored mismatch", iter)
		}
	}
}

// TestShiftedBlocks 验证开头插入少量字节后，后续错位的基线块仍被 COPY 复用。
func TestShiftedBlocks(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	base := makeBaseline(rng)
	newer := append([]byte("XYZ"), base...)
	sig, err := BuildSignature(bytes.NewReader(base))
	if err != nil {
		t.Fatalf("BuildSignature: %v", err)
	}
	ops, delta := runDiffOps(t, sig, newer)
	compareOps(t, naiveOps(base, newer), ops)
	copies := 0
	for _, o := range ops {
		if o.isCopy {
			copies++
		}
	}
	if copies < 2 {
		t.Fatalf("expected shifted blocks to be reused via COPY, got %d copies", copies)
	}
	var restored bytes.Buffer
	if err := Apply(bytes.NewReader(base), bytes.NewReader(delta), &restored); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), newer) {
		t.Fatal("restored mismatch")
	}
}
