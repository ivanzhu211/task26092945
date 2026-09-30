package filedelta

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

// trickleReader 每次 Read 最多返回 max 字节，模拟合法短读。
type trickleReader struct {
	r   io.Reader
	max int
}

func (t *trickleReader) Read(p []byte) (int, error) {
	if len(p) > t.max {
		p = p[:t.max]
	}
	return t.r.Read(p)
}

// roundTrip 对 base/newer 执行签名、差分、还原，并校验结果。
func roundTrip(t *testing.T, base, newer []byte, readChunk int) []byte {
	t.Helper()
	var sigSrc io.Reader = bytes.NewReader(base)
	var diffSrc io.Reader = bytes.NewReader(newer)
	if readChunk > 0 {
		sigSrc = &trickleReader{r: sigSrc, max: readChunk}
		diffSrc = &trickleReader{r: diffSrc, max: readChunk}
	}
	sig, err := BuildSignature(sigSrc)
	if err != nil {
		t.Fatalf("BuildSignature: %v", err)
	}
	var delta bytes.Buffer
	if err := Diff(sig, diffSrc, &delta); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var deltaSrc io.Reader = bytes.NewReader(delta.Bytes())
	if readChunk > 0 {
		deltaSrc = &trickleReader{r: deltaSrc, max: readChunk}
	}
	var restored bytes.Buffer
	if err := Apply(bytes.NewReader(base), deltaSrc, &restored); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), newer) {
		t.Fatalf("restored mismatch: want %d bytes, got %d bytes", len(newer), restored.Len())
	}
	return delta.Bytes()
}

// TestShortReads 用分片短读输入验证签名、差分、还原三条流式路径。
func TestShortReads(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	base := makeBaseline(rng)
	newer := randomEdit(rng, base)
	for _, chunk := range []int{1, 7, 4096} {
		roundTrip(t, base, newer, chunk)
	}
}

// TestEdgeCases 覆盖空文件、全匹配、短末块匹配等边界。
func TestEdgeCases(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	full := make([]byte, BlockSize)
	rng.Read(full)
	tail := make([]byte, 100)
	rng.Read(tail)
	base := append(append([]byte(nil), full...), tail...)

	cases := []struct {
		name  string
		base  []byte
		newer []byte
	}{
		{"both empty", nil, nil},
		{"empty base", nil, []byte("hello world")},
		{"empty newer", base, nil},
		{"identical", base, base},
		{"tail only match", base, append([]byte("ab"), tail...)},
		{"tail at unaligned offset", base, append([]byte("zzz"), append(full[:10], tail...)...)},
		{"shorter than one block", tail, append([]byte("q"), tail...)},
		{"exact multiple no tail", full, full},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig, err := BuildSignature(bytes.NewReader(c.base))
			if err != nil {
				t.Fatalf("BuildSignature: %v", err)
			}
			got, _ := runDiffOps(t, sig, c.newer)
			compareOps(t, naiveOps(c.base, c.newer), got)
			roundTrip(t, c.base, c.newer, 0)
			roundTrip(t, c.base, c.newer, 3)
		})
	}
}

// TestShortTailReuse 验证新文件剩余不足 64KiB 时仍能匹配基线短末块。
func TestShortTailReuse(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	tail := make([]byte, 500)
	rng.Read(tail)
	base := append(make([]byte, BlockSize), tail...)
	rng.Read(base[:BlockSize])
	// 新文件只剩末块内容（前面插入一字节制造错位），总长远不足 64KiB。
	newer := append([]byte("!"), tail...)
	sig, err := BuildSignature(bytes.NewReader(base))
	if err != nil {
		t.Fatalf("BuildSignature: %v", err)
	}
	ops, _ := runDiffOps(t, sig, newer)
	compareOps(t, naiveOps(base, newer), ops)
	want := expectOp{isCopy: true, offset: BlockSize, length: 500}
	if len(ops) != 2 || ops[0].isCopy || !ops[1].isCopy || ops[1].offset != want.offset || ops[1].length != want.length {
		t.Fatalf("expected LITERAL(1) + COPY(%d,%d), got %v", want.offset, want.length, ops)
	}
}
