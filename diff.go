package filedelta

import (
	"crypto/sha256"
	"io"
	"sort"
)

// rollingBasis 是 Rabin-Karp 滚动哈希的底数，运算在自然溢出的 mod 2^64 下进行。
const rollingBasis = 257

// idxKey 是块索引的键：按块长度与弱哈希分组。
type idxKey struct {
	length int
	weak   uint64
}

// rolling 维护某一固定长度窗口的滚动哈希。
type rolling struct {
	length int
	pow    uint64 // rollingBasis^(length-1)
	hash   uint64
	valid  bool
}

// matcher 在 newer 的流式缓冲上执行块匹配。
type matcher struct {
	r     io.Reader
	buf   []byte // buf[start:] 为尚未消费的数据
	start int
	eof   bool

	sig   *Signature
	index map[idxKey][]int // 块索引列表按基线偏移升序
	rolls []rolling        // 按长度降序
}

func newMatcher(sig *Signature, r io.Reader) *matcher {
	m := &matcher{r: r, sig: sig, index: make(map[idxKey][]int)}
	lengths := map[int]bool{}
	for i, b := range sig.Blocks {
		lengths[b.Length] = true
		k := idxKey{length: b.Length, weak: b.Weak}
		m.index[k] = append(m.index[k], i)
	}
	sorted := make([]int, 0, len(lengths))
	for l := range lengths {
		sorted = append(sorted, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))
	for _, l := range sorted {
		pow := uint64(1)
		for i := 0; i < l-1; i++ {
			pow *= rollingBasis
		}
		m.rolls = append(m.rolls, rolling{length: l, pow: pow})
	}
	return m
}

// weakHash 计算窗口的滚动哈希初值。
func weakHash(window []byte) uint64 {
	var h uint64
	for _, b := range window {
		h = h*rollingBasis + uint64(b)
	}
	return h
}

func (m *matcher) len() int { return len(m.buf) - m.start }

// fill 确保缓冲区内至少有 need 字节，或已到达 EOF。
func (m *matcher) fill(need int) error {
	for m.len() < need && !m.eof {
		m.compact()
		if len(m.buf) == cap(m.buf) {
			newCap := cap(m.buf) * 2
			if newCap < need+1 {
				newCap = need + 1
			}
			if newCap < BlockSize+1 {
				newCap = BlockSize + 1
			}
			nbuf := make([]byte, m.len(), newCap)
			copy(nbuf, m.buf[m.start:])
			m.buf = nbuf
			m.start = 0
		}
		n, err := m.r.Read(m.buf[len(m.buf):cap(m.buf)])
		m.buf = m.buf[:len(m.buf)+n]
		if err == io.EOF {
			m.eof = true
		} else if err != nil {
			return err
		}
	}
	return nil
}

// compact 在已消费前缀过大时将其丢弃，避免缓冲区无限增长。
func (m *matcher) compact() {
	if m.start > 0 && m.start >= cap(m.buf)/2 {
		copy(m.buf, m.buf[m.start:])
		m.buf = m.buf[:m.len()]
		m.start = 0
	}
}

// hashAt 返回指定长度窗口在当前位置的滚动哈希，必要时从头计算。
func (m *matcher) hashAt(r *rolling) uint64 {
	if !r.valid {
		r.hash = weakHash(m.buf[m.start : m.start+r.length])
		r.valid = true
	}
	return r.hash
}

// advance 前进一个字节，同时滚动所有有效窗口哈希。
func (m *matcher) advanceOne() {
	for i := range m.rolls {
		r := &m.rolls[i]
		if !r.valid {
			continue
		}
		if m.len() > r.length {
			out := m.buf[m.start]
			in := m.buf[m.start+r.length]
			r.hash = (r.hash-uint64(out)*r.pow)*rollingBasis + uint64(in)
		} else {
			r.valid = false
		}
	}
	m.start++
}

func (m *matcher) advance(n int) {
	for i := 0; i < n; i++ {
		m.advanceOne()
	}
}

// findMatch 在当前位置寻找匹配：先按长度降序，再按基线偏移升序。
// 所有候选均以完整 SHA-256 确认。
func (m *matcher) findMatch() (CopyOp, bool, error) {
	for i := range m.rolls {
		r := &m.rolls[i]
		if err := m.fill(r.length); err != nil {
			return CopyOp{}, false, err
		}
		if m.len() < r.length {
			continue // 剩余数据不足该块长度
		}
		cands := m.index[idxKey{length: r.length, weak: m.hashAt(r)}]
		if len(cands) == 0 {
			continue
		}
		window := m.buf[m.start : m.start+r.length]
		sum := sha256.Sum256(window)
		for _, bi := range cands {
			if m.sig.Blocks[bi].Sum == sum {
				blk := m.sig.Blocks[bi]
				return CopyOp{Offset: blk.Offset, Length: blk.Length}, true, nil
			}
		}
	}
	return CopyOp{}, false, nil
}

// Diff 仅利用签名 sig 对 newer 生成差分并流式写入 out。
// 差分由 COPY(offset,length) 与 LITERAL(bytes) 指令组成。
func Diff(sig *Signature, newer io.Reader, out io.Writer) error {
	m := newMatcher(sig, newer)
	var lit []byte
	flush := func() error {
		if len(lit) > 0 {
			if err := writeLiteral(out, lit); err != nil {
				return err
			}
			lit = lit[:0]
		}
		return nil
	}
	for {
		if err := m.fill(1); err != nil {
			return err
		}
		if m.len() == 0 {
			return flush()
		}
		op, ok, err := m.findMatch()
		if err != nil {
			return err
		}
		if ok {
			if err := flush(); err != nil {
				return err
			}
			if err := writeCopy(out, op); err != nil {
				return err
			}
			m.advance(op.Length)
		} else {
			lit = append(lit, m.buf[m.start])
			m.advance(1)
		}
	}
}
