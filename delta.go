package filedelta

import (
	"encoding/binary"
	"fmt"
	"io"
)

// 差分操作码。
const (
	opCopy    byte = 1
	opLiteral byte = 2
)

// CopyOp 表示从基线 offset 处复制 length 字节。
type CopyOp struct {
	Offset int64
	Length int
}

// writeCopy 向差分流写入一条 COPY 指令。
func writeCopy(out io.Writer, op CopyOp) error {
	var buf [binary.MaxVarintLen64*2 + 1]byte
	buf[0] = opCopy
	n := 1 + binary.PutUvarint(buf[1:], uint64(op.Offset))
	n += binary.PutUvarint(buf[n:], uint64(op.Length))
	_, err := out.Write(buf[:n])
	return err
}

// writeLiteral 向差分流写入一条 LITERAL 指令。
func writeLiteral(out io.Writer, data []byte) error {
	var hdr [binary.MaxVarintLen64 + 1]byte
	hdr[0] = opLiteral
	n := 1 + binary.PutUvarint(hdr[1:], uint64(len(data)))
	if _, err := out.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := out.Write(data)
	return err
}

// op 是从差分流解码出的一条指令。
type op struct {
	isCopy  bool
	offset  int64
	length  int
	literal []byte // 仅 LITERAL 使用
}

// readOp 从 delta 读取一条指令；流结束时返回 io.EOF。
// 使用 io.ReadFull 读取，正确处理合法短读。
func readOp(delta io.Reader) (op, error) {
	var tag [1]byte
	if _, err := io.ReadFull(delta, tag[:]); err != nil {
		if err == io.EOF {
			return op{}, io.EOF
		}
		return op{}, fmt.Errorf("read op tag: %w", err)
	}
	br := &byteReader{r: delta}
	switch tag[0] {
	case opCopy:
		offset, err := binary.ReadUvarint(br)
		if err != nil {
			return op{}, fmt.Errorf("read copy offset: %w", err)
		}
		length, err := binary.ReadUvarint(br)
		if err != nil {
			return op{}, fmt.Errorf("read copy length: %w", err)
		}
		return op{isCopy: true, offset: int64(offset), length: int(length)}, nil
	case opLiteral:
		length, err := binary.ReadUvarint(br)
		if err != nil {
			return op{}, fmt.Errorf("read literal length: %w", err)
		}
		data := make([]byte, int(length))
		if _, err := io.ReadFull(delta, data); err != nil {
			return op{}, fmt.Errorf("read literal data: %w", err)
		}
		return op{length: int(length), literal: data}, nil
	default:
		return op{}, fmt.Errorf("unknown op tag %d", tag[0])
	}
}

// byteReader 为 io.Reader 适配 io.ByteReader，供 binary.ReadUvarint 使用。
type byteReader struct {
	r   io.Reader
	buf [1]byte
}

func (b *byteReader) ReadByte() (byte, error) {
	_, err := io.ReadFull(b.r, b.buf[:])
	return b.buf[0], err
}
