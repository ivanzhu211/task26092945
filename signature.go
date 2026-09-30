package filedelta

import (
	"crypto/sha256"
	"io"
)

// BlockSize 是基线切块的标准大小，末块可能不足该长度。
const BlockSize = 64 * 1024

// Block 描述基线中一个块的签名。
type Block struct {
	Index  int      // 块在基线中的序号
	Offset int64    // 块在基线中的字节偏移
	Length int      // 块的实际长度，末块可能小于 BlockSize
	Weak   uint64   // 块内容的滚动弱哈希，用于候选筛选
	Sum    [32]byte // 块内容的 SHA-256 摘要
}

// Signature 是基线文件的块签名集合。
type Signature struct {
	Blocks []Block
}

// BuildSignature 顺序读取 base，按 BlockSize 切块并计算签名。
// 空文件返回不含任何块的签名。
func BuildSignature(base io.Reader) (*Signature, error) {
	sig := &Signature{}
	buf := make([]byte, BlockSize)
	var offset int64
	for {
		// ReadFull 会循环读取直到填满或遇到 EOF，正确处理合法短读。
		n, err := io.ReadFull(base, buf)
		if err == io.EOF {
			// 第一个块就 EOF：空文件，没有块。
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		// n > 0：得到一个完整块或短末块。
		sig.Blocks = append(sig.Blocks, Block{
			Index:  len(sig.Blocks),
			Offset: offset,
			Length: n,
			Weak:   weakHash(buf[:n]),
			Sum:    sha256.Sum256(buf[:n]),
		})
		offset += int64(n)
		if err == io.ErrUnexpectedEOF {
			// 短末块之后即文件结束。
			break
		}
	}
	return sig, nil
}
