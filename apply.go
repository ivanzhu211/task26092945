package filedelta

import (
	"io"
)

// Apply 流式应用差分 delta，从 base 读取 COPY 引用的数据，
// 还原出的新文件内容写入 out。
func Apply(base io.ReaderAt, delta io.Reader, out io.Writer) error {
	for {
		o, err := readOp(delta)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if o.isCopy {
			buf := make([]byte, o.length)
			// ReaderAt.ReadAt 在读取不足 len(buf) 时必然返回错误。
			if _, err := base.ReadAt(buf, o.offset); err != nil {
				return err
			}
			if _, err := out.Write(buf); err != nil {
				return err
			}
		} else {
			if _, err := out.Write(o.literal); err != nil {
				return err
			}
		}
	}
}
