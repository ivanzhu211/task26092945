# filedelta

文件级增量备份库：保存基线文件的块签名，仅凭签名生成新文件的差分，再用基线与差分还原新文件。插入或删除少量字节后，后续错位的基线块仍能通过 COPY 复用。

## 用法

```go
sig, _ := filedelta.BuildSignature(baseReader) // 基线按 64KiB 切块，末块保留实际长度
var delta bytes.Buffer
filedelta.Diff(sig, newerReader, &delta)       // 只凭签名生成 COPY/LITERAL 差分
var out bytes.Buffer
filedelta.Apply(baseReaderAt, &delta, &out)    // 流式还原，out 与 newer 逐字节相同
```

## 匹配规则

- 在新文件任意字节偏移处寻找与基线块完全相同的完整块（含不足 64KiB 的短末块）。
- 多个候选时先选最长块，再选基线偏移最小者。
- 无匹配时当前字节进入 LITERAL，相邻 LITERAL 自动合并。
- 滚动弱哈希（Rabin-Karp）筛选候选，所有 COPY 均经 SHA-256 确认。

## 测试

```sh
go test ./...
```

包含朴素参照实现对比（随机插入/删除/覆盖、跨块编辑、非对齐匹配）与分片短读流式路径验证。
