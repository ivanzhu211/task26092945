# filedelta

文件级增量备份库：保存基线文件的块签名，仅凭签名生成新文件的差分，
再用基线与差分还原新文件。插入或删除少量字节后，后续错位的基线块
仍可复用（rsync 风格：滚动弱校验预筛 + SHA-256 确认）。

## API

```go
sig, _ := filedelta.NewSignature(baseReader)   // 64KiB 切块，末块保留实际长度
err  := filedelta.Diff(sig, newerReader, deltaWriter)  // 只用签名，流式写出差分
err  = filedelta.Apply(baseReaderAt, deltaReader, outWriter) // 流式还原
```

- 差分由 `COPY(offset,length)` 与 `LITERAL(bytes)` 组成，二进制编码：
  操作字节 `'C'/'L'` + uvarint 参数（LITERAL 后跟原始字节）。
- 匹配规则：当前位置处内容完全相同的最长完整块优先，其次基线偏移最小；
  无匹配则输出 1 字节 LITERAL（相邻 LITERAL 会合并）。
- 所有 COPY 均经 SHA-256 确认；滚动校验仅作候选预筛。

## 测试

```sh
go test ./...
```

测试包含：小样本朴素参照实现对比（重复块 + 短末块基线上的随机
插入/删除/覆盖，覆盖跨块编辑与非对齐匹配）、分片短读输入、边界用例。
