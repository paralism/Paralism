# crypto 模块测试设计方案

## 模块概述

`crypto/` 是 HyperchainCore 的密码学层，包含：
- SHA256 摘要算法（`Digest<DT::sha256>`）
- Merkle 树构建与验证

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| sha256.h | `Digest<DT::sha256>`, `AddData`, `getDigest` |
| 相关: commonstruct.h | `T_HYPERBLOCKBODY::MTRoot()` — Merkle 根计算 |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_digest.cpp | crypto/ | SHA256 摘要计算、Merkle 树逻辑 |

---

## test_digest.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| DIG-01 | EmptyDigest | 空输入 | 非零哈希（SHA256 of empty） | P0 |
| DIG-02 | DeterministicDigest | 相同输入两次 | 哈希一致 | P0 |
| DIG-03 | DifferentInput | 不同输入 | 哈希不同 | P0 |
| DIG-04 | AddDataString | 字符串数据 | 非零 | P0 |
| DIG-05 | AddDataBinary | 二进制数据 | 非零 | P0 |
| DIG-06 | IncrementalVsBatch | "AB" vs "A"+"B" | 哈希一致 | P0 |
| DIG-07 | MerkleRootSingleLeaf | 1 个叶子 | ==叶子本身 | P1 |
| DIG-08 | MerkleRootTwoLeaves | 2 个叶子 | ==H(A||B) | P1 |
| DIG-09 | MerkleRootOddLeaves | 3 个叶子 | 补全后正确 | P1 |
| DIG-10 | MerkleOrderMatters | AB vs BA | 不同 | P0 |
