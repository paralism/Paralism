# headers 模块测试设计方案

## 模块概述

`headers/` 是 HyperchainCore 的核心数据结构定义层，包含：
- `shastruct.h` — `T_SHA256` 哈希结构及比较运算
- `commonstruct.h` — `T_LOCALBLOCK`、`T_HYPERBLOCK`、`T_APPTYPE` 等全部链上数据结构
- `inter_public.h` — 跨模块公共接口定义

## 被测文件

| 文件 | 关键类/结构体 |
|------|-------------|
| shastruct.h | `T_SHA256` (`_tsha256`) |
| commonstruct.h | `T_LOCALBLOCK`, `T_LOCALBLOCKHEADER`, `T_LOCALBLOCKBODY`, `T_HYPERBLOCK`, `T_HYPERBLOCKHEADER`, `T_HYPERBLOCKBODY`, `T_APPTYPE` |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_sha256.cpp | shastruct.h | T_SHA256 完整测试 |
| test_commonstruct.cpp | commonstruct.h | 局部块/超块构造与操作 |

---

## test_sha256.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| SHA-01 | ZeroConstruct | `T_SHA256(0)` | 32 字节全 0x00 | P0 |
| SHA-02 | FillConstruct | `T_SHA256(1)` | 32 字节全 0x01 | P0 |
| SHA-03 | EqualitySameContent | 两个相同内容的哈希 | `==` 返回 true | P0 |
| SHA-04 | EqualityDifferent | `0xAA...` vs `0xBB...` | `==` 返回 false | P0 |
| SHA-05 | LessThanOrdering | `0xAA...` vs `0xBB...` | `<` 返回 true | P0 |
| SHA-06 | GreaterThanSymmetry | `0xBB...` vs `0xAA...` | `>` 返回 true | P0 |
| SHA-07 | SelfComparison | `a == a, !(a < a)` | 恒为 true | P0 |
| SHA-08 | HexStringLength | 任意哈希 | hex 长度 == 64 | P0 |
| SHA-09 | HexStringContent | 首字节 0xDE | hex 前两字符 "de" | P1 |
| SHA-10 | IsNullZero | `T_SHA256(0)` | `isNull()` == true | P1 |
| SHA-11 | IsNullNonZero | `0xAA...` | `isNull()` == false | P1 |
| SHA-12 | CopyAssignment | 拷贝后修改副本 | 原值不变 | P0 |
| SHA-13 | MapKeyLookup | 插入两个不同 key | 查找正确 | P0 |
| SHA-14 | MapKeyOverwrite | 相同 key 覆盖 | size 不变 | P0 |
| SHA-15 | SetUniqueness | 插入相同值两次 | size == 1 | P1 |
| SHA-16 | BoostSerRoundTrip | 序列化→反序列化 | 结果一致 | P0 |
| SHA-17 | TransitiveOrdering | a < b, b < c | a < c | P1 |

## test_commonstruct.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| BLK-01 | LocalBlockFieldAccess | 构造后 | getter 返回设定值 | P0 |
| BLK-02 | BuildBodyHashNonZero | 设置 payload | body hash 非零 | P0 |
| BLK-03 | SamePayloadSameHash | 两个相同 payload | body hash 一致 | P0 |
| BLK-04 | DiffPayloadDiffHash | 不同 payload | body hash 不同 | P0 |
| BLK-05 | CalcHashSelfRepeatable | 多次计算 | 结果一致 | P0 |
| BLK-06 | LocalBlockSerRoundTrip | 序列化→反序列化 | 所有字段一致 | P0 |
| BLK-07 | HyperBlockChildCount | AddChildChain(3块) | GetChildBlockCount==3 | P0 |
| BLK-08 | HyperBlockRebuild | Rebuild | vecChildChainBlockCount 正确 | P0 |
| BLK-09 | HyperBlockHashRepeatable | 两次 calculateHashSelf | 相同且非零 | P0 |
| BLK-10 | HeaderHashDiffersFullHash | 头部哈希 vs 完整哈希 | 不同 | P0 |
| BLK-11 | ModificationChangesHash | 修改 uiWeight | 哈希变化 | P0 |
| BLK-12 | MultipleChildChains | 3 条子链(2+1+3块) | count==6, chains==3 | P0 |
| BLK-13 | EmptyHyperBlock | 无子链 | count==0, chains==0 | P1 |
| BLK-14 | LargePayload | 1MB payload | 序列化往返正确 | P1 |
| BLK-15 | MoveSemantics | move 构造 | 源 payload 为空 | P1 |
| BLK-16 | AppTypeSerialize | 设置 Paracoin 类型 | 往返正确 | P1 |
| BLK-17 | ChainLinkage | 10块连续链 | preHash 链接正确 | P0 |
