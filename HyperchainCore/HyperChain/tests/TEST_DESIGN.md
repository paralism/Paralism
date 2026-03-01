# HyperChain 模块测试设计方案

## 模块概述

`HyperChain/` 是 HyperchainCore 的链空间管理核心，包含：
- `HyperChainSpace.cpp/h` — 超块缓存管理、分叉选择、链同步、超块验收

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| HyperChainSpace.h | `CHyperChainSpace` |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_hyperchainspace.cpp | HyperChainSpace.cpp | 分叉选择、HID 区间段、缓存逻辑 |

---

## test_hyperchainspace.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| HCS-01 | isMoreWell_MoreBlocks | 远端 7 vs 本地 5 | true | P0 |
| HCS-02 | isMoreWell_SameCount_SmallerHash | 相同数量, 远端 hash 更小 | true | P0 |
| HCS-03 | isMoreWell_SameCount_LargerHash | 相同数量, 远端 hash 更大 | false | P0 |
| HCS-04 | isMoreWell_FewerBlocks | 远端 3 vs 本地 5 | false | P0 |
| HCS-05 | isAccept_NotExist | 本地不存在该块 | 接受 (true) | P0 |
| HCS-06 | isAccept_SameHash | 同一个块 | 拒绝 (false) | P0 |
| HCS-07 | isAccept_Fork | 同高度不同哈希 | 接受 (true) | P0 |
| HCS-08 | HIDSection_Continuous | {1,2,3,4,5} | ["1-5"] | P0 |
| HCS-09 | HIDSection_Disjoint | {1,2,3,5,6,8} | ["1-3","5-6","8-8"] | P0 |
| HCS-10 | HIDSection_Single | {42} | ["42-42"] | P1 |
| HCS-11 | HIDSection_Empty | {} | [] | P1 |
| HCS-12 | SaveAndLoad | 存→读 | 数据一致 | P0 |
| HCS-13 | CacheUpdate_NewHighest | 新最高块 | uiMaxBlockNum 更新 | P0 |
| HCS-14 | CacheUpdate_OlderBlock | 低于最高块 | uiMaxBlockNum 不变 | P1 |
