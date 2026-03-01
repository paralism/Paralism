# consensus 模块测试设计方案

## 模块概述

`consensus/` 是 HyperchainCore 的共识引擎，包含：
- `consensus_engine.cpp/h` — 四阶段共识调度、超块创建、上链管理
- `buddyinfo.h` — `_tp2pmanagerstatus` 共识状态结构
- `crosschaintx.cpp/h` — 跨链交易状态机 (Para ↔ Ethereum)

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| consensus_engine.h | `ConsensusEngine`, `ONCHAINSTATUS` |
| buddyinfo.h | `_tp2pmanagerstatus`, `ClearStatus`, 共识阶段计算 |
| crosschaintx.h | `CrossChainExecutorBase`, `ParaToEthExecutor`, 状态类 |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_consensus_engine.cpp | consensus_engine.cpp, buddyinfo.h | 阶段计算、状态管理 |
| test_crosschaintx.cpp | crosschaintx.cpp | 跨链状态机 |

---

## test_consensus_engine.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| CON-01 | ConsensusCircle | time(nullptr) | >0 的整数 | P0 |
| CON-02 | SameWindowSameCircle | 同30秒窗口 | circle 相同 | P0 |
| CON-03 | PhaseMapping_Prepare | 0-25%窗口 | PREPARE | P0 |
| CON-04 | PhaseMapping_Local | 25-50%窗口 | LOCAL | P0 |
| CON-05 | PhaseMapping_Global | 50-75%窗口 | GLOBAL | P0 |
| CON-06 | PhaseMapping_Persist | 75-100%窗口 | PERSIST | P0 |
| CON-07 | ClearStatus_Flags | ClearStatus() | 所有 bool=false | P0 |
| CON-08 | ClearStatus_Lists | ClearStatus() | 所有 list 为空 | P0 |
| CON-09 | ClearStatus_BuddyInfo | ClearStatus() | eBuddyState=IDLE | P0 |
| CON-10 | OnChainStatus_Enum | 所有枚举值 | 可转换为 char | P1 |

## test_crosschaintx.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| CC-01 | InitialState | 新建 executor | 未完成 | P0 |
| CC-02 | ExceptionPreserves | ExceptionState | prevState 保留 | P0 |
| CC-03 | CompletedFlag | CompletedState | isCompleted==true | P0 |
| CC-04 | ReentryGuard | m_isDoing | 初始为 false | P0 |
| CC-05 | StateToString | toString() | 包含状态名 | P1 |
| CC-06 | ExecutorDetails | details() | 包含金额和地址 | P1 |
