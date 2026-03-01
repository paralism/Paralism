# node 模块测试设计方案

## 模块概述

`node/` 是 HyperchainCore 的 P2P 网络与消息通信层，包含：
- `UInt128.cpp/h` — 128 位整数（节点 ID、Kademlia 距离计算）
- `NodeManager.cpp/h` — 节点发现与管理
- `MsgHandler.cpp/h` — ZMQ 消息处理
- `zmsg.cpp/h` — ZMQ 消息封装
- `HCMQBroker/Client/Wrk` — 消息队列 Broker/Worker 框架
- `Singleton.h` — 单例模板

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| UInt128.h | `CUInt128` |
| Singleton.h | `Singleton<T>` |
| zmsg.h / MsgHandler.h | `MQMsgPush`, `MQMsgPop`, `zmsg` |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_uint128.cpp | UInt128.cpp | 128 位整数运算 |
| test_singleton.cpp | Singleton.h | 单例创建/释放 |
| test_mqmsg.cpp | MsgHandler.h, zmsg.h | 消息序列化往返 |

---

## test_uint128.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| U128-01 | ZeroConstruct | uint32(0) | IsZero()==true | P0 |
| U128-02 | NonZeroConstruct | uint32(1) | IsZero()==false | P0 |
| U128-03 | Equality | 相同值 | ==返回 true | P0 |
| U128-04 | Inequality | 不同值 | !=返回 true | P0 |
| U128-05 | LessThan | 0 vs 1 | <返回 true | P0 |
| U128-06 | XORDistance | 0xFF ^ 0x0F | ==0xF0 | P0 |
| U128-07 | HexStringLen | 任意值 | 长度 32 | P1 |
| U128-08 | ShiftLeft | 1 << 8 | ==256 | P1 |
| U128-09 | SerRoundTrip | Boost 序列化 | 往返一致 | P0 |
| U128-10 | CopyConstruct | 拷贝 | ==原值 | P1 |

## test_singleton.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| SGL-01 | InstanceCreation | instance() | !=nullptr | P0 |
| SGL-02 | GetInstance | 创建后 get | !=nullptr | P0 |
| SGL-03 | Uniqueness | 两次 instance | 地址相同 | P0 |
| SGL-04 | Release | release 后 get | ==nullptr | P0 |
| SGL-05 | ParameterizedCtor | instance("a",1) | 字段正确 | P1 |

## test_mqmsg.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| MQ-01 | Uint64RoundTrip | push uint64→pop | 值一致 | P0 |
| MQ-02 | MultiParam | push(u64,bool,u32)→pop | 顺序正确 | P0 |
| MQ-03 | StringRoundTrip | push string→pop | 内容一致 | P0 |
| MQ-04 | EmptyString | push ""→pop | =="" | P1 |
| MQ-05 | LargeString | push 1MB→pop | 长度一致 | P1 |
| MQ-06 | TypeSizeMismatch | push u32, pop u64 | 大小不匹配 | P0 |
