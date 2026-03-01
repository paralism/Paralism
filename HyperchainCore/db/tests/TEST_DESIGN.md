# db 模块测试设计方案

## 模块概述

`db/` 是 HyperchainCore 的持久化层，包含：
- `dbmgr.cpp/h` — SQLite 数据库管理器，超块/局部块的 CRUD、事务管理
- `RestApi.cpp/h` — RESTful API 服务，上链状态查询、批量注册
- `HyperchainDB.cpp/h` — 数据库辅助函数

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| dbmgr.h | `DBmgr`, `DBmgr::Transaction` |
| RestApi.h | `RestApi::getOnchainState`, `RestApi::MakeRegistration` |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_dbmgr.cpp | dbmgr.cpp | 数据库 CRUD、事务、并发 |
| test_restapi.cpp | RestApi.cpp | REST 状态查询逻辑 |

---

## test_dbmgr.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| DB-01 | OpenAndClose | open→isOpen→close | true→false | P0 |
| DB-02 | HyperBlockInsert | insertHyperblock | 返回 0 | P0 |
| DB-03 | HyperBlockRead | insert→get | 数据一致 | P0 |
| DB-04 | LocalBlockInsertRead | insert→get | payload 一致 | P0 |
| DB-05 | HyperBlockOverwrite | 同 ID 连续 insert | 后者覆盖 | P0 |
| DB-06 | DeleteHyperblock | delete | isBlockExisted==false | P0 |
| DB-07 | IsBlockExisted_True | 插入后查询 | true | P0 |
| DB-08 | IsBlockExisted_False | 未插入时查询 | false | P0 |
| DB-09 | TransactionCommit | set_trans_succ | 数据持久 | P0 |
| DB-10 | TransactionRollback | 不调用 set_trans_succ | 数据消失 | P0 |
| DB-11 | HashInfoRoundTrip | updateHashInfo→get | 一致 | P1 |
| DB-12 | BatchLocalBlocks | 插入5个→getLocalBlocks | size==5 | P1 |
| DB-13 | EmptyTableQuery | 空表查询 | 返回非零/空 | P1 |
| DB-14 | BulkInsertBenchmark | 1000个超块 | <30秒 | P2 |

## test_restapi.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| REST-01 | StatusMapComplete | 所有 ONCHAINSTATUS | 都有对应字符串 | P0 |
| REST-02 | NonexistentRequest | 未知 requestID | "nonexistent" | P0 |
| REST-03 | BatchStatusPending | 内存中有 batchID | "pending" | P1 |
