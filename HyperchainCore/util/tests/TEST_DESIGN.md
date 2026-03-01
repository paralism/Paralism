# util 模块测试设计方案

## 模块概述

`util/` 是 HyperchainCore 的工具层，包含：
- `MutexObj.h` — 互斥锁封装（`CMutexObj`、`CAutoMutexLock`）与信号量
- `common.h` — 通用辅助函数（StringFormat、time2string 等）
- `hex.hpp` — 十六进制编解码

## 被测文件

| 文件 | 关键类/函数 |
|------|-----------|
| MutexObj.h | `CMutexObj`, `CAutoMutexLock`, `semaphore_t` |
| common.h | `StringFormat`, `time2string` |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_mutexobj.cpp | MutexObj.h | 锁、RAII、并发互斥、信号量 |
| test_common.cpp | common.h | 字符串格式化、时间转换 |

---

## test_mutexobj.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| MTX-01 | BasicLockUnlock | Lock→UnLock | 不死锁 | P0 |
| MTX-02 | RecursiveLock | Lock×2→UnLock×2 | 不死锁 | P0 |
| MTX-03 | AutoLockRAII | 作用域内外 | 出域自动解锁 | P0 |
| MTX-04 | AutoLockManualUnlock | unlock() | 其他线程可获取 | P1 |
| MTX-05 | MultiThreadCounter | 2线程各+10000 | 总计==20000 | P0 |
| MTX-06 | SemaphoreSignalWait | signal→wait | 唤醒 | P0 |
| MTX-07 | SemaphoreTryWaitNoSignal | trywait | 返回非零 | P1 |
| MTX-08 | SemaphoreMultiSignal | 3次signal→3次wait | 全部唤醒 | P1 |

## test_common.cpp 测试矩阵

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| CMN-01 | StringFormatBasic | "hello %d", 42 | "hello 42" | P0 |
| CMN-02 | StringFormatMulti | "%s=%d", "x", 1 | "x=1" | P0 |
| CMN-03 | StringFormatEmpty | "" | "" | P1 |
| CMN-04 | Time2StringNonEmpty | time(nullptr) | 非空字符串 | P0 |
| CMN-05 | Time2StringLength | time(nullptr) | >=10 字符 | P1 |
