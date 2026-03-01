// =============================================================================
// test_mutex.cpp — MMutex 互斥锁单元测试
// 对应源文件: HttpUnit/mutex.h
// =============================================================================
#include <gtest/gtest.h>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>

// ═══════════════════════════════════════════════════════════════
//  直接引入 MMutex (header-only 实现)
// ═══════════════════════════════════════════════════════════════
#include "HttpUnit/mutex.h"

// ═══════════════ 基本操作 ═══════════════

// MUT-01: Lock → Unlock 不死锁
TEST(MMutexTest, BasicLockUnlock) {
    MMutex mtx;
    mtx.Lock();
    mtx.Unlock();
    SUCCEED();
}

// MUT-03: 构造→析构不崩溃
TEST(MMutexTest, DestructorSafe) {
    {
        MMutex mtx;
        mtx.Lock();
        mtx.Unlock();
    }
    SUCCEED();
}

// 额外: 多次 Lock/Unlock 循环
TEST(MMutexTest, RepeatedLockUnlock) {
    MMutex mtx;
    for (int i = 0; i < 1000; ++i) {
        mtx.Lock();
        mtx.Unlock();
    }
    SUCCEED();
}

// ═══════════════ 多线程互斥 ═══════════════

// MUT-02: 2 线程各 +5000 = 10000
TEST(MMutexConcurrencyTest, TwoThreadCounter) {
    MMutex mtx;
    int counter = 0;
    constexpr int ITERS = 5000;

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            mtx.Lock();
            ++counter;
            mtx.Unlock();
        }
    };

    std::thread t1(worker), t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter, 2 * ITERS);
}

// 额外: 4 线程
TEST(MMutexConcurrencyTest, FourThreadCounter) {
    MMutex mtx;
    int counter = 0;
    constexpr int ITERS = 2500;

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            mtx.Lock();
            ++counter;
            mtx.Unlock();
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) threads.emplace_back(worker);
    for (auto& t : threads) t.join();
    EXPECT_EQ(counter, 4 * ITERS);
}

// 额外: 无锁对照 (验证锁确实必要)
TEST(MMutexConcurrencyTest, WithoutLockRace) {
    // 此测试验证如果不加锁则计数器可能不正确
    // 仅作为对照参考，不做 EXPECT（竞争条件非确定性）
    std::atomic<int> raceCounter{0};
    int unsafeCounter = 0;
    constexpr int ITERS = 50000;

    auto unsafeWorker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            ++unsafeCounter; // 故意不加锁
            raceCounter.fetch_add(1);
        }
    };

    std::thread t1(unsafeWorker), t2(unsafeWorker);
    t1.join();
    t2.join();

    // atomic 版本一定正确
    EXPECT_EQ(raceCounter.load(), 2 * ITERS);
    // unsafeCounter 可能不等于 2*ITERS (竞争条件)
    // 不做 EXPECT，仅输出供参考
    std::cout << "[INFO] unsafe counter = " << unsafeCounter
              << " (expected " << 2 * ITERS << ")" << std::endl;
}

// ═══════════════ RAII 风格使用模式 ═══════════════

// 模拟 RAII 锁守卫 (MMutex 没有自带 RAII)
class MMutexGuard {
    MMutex& m_mtx;
public:
    explicit MMutexGuard(MMutex& mtx) : m_mtx(mtx) { m_mtx.Lock(); }
    ~MMutexGuard() { m_mtx.Unlock(); }
    MMutexGuard(const MMutexGuard&) = delete;
    MMutexGuard& operator=(const MMutexGuard&) = delete;
};

TEST(MMutexRAIITest, GuardPattern) {
    MMutex mtx;
    int counter = 0;
    constexpr int ITERS = 5000;

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            MMutexGuard guard(mtx);
            ++counter;
        }
    };

    std::thread t1(worker), t2(worker);
    t1.join();
    t2.join();
    EXPECT_EQ(counter, 2 * ITERS);
}

// RAII 异常安全性
TEST(MMutexRAIITest, ExceptionSafety) {
    MMutex mtx;
    try {
        MMutexGuard guard(mtx);
        throw std::runtime_error("test_exception");
    } catch (...) {
        // guard 析构应已解锁
    }
    // 再次获取锁不应死锁
    mtx.Lock();
    mtx.Unlock();
    SUCCEED();
}
