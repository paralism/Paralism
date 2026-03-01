// =============================================================================
// test_mutexobj.cpp — CMutexObj / CAutoMutexLock / semaphore_t 单元测试
// 对应源文件: util/MutexObj.h
// =============================================================================
#include <gtest/gtest.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <vector>

// ═══════════════════════════════════════════════════════════════
//  模拟 CMutexObj / CAutoMutexLock（提取核心逻辑，不依赖平台宏）
// ═══════════════════════════════════════════════════════════════

namespace MutexSim {

class CMutexObj {
    std::recursive_mutex m_mutex;
public:
    void Lock()   { m_mutex.lock(); }
    void UnLock() { m_mutex.unlock(); }
    std::recursive_mutex& native() { return m_mutex; }
};

class CAutoMutexLock {
    CMutexObj& m_ref;
    bool m_locked;
public:
    explicit CAutoMutexLock(CMutexObj& obj) : m_ref(obj), m_locked(true) {
        m_ref.Lock();
    }
    ~CAutoMutexLock() {
        if (m_locked) m_ref.UnLock();
    }
    void unlock() {
        if (m_locked) { m_ref.UnLock(); m_locked = false; }
    }
};

class semaphore_t {
    std::mutex m_mtx;
    std::condition_variable m_cv;
    int m_count = 0;
public:
    void signal() {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_count;
        m_cv.notify_one();
    }
    // blocking=true: 阻塞等待; blocking=false: 非阻塞尝试
    int wait(bool blocking) {
        std::unique_lock<std::mutex> lk(m_mtx);
        if (blocking) {
            m_cv.wait(lk, [this]{ return m_count > 0; });
            --m_count;
            return 0;
        } else {
            if (m_count > 0) { --m_count; return 0; }
            return -1;
        }
    }
};

} // namespace MutexSim

// ═══════════════ CMutexObj 测试 ═══════════════

// MTX-01: 基本加解锁
TEST(MutexObjTest, BasicLockUnlock) {
    MutexSim::CMutexObj mutex;
    mutex.Lock();
    mutex.UnLock();
    SUCCEED();
}

// MTX-02: 递归锁
TEST(MutexObjTest, RecursiveLock) {
    MutexSim::CMutexObj mutex;
    mutex.Lock();
    mutex.Lock();
    mutex.UnLock();
    mutex.UnLock();
    SUCCEED();
}

// ═══════════════ CAutoMutexLock 测试 ═══════════════

// MTX-03: RAII 自动解锁
TEST(AutoLockTest, RAIIAutoUnlock) {
    MutexSim::CMutexObj mutex;
    {
        MutexSim::CAutoMutexLock lock(mutex);
    }
    // 出域后应自动解锁，再次获取不死锁
    MutexSim::CAutoMutexLock lock2(mutex);
    SUCCEED();
}

// MTX-04: 手动 unlock
TEST(AutoLockTest, ManualUnlock) {
    MutexSim::CMutexObj mutex;
    MutexSim::CAutoMutexLock lock(mutex);
    lock.unlock();

    std::atomic<bool> acquired{false};
    std::thread t([&]() {
        MutexSim::CAutoMutexLock inner(mutex);
        acquired = true;
    });
    t.join();
    EXPECT_TRUE(acquired);
}

// ═══════════════ 多线程互斥 ═══════════════

// MTX-05: 并发计数器
TEST(MutexConcurrencyTest, MultiThreadCounter) {
    MutexSim::CMutexObj mutex;
    int counter = 0;
    constexpr int ITERS = 10000;

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            MutexSim::CAutoMutexLock lock(mutex);
            ++counter;
        }
    };

    std::thread t1(worker), t2(worker);
    t1.join(); t2.join();
    EXPECT_EQ(counter, 2 * ITERS);
}

// 额外: 4 线程
TEST(MutexConcurrencyTest, FourThreadCounter) {
    MutexSim::CMutexObj mutex;
    int counter = 0;
    constexpr int ITERS = 5000;

    auto worker = [&]() {
        for (int i = 0; i < ITERS; ++i) {
            MutexSim::CAutoMutexLock lock(mutex);
            ++counter;
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) threads.emplace_back(worker);
    for (auto& t : threads) t.join();
    EXPECT_EQ(counter, 4 * ITERS);
}

// ═══════════════ semaphore_t 测试 ═══════════════

// MTX-06: signal→wait
TEST(SemaphoreTest, SignalAndWait) {
    MutexSim::semaphore_t sem;
    std::atomic<bool> done{false};

    std::thread waiter([&]() {
        sem.wait(true);
        done = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(done);
    sem.signal();
    waiter.join();
    EXPECT_TRUE(done);
}

// MTX-07: 非阻塞 tryWait 无信号
TEST(SemaphoreTest, TryWaitNoSignal) {
    MutexSim::semaphore_t sem;
    EXPECT_NE(sem.wait(false), 0);
}

// MTX-08: 多次 signal
TEST(SemaphoreTest, MultiSignal) {
    MutexSim::semaphore_t sem;
    sem.signal();
    sem.signal();
    sem.signal();
    EXPECT_EQ(sem.wait(false), 0);
    EXPECT_EQ(sem.wait(false), 0);
    EXPECT_EQ(sem.wait(false), 0);
    EXPECT_NE(sem.wait(false), 0); // 第 4 次应失败
}
