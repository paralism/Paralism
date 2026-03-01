// =============================================================================
// test_dbmgr.cpp — DBmgr 数据库管理器单元测试
// 对应源文件: db/dbmgr.cpp
// =============================================================================
#include <gtest/gtest.h>
#include "db/dbmgr.h"
#include "TestHelper.h"
#include <filesystem>
#include <chrono>
#include <thread>

class DBmgrTest : public ::testing::Test {
protected:
    DBmgr db;
    std::string dbpath;

    void SetUp() override {
        dbpath = TestHelper::TempDBPath();
        ASSERT_EQ(db.open(dbpath.c_str()), 0) << "Failed to open: " << dbpath;
    }
    void TearDown() override {
        if (db.isOpen()) db.close();
        std::filesystem::remove(dbpath);
    }
};

// ═══════════════ 基础连接 ═══════════════

// DB-01
TEST_F(DBmgrTest, OpenAndClose) {
    EXPECT_TRUE(db.isOpen());
    db.close();
    EXPECT_FALSE(db.isOpen());
}

// ═══════════════ 超块 CRUD ═══════════════

// DB-02
TEST_F(DBmgrTest, HyperBlockInsert) {
    auto hb = TestHelper::MakeHyperBlock(1, TestHelper::ZeroHash(), 3);
    hb.calculateHashSelf();
    EXPECT_EQ(db.insertHyperblock(hb), 0);
}

// DB-03
TEST_F(DBmgrTest, HyperBlockInsertAndRead) {
    auto original = TestHelper::MakeHyperBlock(1, TestHelper::ZeroHash(), 3);
    original.calculateHashSelf();
    ASSERT_EQ(db.insertHyperblock(original), 0);

    EXPECT_TRUE(db.isBlockExisted(1));
}

// DB-04: 局部块
TEST_F(DBmgrTest, LocalBlockInsertAndRead) {
    auto lb = TestHelper::MakeLocalBlock(1, "db_test_payload");
    lb.CalculateHashSelf();
    ASSERT_EQ(db.insertLocalblock(lb, 10, 1), 0);

    T_LOCALBLOCK loaded;
    int ret = db.getLocalblock(loaded, 10, 1, 1);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(loaded.GetPayLoad(), "db_test_payload");
}

// DB-05: 覆盖写入
TEST_F(DBmgrTest, HyperBlockOverwrite) {
    auto v1 = TestHelper::MakeHyperBlock(5, TestHelper::ZeroHash(), 2);
    v1.calculateHashSelf();
    auto v2 = TestHelper::MakeHyperBlock(5, TestHelper::ZeroHash(), 7);
    v2.calculateHashSelf();

    ASSERT_EQ(db.insertHyperblock(v1), 0);
    ASSERT_EQ(db.insertHyperblock(v2), 0);
    EXPECT_TRUE(db.isBlockExisted(5));
}

// DB-06: 删除
TEST_F(DBmgrTest, DeleteHyperblock) {
    auto hb = TestHelper::MakeHyperBlock(7);
    hb.calculateHashSelf();
    db.insertHyperblock(hb);
    db.insertLocalblock(TestHelper::MakeLocalBlock(0, "del"), 7, 1);

    EXPECT_TRUE(db.isBlockExisted(7));
    db.deleteHyperblockAndLocalblock(7);
    EXPECT_FALSE(db.isBlockExisted(7));
}

// ═══════════════ isBlockExisted ═══════════════

// DB-07
TEST_F(DBmgrTest, IsBlockExisted_True) {
    auto hb = TestHelper::MakeHyperBlock(100);
    hb.calculateHashSelf();
    db.insertHyperblock(hb);
    EXPECT_TRUE(db.isBlockExisted(100));
}

// DB-08
TEST_F(DBmgrTest, IsBlockExisted_False) {
    EXPECT_FALSE(db.isBlockExisted(99999));
}

// ═══════════════ 事务 ═══════════════

// DB-09: 事务提交
TEST_F(DBmgrTest, TransactionCommit) {
    {
        auto txn = db.beginTran();
        auto hb = TestHelper::MakeHyperBlock(43);
        hb.calculateHashSelf();
        db.insertHyperblock(hb);
        txn.set_trans_succ();
    }
    EXPECT_TRUE(db.isBlockExisted(43));
}

// DB-10: 事务回滚
TEST_F(DBmgrTest, TransactionRollback) {
    {
        auto txn = db.beginTran();
        auto hb = TestHelper::MakeHyperBlock(42);
        hb.calculateHashSelf();
        db.insertHyperblock(hb);
        // 不调用 set_trans_succ → 析构时 rollback
    }
    EXPECT_FALSE(db.isBlockExisted(42));
}

// ═══════════════ 批量操作 ═══════════════

// DB-12
TEST_F(DBmgrTest, BatchLocalBlocks) {
    auto hb = TestHelper::MakeHyperBlock(20, TestHelper::ZeroHash(), 5);
    hb.calculateHashSelf();
    db.insertHyperblock(hb);

    auto& chains = hb.GetChildChains();
    uint16 chainnum = 1;
    for (auto& chain : chains) {
        for (auto& lb : chain) {
            db.insertLocalblock(lb, 20, chainnum);
        }
        chainnum++;
    }

    std::list<T_LOCALBLOCK> loaded;
    db.getLocalBlocks(loaded, 20);
    EXPECT_EQ(loaded.size(), 5u);
}

// DB-13: 空表查询
TEST_F(DBmgrTest, EmptyTableQuery) {
    EXPECT_FALSE(db.isBlockExisted(88888));
}

// DB-14: 性能基准
TEST_F(DBmgrTest, BulkInsertBenchmark) {
    auto chain = TestHelper::MakeChain(500, 2);
    auto start = std::chrono::steady_clock::now();
    {
        auto txn = db.beginTran();
        for (auto& hb : chain) {
            db.insertHyperblock(hb);
        }
        txn.set_trans_succ();
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << "[BENCHMARK] 500 hyperblocks insert: " << ms << " ms" << std::endl;
    EXPECT_LT(ms, 30000);
}
