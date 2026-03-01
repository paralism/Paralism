// =============================================================================
// test_commonstruct.cpp — T_LOCALBLOCK / T_HYPERBLOCK 单元测试
// 对应源文件: headers/commonstruct.h
// =============================================================================
#include <gtest/gtest.h>
#include "TestHelper.h"
#include <sstream>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

// ═══════════════════════════════════════════════════════════════
//  T_LOCALBLOCK 测试
// ═══════════════════════════════════════════════════════════════

class LocalBlockTest : public ::testing::Test {
protected:
    T_LOCALBLOCK block;
    void SetUp() override {
        block = TestHelper::MakeLocalBlock(1, "hello_hyperchain");
    }
};

// BLK-01: 字段访问
TEST_F(LocalBlockTest, FieldAccess) {
    EXPECT_EQ(block.GetID(), 1);
    EXPECT_EQ(block.GetPayLoad(), "hello_hyperchain");
    EXPECT_GT(block.GetCTime(), 0u);
    EXPECT_EQ(block.GetNonce(), 42u);
}

// BLK-02: body hash 非零
TEST_F(LocalBlockTest, BuildBodyHashNonZero) {
    EXPECT_FALSE(block.header.tMTRootorBlockBodyHash.isNull());
}

// BLK-03: 相同 payload → 相同 hash
TEST_F(LocalBlockTest, SamePayloadSameHash) {
    auto b1 = TestHelper::MakeLocalBlock(1, "same");
    auto b2 = TestHelper::MakeLocalBlock(1, "same");
    EXPECT_TRUE(b1.header.tMTRootorBlockBodyHash == b2.header.tMTRootorBlockBodyHash);
}

// BLK-04: 不同 payload → 不同 hash
TEST_F(LocalBlockTest, DiffPayloadDiffHash) {
    auto b1 = TestHelper::MakeLocalBlock(1, "data_a");
    auto b2 = TestHelper::MakeLocalBlock(1, "data_b");
    EXPECT_FALSE(b1.header.tMTRootorBlockBodyHash == b2.header.tMTRootorBlockBodyHash);
}

// BLK-05: 哈希计算可重复
TEST_F(LocalBlockTest, CalcHashSelfRepeatable) {
    block.CalculateHashSelf();
    T_SHA256 h1 = block.GetHashSelf();
    block.CalculateHashSelf();
    T_SHA256 h2 = block.GetHashSelf();
    EXPECT_TRUE(h1 == h2);
    EXPECT_FALSE(h1.isNull());
}

// BLK-06: 序列化往返
TEST_F(LocalBlockTest, SerRoundTrip) {
    std::stringstream ss;
    {
        boost::archive::binary_oarchive oa(ss, boost::archive::archive_flags::no_header);
        oa << block;
    }
    T_LOCALBLOCK restored;
    {
        boost::archive::binary_iarchive ia(ss, boost::archive::archive_flags::no_header);
        ia >> restored;
    }
    EXPECT_EQ(restored.GetID(), block.GetID());
    EXPECT_EQ(restored.GetPayLoad(), block.GetPayLoad());
    EXPECT_TRUE(restored.header.tMTRootorBlockBodyHash == block.header.tMTRootorBlockBodyHash);
}

// BLK-14: 大 payload 序列化
TEST_F(LocalBlockTest, LargePayload) {
    std::string big(1024 * 1024, 'X');
    auto bigBlock = TestHelper::MakeLocalBlock(99, big);
    std::stringstream ss;
    {
        boost::archive::binary_oarchive oa(ss, boost::archive::archive_flags::no_header);
        oa << bigBlock;
    }
    T_LOCALBLOCK restored;
    {
        boost::archive::binary_iarchive ia(ss, boost::archive::archive_flags::no_header);
        ia >> restored;
    }
    EXPECT_EQ(restored.GetPayLoad().size(), 1024u * 1024u);
    EXPECT_EQ(restored.GetPayLoad(), big);
}

// BLK-15: Move 语义
TEST_F(LocalBlockTest, MoveSemantics) {
    std::string original = block.GetPayLoad();
    T_LOCALBLOCK moved(std::move(block));
    EXPECT_EQ(moved.GetPayLoad(), original);
    EXPECT_TRUE(block.GetPayLoad().empty());
}

// ═══════════════════════════════════════════════════════════════
//  T_HYPERBLOCK 测试
// ═══════════════════════════════════════════════════════════════

class HyperBlockTest : public ::testing::Test {
protected:
    T_HYPERBLOCK hblock;
    void SetUp() override {
        hblock = TestHelper::MakeHyperBlock(10, TestHelper::RandomHash(), 3);
    }
};

// BLK-07: 子块计数
TEST_F(HyperBlockTest, ChildBlockCount) {
    EXPECT_EQ(hblock.GetChildBlockCount(), 3u);
}

// BLK-08: Rebuild 填充
TEST_F(HyperBlockTest, RebuildFillsFields) {
    EXPECT_EQ(hblock.GetChildChainsCount(), 1u);
    EXPECT_EQ(hblock.header.vecChildChainBlockCount.size(), 1u);
    EXPECT_EQ(hblock.header.vecChildChainBlockCount[0], 3);
}

// BLK-09: 超块哈希可重复
TEST_F(HyperBlockTest, HashSelfRepeatable) {
    hblock.calculateHashSelf();
    T_SHA256 h1 = hblock.GetHashSelf();
    hblock.calculateHashSelf();
    T_SHA256 h2 = hblock.GetHashSelf();
    EXPECT_TRUE(h1 == h2);
    EXPECT_FALSE(h1.isNull());
}

// BLK-10: header hash ≠ full hash
TEST_F(HyperBlockTest, HeaderHashDiffersFullHash) {
    hblock.calculateHashSelf();
    T_SHA256 fullHash = hblock.GetHashSelf();
    T_SHA256 headerHash = hblock.calculateHeaderHashSelf();
    EXPECT_FALSE(fullHash == headerHash);
}

// BLK-11: 修改后哈希变化
TEST_F(HyperBlockTest, ModificationChangesHash) {
    hblock.calculateHashSelf();
    T_SHA256 before = hblock.GetHashSelf();
    hblock.header.uiWeight += 1;
    hblock.calculateHashSelf();
    T_SHA256 after = hblock.GetHashSelf();
    EXPECT_FALSE(before == after);
}

// BLK-12: 多条子链
TEST_F(HyperBlockTest, MultipleChildChains) {
    T_HYPERBLOCK multi;
    multi.header.uiID = 20;
    multi.header.uiTime = static_cast<uint64>(time(nullptr));

    std::list<T_LOCALBLOCK> c1, c2, c3;
    c1.push_back(TestHelper::MakeLocalBlock(0, "c1_0"));
    c1.push_back(TestHelper::MakeLocalBlock(1, "c1_1"));
    c2.push_back(TestHelper::MakeLocalBlock(0, "c2_0"));
    c3.push_back(TestHelper::MakeLocalBlock(0, "c3_0"));
    c3.push_back(TestHelper::MakeLocalBlock(1, "c3_1"));
    c3.push_back(TestHelper::MakeLocalBlock(2, "c3_2"));

    multi.AddChildChain(std::move(c1));
    multi.AddChildChain(std::move(c2));
    multi.AddChildChain(std::move(c3));
    multi.Rebuild();

    EXPECT_EQ(multi.GetChildChainsCount(), 3u);
    EXPECT_EQ(multi.GetChildBlockCount(), 6u);
}

// BLK-13: 空超块
TEST_F(HyperBlockTest, EmptyHyperBlock) {
    T_HYPERBLOCK empty;
    EXPECT_EQ(empty.GetChildBlockCount(), 0u);
    EXPECT_EQ(empty.GetChildChainsCount(), 0u);
}

// BLK-17: 链连续性
TEST_F(HyperBlockTest, ChainLinkage) {
    auto chain = TestHelper::MakeChain(10, 2);
    EXPECT_TRUE(chain[0].GetPreHash() == TestHelper::ZeroHash());
    for (int i = 1; i < 10; ++i) {
        EXPECT_TRUE(chain[i].GetPreHash() == chain[i - 1].GetHashSelf())
            << "Block " << i << " preHash mismatch";
    }
}
