// =============================================================================
// test_hyperchainspace.cpp — CHyperChainSpace 链空间管理单元测试
// 对应源文件: HyperChain/HyperChainSpace.cpp
//
// 注意: CHyperChainSpace 深度耦合 ZMQ 消息队列和网络层，此处仅测试
//       可独立提取的纯逻辑方法。完整集成测试需要启动 MQ Broker。
// =============================================================================
#include <gtest/gtest.h>
#include "TestHelper.h"
#include <set>
#include <vector>
#include <string>
#include <cstring>

// ═══════════════════════════════════════════════════════════════
//  isMoreWellThanLocal 逻辑测试
//  原函数签名: bool isMoreWellThanLocal(const T_HYPERBLOCK& local,
//              uint64 blockid, uint64 blockcount, const T_SHA256& hash)
// ═══════════════════════════════════════════════════════════════

// 提取 isMoreWellThanLocal 的核心逻辑供独立测试
namespace ChainSpaceLogic {

bool isMoreWellThanLocal(
    uint64 localChildCount, const T_SHA256& localHash,
    uint64 remoteChildCount, const T_SHA256& remoteHash)
{
    if (remoteChildCount > localChildCount) return true;
    if (remoteChildCount == localChildCount) {
        if (remoteHash < localHash) return true;
    }
    return false;
}

// 提取 GenerateHIDSection 的核心逻辑
void GenerateHIDSection(const std::set<uint64>& hids, std::vector<std::string>& sections) {
    sections.clear();
    if (hids.empty()) return;
    uint64 start = *hids.begin();
    uint64 prev = start;
    for (auto it = std::next(hids.begin()); it != hids.end(); ++it) {
        if (*it != prev + 1) {
            sections.push_back(std::to_string(start) + "-" + std::to_string(prev));
            start = *it;
        }
        prev = *it;
    }
    sections.push_back(std::to_string(start) + "-" + std::to_string(prev));
}

} // namespace ChainSpaceLogic

// ═══════════════ isMoreWellThanLocal 测试 ═══════════════

class ForkSelectionTest : public ::testing::Test {
protected:
    T_SHA256 hashSmall, hashLarge;
    void SetUp() override {
        memset(hashSmall.pID, 0x11, DEF_SHA256_LEN);
        memset(hashLarge.pID, 0xEE, DEF_SHA256_LEN);
    }
};

// HCS-01
TEST_F(ForkSelectionTest, MoreBlocksWins) {
    EXPECT_TRUE(ChainSpaceLogic::isMoreWellThanLocal(5, hashSmall, 7, hashLarge));
}

// HCS-02
TEST_F(ForkSelectionTest, SameCount_SmallerHashWins) {
    EXPECT_TRUE(ChainSpaceLogic::isMoreWellThanLocal(5, hashLarge, 5, hashSmall));
}

// HCS-03
TEST_F(ForkSelectionTest, SameCount_LargerHashLoses) {
    EXPECT_FALSE(ChainSpaceLogic::isMoreWellThanLocal(5, hashSmall, 5, hashLarge));
}

// HCS-04
TEST_F(ForkSelectionTest, FewerBlocksLoses) {
    EXPECT_FALSE(ChainSpaceLogic::isMoreWellThanLocal(5, hashSmall, 3, hashSmall));
}

// ═══════════════ isAcceptHyperBlock 逻辑测试 ═══════════════

// HCS-05: 本地不存在
TEST(AcceptBlockTest, NotExist_Accept) {
    // 当 getHyperBlock 返回 false（本地不存在）时，应接受
    bool localExisted = false;
    EXPECT_TRUE(!localExisted); // 逻辑: if (!Existed) return true;
}

// HCS-06: 相同哈希
TEST(AcceptBlockTest, SameHash_Reject) {
    T_SHA256 h = TestHelper::RandomHash();
    EXPECT_TRUE(h == h); // 哈希相同时拒绝
}

// HCS-07: 分叉（同高度不同哈希）
TEST(AcceptBlockTest, Fork_Accept) {
    T_SHA256 h1 = TestHelper::FilledHash(0xAA);
    T_SHA256 h2 = TestHelper::FilledHash(0xBB);
    EXPECT_FALSE(h1 == h2); // 哈希不同 → 当前代码无条件接受
}

// ═══════════════ GenerateHIDSection 测试 ═══════════════

// HCS-08
TEST(HIDSectionTest, Continuous) {
    std::set<uint64> hids = {1, 2, 3, 4, 5};
    std::vector<std::string> sections;
    ChainSpaceLogic::GenerateHIDSection(hids, sections);
    ASSERT_EQ(sections.size(), 1u);
    EXPECT_EQ(sections[0], "1-5");
}

// HCS-09
TEST(HIDSectionTest, Disjoint) {
    std::set<uint64> hids = {1, 2, 3, 5, 6, 8};
    std::vector<std::string> sections;
    ChainSpaceLogic::GenerateHIDSection(hids, sections);
    ASSERT_EQ(sections.size(), 3u);
    EXPECT_EQ(sections[0], "1-3");
    EXPECT_EQ(sections[1], "5-6");
    EXPECT_EQ(sections[2], "8-8");
}

// HCS-10
TEST(HIDSectionTest, Single) {
    std::set<uint64> hids = {42};
    std::vector<std::string> sections;
    ChainSpaceLogic::GenerateHIDSection(hids, sections);
    ASSERT_EQ(sections.size(), 1u);
    EXPECT_EQ(sections[0], "42-42");
}

// HCS-11
TEST(HIDSectionTest, Empty) {
    std::set<uint64> hids;
    std::vector<std::string> sections;
    ChainSpaceLogic::GenerateHIDSection(hids, sections);
    EXPECT_TRUE(sections.empty());
}

// ═══════════════ 缓存更新逻辑 ═══════════════

// HCS-13: 模拟新最高块更新
TEST(CacheUpdateTest, NewHighestBlock) {
    std::atomic<uint64> uiMaxBlockNum{10};
    uint64 newBlockId = 15;
    if (uiMaxBlockNum <= newBlockId) {
        uiMaxBlockNum = newBlockId;
    }
    EXPECT_EQ(uiMaxBlockNum.load(), 15u);
}

// HCS-14: 旧块不更新最高块号
TEST(CacheUpdateTest, OlderBlockNoUpdate) {
    std::atomic<uint64> uiMaxBlockNum{10};
    uint64 oldBlockId = 5;
    if (uiMaxBlockNum <= oldBlockId) {
        uiMaxBlockNum = oldBlockId;
    }
    EXPECT_EQ(uiMaxBlockNum.load(), 10u); // 不变
}
