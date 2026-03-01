// =============================================================================
// test_consensus_engine.cpp — 共识引擎单元测试
// 对应源文件: consensus/consensus_engine.cpp, consensus/buddyinfo.h
// =============================================================================
#include <gtest/gtest.h>
#include "TestHelper.h"
#include <ctime>
#include <atomic>
#include <list>
#include <string>

// ═══════════════════════════════════════════════════════════════
//  共识周期与阶段计算（提取核心逻辑，不依赖完整 ConsensusEngine）
// ═══════════════════════════════════════════════════════════════

namespace ConsensusLogic {

constexpr int NEXTBUDDYTIME = 30; // 秒

inline int64_t GetConsensusCircle(int64_t t) {
    return t / NEXTBUDDYTIME;
}

enum class PHASE { PREPARE = 0, LOCAL, GLOBAL, PERSIST };

inline PHASE GetPhase(int64_t t) {
    int pos = static_cast<int>(t % NEXTBUDDYTIME);
    int quarter = NEXTBUDDYTIME / 4; // 7
    if (pos < quarter)     return PHASE::PREPARE;
    if (pos < 2 * quarter) return PHASE::LOCAL;
    if (pos < 3 * quarter) return PHASE::GLOBAL;
    return PHASE::PERSIST;
}

} // namespace ConsensusLogic

// ═══════════════ 共识周期测试 ═══════════════

// CON-01: 共识周期 > 0
TEST(ConsensusCircleTest, PositiveValue) {
    int64_t now = time(nullptr);
    EXPECT_GT(ConsensusLogic::GetConsensusCircle(now), 0);
}

// CON-02: 同一 30 秒窗口内 circle 相同
TEST(ConsensusCircleTest, SameWindowSameCircle) {
    int64_t base = 1000000 * ConsensusLogic::NEXTBUDDYTIME; // 一个整数倍起始点
    int64_t t1 = base;
    int64_t t2 = base + ConsensusLogic::NEXTBUDDYTIME - 1;
    EXPECT_EQ(ConsensusLogic::GetConsensusCircle(t1),
              ConsensusLogic::GetConsensusCircle(t2));
}

// ═══════════════ 阶段映射测试 ═══════════════

class PhaseTest : public ::testing::TestWithParam<std::pair<int, ConsensusLogic::PHASE>> {};

// CON-03 ~ CON-06: 参数化阶段测试
TEST_P(PhaseTest, CorrectPhaseMapping) {
    auto [offset, expected] = GetParam();
    // 构造时间 = 某个 30 秒周期起始 + offset
    int64_t base = 1000000 * ConsensusLogic::NEXTBUDDYTIME;
    EXPECT_EQ(ConsensusLogic::GetPhase(base + offset), expected);
}

INSTANTIATE_TEST_SUITE_P(PhaseMappings, PhaseTest, ::testing::Values(
    std::make_pair(0,  ConsensusLogic::PHASE::PREPARE),   // CON-03: 0s
    std::make_pair(3,  ConsensusLogic::PHASE::PREPARE),   //         3s
    std::make_pair(6,  ConsensusLogic::PHASE::PREPARE),   //         6s
    std::make_pair(7,  ConsensusLogic::PHASE::LOCAL),     // CON-04: 7s
    std::make_pair(10, ConsensusLogic::PHASE::LOCAL),     //         10s
    std::make_pair(13, ConsensusLogic::PHASE::LOCAL),     //         13s
    std::make_pair(14, ConsensusLogic::PHASE::GLOBAL),    // CON-05: 14s
    std::make_pair(18, ConsensusLogic::PHASE::GLOBAL),    //         18s
    std::make_pair(20, ConsensusLogic::PHASE::GLOBAL),    //         20s
    std::make_pair(21, ConsensusLogic::PHASE::PERSIST),   // CON-06: 21s
    std::make_pair(25, ConsensusLogic::PHASE::PERSIST),   //         25s
    std::make_pair(29, ConsensusLogic::PHASE::PERSIST)    //         29s
));

// ═══════════════════════════════════════════════════════════════
//  _tp2pmanagerstatus::ClearStatus 模拟测试
//  由于原始结构依赖大量项目内类型，此处用等价结构验证清除逻辑
// ═══════════════════════════════════════════════════════════════

namespace {

// 模拟精简版 _tp2pmanagerstatus
struct MockP2PStatus {
    bool bStartGlobalFlag = false;
    bool bGlobalChainChangeFlag = false;
    std::atomic<bool> bHaveOnChainReq{false};
    std::list<int> listLocalBuddyChainInfo;

    enum BuddyState { IDLE = 0, SEND_ON_CHAIN_REQ };
    struct {
        uint64_t uiCurBuddyNo = 0;
        BuddyState eBuddyState = IDLE;
        uint16_t usBlockNum = 0;
        uint16_t usChainNum = 0;
    } tBuddyInfo;

    bool bHyperBlockCreated = false;

    void ClearStatus() {
        bStartGlobalFlag = false;
        bGlobalChainChangeFlag = false;
        bHaveOnChainReq = false;
        listLocalBuddyChainInfo.clear();
        tBuddyInfo.uiCurBuddyNo = 0;
        tBuddyInfo.eBuddyState = IDLE;
        tBuddyInfo.usBlockNum = 0;
        tBuddyInfo.usChainNum = 0;
        bHyperBlockCreated = false;
    }
};

} // anonymous namespace

class ClearStatusTest : public ::testing::Test {
protected:
    MockP2PStatus status;

    void SetUp() override {
        status.bStartGlobalFlag = true;
        status.bGlobalChainChangeFlag = true;
        status.bHaveOnChainReq = true;
        status.listLocalBuddyChainInfo = {1, 2, 3, 4, 5};
        status.tBuddyInfo.uiCurBuddyNo = 10;
        status.tBuddyInfo.eBuddyState = MockP2PStatus::SEND_ON_CHAIN_REQ;
        status.tBuddyInfo.usBlockNum = 5;
        status.tBuddyInfo.usChainNum = 3;
        status.bHyperBlockCreated = true;
    }
};

// CON-07: 标志位重置
TEST_F(ClearStatusTest, FlagsReset) {
    status.ClearStatus();
    EXPECT_FALSE(status.bStartGlobalFlag);
    EXPECT_FALSE(status.bGlobalChainChangeFlag);
    EXPECT_FALSE(status.bHaveOnChainReq.load());
    EXPECT_FALSE(status.bHyperBlockCreated);
}

// CON-08: 列表清空
TEST_F(ClearStatusTest, ListsCleared) {
    status.ClearStatus();
    EXPECT_TRUE(status.listLocalBuddyChainInfo.empty());
}

// CON-09: BuddyInfo 重置
TEST_F(ClearStatusTest, BuddyInfoReset) {
    status.ClearStatus();
    EXPECT_EQ(status.tBuddyInfo.eBuddyState, MockP2PStatus::IDLE);
    EXPECT_EQ(status.tBuddyInfo.usBlockNum, 0);
    EXPECT_EQ(status.tBuddyInfo.usChainNum, 0);
    EXPECT_EQ(status.tBuddyInfo.uiCurBuddyNo, 0u);
}

// CON-10: ONCHAINSTATUS 枚举可转 char
TEST(OnChainStatusTest, EnumValues) {
    enum class ONCHAINSTATUS : char {
        queueing, onchaining1, onchaining2, onchained,
        matured, failed, nonexistent, unknown, pending
    };
    EXPECT_EQ(static_cast<char>(ONCHAINSTATUS::queueing), 0);
    EXPECT_EQ(static_cast<char>(ONCHAINSTATUS::pending), 8);
}
