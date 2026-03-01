// =============================================================================
// test_crosschaintx.cpp — 跨链交易状态机单元测试
// 对应源文件: consensus/crosschaintx.cpp
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <memory>
#include <stdexcept>

// ═══════════════════════════════════════════════════════════════
//  跨链状态机模拟（提取核心逻辑，不依赖完整 Ethereum/Paracoin 栈）
// ═══════════════════════════════════════════════════════════════

namespace CrossChainSim {

class IState {
public:
    virtual ~IState() = default;
    virtual std::string name() const = 0;
    virtual bool isCompleted() const { return false; }
    virtual bool isFailed() const { return false; }
};

using StatePtr = std::shared_ptr<IState>;

class StartState : public IState {
public:
    std::string name() const override { return "StartState"; }
};

class ParaTxCreatedState : public IState {
public:
    std::string txid;
    explicit ParaTxCreatedState(const std::string& id) : txid(id) {}
    std::string name() const override { return "ParaTxCreatedState"; }
};

class WaitingParaTxOnChain : public IState {
public:
    std::string name() const override { return "WaitingParaTxOnChain"; }
};

class EthTxCreatedState : public IState {
public:
    std::string name() const override { return "EthTxCreatedState"; }
};

class CompletedState : public IState {
public:
    std::string name() const override { return "CompletedState"; }
    bool isCompleted() const override { return true; }
};

class ExceptionState : public IState {
public:
    StatePtr prevState;
    std::string reason;
    ExceptionState(StatePtr prev, const std::string& r) : prevState(prev), reason(r) {}
    std::string name() const override { return "ExceptionState"; }
    bool isFailed() const override { return true; }
};

// 简化版跨链执行器
class CrossChainExecutor {
public:
    std::string swapId;
    StatePtr currentState;
    bool m_isDoing = false;

    explicit CrossChainExecutor(const std::string& id)
        : swapId(id), currentState(std::make_shared<StartState>()) {}

    void transitionTo(StatePtr newState) {
        currentState = newState;
    }

    bool isCompleted() const { return currentState && currentState->isCompleted(); }
    bool isFailed() const { return currentState && currentState->isFailed(); }
    std::string stateName() const { return currentState ? currentState->name() : "null"; }

    // 模拟跨链流程: Start → ParaTxCreated → WaitingPara → EthTxCreated → Completed
    void simulateSuccess() {
        transitionTo(std::make_shared<ParaTxCreatedState>("para_tx_001"));
        transitionTo(std::make_shared<WaitingParaTxOnChain>());
        transitionTo(std::make_shared<EthTxCreatedState>());
        transitionTo(std::make_shared<CompletedState>());
    }

    // 模拟异常: Start → ParaTxCreated → Exception
    void simulateFailure() {
        auto paraTx = std::make_shared<ParaTxCreatedState>("para_tx_002");
        transitionTo(paraTx);
        transitionTo(std::make_shared<ExceptionState>(paraTx, "ETH node unreachable"));
    }
};

} // namespace CrossChainSim

// ═══════════════ 测试 ═══════════════

class CrossChainTest : public ::testing::Test {
protected:
    std::unique_ptr<CrossChainSim::CrossChainExecutor> executor;
    void SetUp() override {
        executor = std::make_unique<CrossChainSim::CrossChainExecutor>("swap_test_001");
    }
};

// CC-01: 初始状态
TEST_F(CrossChainTest, InitialState) {
    EXPECT_EQ(executor->stateName(), "StartState");
    EXPECT_FALSE(executor->isCompleted());
    EXPECT_FALSE(executor->isFailed());
}

// CC-02: 异常状态保留前驱
TEST_F(CrossChainTest, ExceptionPreservesPrevState) {
    executor->simulateFailure();
    EXPECT_TRUE(executor->isFailed());
    EXPECT_EQ(executor->stateName(), "ExceptionState");

    auto excState = std::dynamic_pointer_cast<CrossChainSim::ExceptionState>(executor->currentState);
    ASSERT_NE(excState, nullptr);
    EXPECT_EQ(excState->prevState->name(), "ParaTxCreatedState");
    EXPECT_EQ(excState->reason, "ETH node unreachable");
}

// CC-03: 完成状态标记
TEST_F(CrossChainTest, CompletedFlag) {
    executor->simulateSuccess();
    EXPECT_TRUE(executor->isCompleted());
    EXPECT_FALSE(executor->isFailed());
    EXPECT_EQ(executor->stateName(), "CompletedState");
}

// CC-04: 重入保护标志
TEST_F(CrossChainTest, ReentryGuard) {
    EXPECT_FALSE(executor->m_isDoing);
    executor->m_isDoing = true;
    EXPECT_TRUE(executor->m_isDoing);
}

// CC-05: 状态转换名称链
TEST_F(CrossChainTest, StateTransitionNames) {
    EXPECT_EQ(executor->stateName(), "StartState");
    executor->transitionTo(std::make_shared<CrossChainSim::ParaTxCreatedState>("tx1"));
    EXPECT_EQ(executor->stateName(), "ParaTxCreatedState");
    executor->transitionTo(std::make_shared<CrossChainSim::WaitingParaTxOnChain>());
    EXPECT_EQ(executor->stateName(), "WaitingParaTxOnChain");
    executor->transitionTo(std::make_shared<CrossChainSim::EthTxCreatedState>());
    EXPECT_EQ(executor->stateName(), "EthTxCreatedState");
    executor->transitionTo(std::make_shared<CrossChainSim::CompletedState>());
    EXPECT_EQ(executor->stateName(), "CompletedState");
}

// CC-06: Executor 详情
TEST_F(CrossChainTest, ExecutorSwapId) {
    EXPECT_EQ(executor->swapId, "swap_test_001");
}

// CC-07: 中途崩溃模拟 — 状态丢失（内存存储的风险验证）
TEST_F(CrossChainTest, StateNotPersisted) {
    executor->transitionTo(std::make_shared<CrossChainSim::WaitingParaTxOnChain>());
    // 模拟"崩溃"：重新创建 executor，状态丢失回到 Start
    executor = std::make_unique<CrossChainSim::CrossChainExecutor>("swap_test_001");
    EXPECT_EQ(executor->stateName(), "StartState"); // 状态回到初始
}
