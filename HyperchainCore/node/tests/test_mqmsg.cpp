// =============================================================================
// test_mqmsg.cpp — MQMsgPush / MQMsgPop 消息序列化单元测试
// 对应源文件: node/MsgHandler.h, node/zmsg.h
//
// 注意: zmsg 依赖 ZMQ socket，此处用模拟帧队列测试序列化逻辑
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>

// ═══════════════════════════════════════════════════════════════
//  模拟 zmsg 帧队列（提取 MQMsgPush/Pop 的核心序列化逻辑）
//  实际 zmsg 使用 std::deque<string>，此处等价模拟
// ═══════════════════════════════════════════════════════════════

namespace MQSim {

class MockMsg {
public:
    std::vector<std::string> frames;

    void push_back(const std::string& frame) { frames.push_back(frame); }
    void push_back(std::string&& frame) { frames.push_back(std::move(frame)); }

    std::string pop_front() {
        if (frames.empty()) return "";
        std::string f = std::move(frames.front());
        frames.erase(frames.begin());
        return f;
    }

    bool empty() const { return frames.empty(); }
    size_t size() const { return frames.size(); }
};

// ─── MQMsgPush: 将 POD 类型序列化为帧 ───

template<typename T>
void MQMsgPush(MockMsg* msg, const T& val) {
    std::string frame(reinterpret_cast<const char*>(&val), sizeof(T));
    msg->push_back(std::move(frame));
}

// 字符串特化
inline void MQMsgPush(MockMsg* msg, const std::string& val) {
    msg->push_back(val);
}

// 多参数递归
template<typename T, typename... Args>
void MQMsgPush(MockMsg* msg, const T& first, const Args&... rest) {
    MQMsgPush(msg, first);
    MQMsgPush(msg, rest...);
}

// ─── MQMsgPop: 从帧反序列化为 POD ───

template<typename T>
void MQMsgPop(MockMsg* msg, T& val) {
    std::string frame = msg->pop_front();
    if (frame.size() == sizeof(T)) {
        memcpy(&val, frame.c_str(), sizeof(T));
    } else {
        // 类型大小不匹配！当前代码中的 bug
        memset(&val, 0, sizeof(T));
    }
}

// 字符串特化
inline void MQMsgPop(MockMsg* msg, std::string& val) {
    val = msg->pop_front();
}

// 多参数递归
template<typename T, typename... Args>
void MQMsgPop(MockMsg* msg, T& first, Args&... rest) {
    MQMsgPop(msg, first);
    MQMsgPop(msg, rest...);
}

// ─── 安全版 Pop（带大小检查）───

template<typename T>
bool MQMsgPopSafe(MockMsg* msg, T& val) {
    std::string frame = msg->pop_front();
    if (frame.size() != sizeof(T)) return false;
    memcpy(&val, frame.c_str(), sizeof(T));
    return true;
}

} // namespace MQSim

// ═══════════════ 测试 ═══════════════

class MQMsgTest : public ::testing::Test {
protected:
    MQSim::MockMsg msg;
};

// MQ-01: uint64 往返
TEST_F(MQMsgTest, Uint64RoundTrip) {
    uint64_t original = 0xDEADBEEF12345678ULL;
    MQSim::MQMsgPush(&msg, original);

    uint64_t restored = 0;
    MQSim::MQMsgPop(&msg, restored);
    EXPECT_EQ(restored, original);
}

// MQ-02: 多参数往返
TEST_F(MQMsgTest, MultiParamRoundTrip) {
    uint64_t v1 = 42;
    bool v2 = true;
    uint32_t v3 = 100;
    MQSim::MQMsgPush(&msg, v1, v2, v3);

    uint64_t r1 = 0; bool r2 = false; uint32_t r3 = 0;
    MQSim::MQMsgPop(&msg, r1, r2, r3);

    EXPECT_EQ(r1, 42u);
    EXPECT_EQ(r2, true);
    EXPECT_EQ(r3, 100u);
}

// MQ-03: 字符串往返
TEST_F(MQMsgTest, StringRoundTrip) {
    std::string original = "hello_hyperchain_message";
    MQSim::MQMsgPush(&msg, original);

    std::string restored;
    MQSim::MQMsgPop(&msg, restored);
    EXPECT_EQ(restored, original);
}

// MQ-04: 空字符串
TEST_F(MQMsgTest, EmptyString) {
    std::string original = "";
    MQSim::MQMsgPush(&msg, original);
    std::string restored = "non-empty";
    MQSim::MQMsgPop(&msg, restored);
    EXPECT_EQ(restored, "");
}

// MQ-05: 大字符串
TEST_F(MQMsgTest, LargeString) {
    std::string big(1024 * 1024, 'Z'); // 1MB
    MQSim::MQMsgPush(&msg, big);
    std::string restored;
    MQSim::MQMsgPop(&msg, restored);
    EXPECT_EQ(restored.size(), 1024u * 1024u);
    EXPECT_EQ(restored, big);
}

// MQ-06: 类型大小不匹配检测（核心安全问题）
TEST_F(MQMsgTest, TypeSizeMismatch) {
    uint32_t small = 0xABCD;
    MQSim::MQMsgPush(&msg, small);          // push 4 字节

    EXPECT_EQ(msg.frames[0].size(), sizeof(uint32_t));
    EXPECT_NE(msg.frames[0].size(), sizeof(uint64_t));

    uint64_t big = 0;
    bool ok = MQSim::MQMsgPopSafe(&msg, big); // 尝试 pop 8 字节
    EXPECT_FALSE(ok) << "Should fail: pushed 4 bytes but trying to pop 8";
}

// MQ-07: 帧顺序 — FIFO
TEST_F(MQMsgTest, FrameOrderFIFO) {
    uint32_t a = 1, b = 2, c = 3;
    MQSim::MQMsgPush(&msg, a);
    MQSim::MQMsgPush(&msg, b);
    MQSim::MQMsgPush(&msg, c);

    uint32_t r;
    MQSim::MQMsgPop(&msg, r); EXPECT_EQ(r, 1u);
    MQSim::MQMsgPop(&msg, r); EXPECT_EQ(r, 2u);
    MQSim::MQMsgPop(&msg, r); EXPECT_EQ(r, 3u);
    EXPECT_TRUE(msg.empty());
}

// MQ-08: bool 往返（1 字节类型）
TEST_F(MQMsgTest, BoolRoundTrip) {
    MQSim::MQMsgPush(&msg, true);
    MQSim::MQMsgPush(&msg, false);

    bool r1, r2;
    MQSim::MQMsgPop(&msg, r1);
    MQSim::MQMsgPop(&msg, r2);
    EXPECT_TRUE(r1);
    EXPECT_FALSE(r2);
}
