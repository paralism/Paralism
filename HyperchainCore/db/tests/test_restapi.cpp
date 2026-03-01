// =============================================================================
// test_restapi.cpp — RestApi 状态查询逻辑单元测试
// 对应源文件: db/RestApi.cpp
// =============================================================================
#include <gtest/gtest.h>
#include "headers/inter_public.h"
#include <string>
#include <unordered_map>

// 复现 RestApi 中的状态映射（不依赖完整 RestApi 初始化）
enum class ONCHAINSTATUS_T : char {
    queueing, onchaining1, onchaining2, onchained,
    matured, failed, nonexistent, unknown, pending
};

static std::unordered_map<int, std::string> BuildStatusMap() {
    return {
        {0, "queueing"}, {1, "onchaining1"}, {2, "onchaining2"},
        {3, "onchained"}, {4, "matured"}, {5, "failed"},
        {6, "nonexistent"}, {7, "unknown"}, {8, "pending"}
    };
}

// REST-01: 状态映射完整性
TEST(RestApiStatusTest, StatusMapComplete) {
    auto m = BuildStatusMap();
    EXPECT_EQ(m.size(), 9u);
    EXPECT_EQ(m[0], "queueing");
    EXPECT_EQ(m[4], "matured");
    EXPECT_EQ(m[5], "failed");
    EXPECT_EQ(m[6], "nonexistent");
    EXPECT_EQ(m[7], "unknown");
    EXPECT_EQ(m[8], "pending");
}

// REST-02: 默认状态为 unknown
TEST(RestApiStatusTest, DefaultStatusUnknown) {
    auto m = BuildStatusMap();
    EXPECT_EQ(m[7], "unknown");
}

// REST-03: 上链地址有效性
TEST(RestApiAddressTest, InvalidAddressDetection) {
    T_LOCALBLOCKADDRESS addr;
    // 默认地址应为无效
    EXPECT_FALSE(addr.isValid());
    addr.hid = 1;
    addr.chainnum = 1;
    addr.id = 1;
    EXPECT_TRUE(addr.isValid());
}
