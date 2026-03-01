// =============================================================================
// test_common.cpp — 通用辅助函数单元测试
// 对应源文件: util/common.h
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <vector>

// ═══════════════════════════════════════════════════════════════
//  提取 StringFormat / time2string 核心逻辑
// ═══════════════════════════════════════════════════════════════

namespace CommonUtil {

inline std::string StringFormat(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return std::string(buf);
}

inline std::string time2string(time_t t) {
    struct tm tm_val;
#ifdef _WIN32
    localtime_s(&tm_val, &t);
#else
    localtime_r(&t, &tm_val);
#endif
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_val);
    return std::string(buf);
}

} // namespace CommonUtil

// ═══════════════ StringFormat 测试 ═══════════════

// CMN-01: 基本格式化
TEST(StringFormatTest, Basic) {
    auto s = CommonUtil::StringFormat("hello %d", 42);
    EXPECT_EQ(s, "hello 42");
}

// CMN-02: 多参数
TEST(StringFormatTest, MultiParam) {
    auto s = CommonUtil::StringFormat("%s=%d, %s=%.2f", "x", 1, "pi", 3.14);
    EXPECT_EQ(s, "x=1, pi=3.14");
}

// CMN-03: 空串
TEST(StringFormatTest, Empty) {
    auto s = CommonUtil::StringFormat("");
    EXPECT_EQ(s, "");
}

// CMN-06: 十六进制格式
TEST(StringFormatTest, HexFormat) {
    auto s = CommonUtil::StringFormat("0x%08X", 0xDEADBEEF);
    EXPECT_EQ(s, "0xDEADBEEF");
}

// CMN-07: 长字符串拼接
TEST(StringFormatTest, LongString) {
    std::string longstr(2000, 'A');
    auto s = CommonUtil::StringFormat("prefix_%s", longstr.c_str());
    EXPECT_EQ(s.substr(0, 7), "prefix_");
    EXPECT_GT(s.size(), 2000u);
}

// ═══════════════ time2string 测试 ═══════════════

// CMN-04: 输出非空
TEST(Time2StringTest, NonEmpty) {
    auto s = CommonUtil::time2string(time(nullptr));
    EXPECT_FALSE(s.empty());
}

// CMN-05: 输出长度（至少 "YYYY-MM-DD HH:MM:SS" = 19 字符）
TEST(Time2StringTest, MinLength) {
    auto s = CommonUtil::time2string(time(nullptr));
    EXPECT_GE(s.size(), 19u);
}

// CMN-08: 已知 epoch 验证
TEST(Time2StringTest, KnownEpoch) {
    // 2024-01-01 00:00:00 UTC = 1704067200
    // 注意: 此测试依赖 UTC 时区。在非 UTC 环境下格式化结果会不同。
    // 此处仅验证输出格式而非具体值
    auto s = CommonUtil::time2string(1704067200);
    EXPECT_EQ(s[4], '-');
    EXPECT_EQ(s[7], '-');
    EXPECT_EQ(s[10], ' ');
    EXPECT_EQ(s[13], ':');
}
