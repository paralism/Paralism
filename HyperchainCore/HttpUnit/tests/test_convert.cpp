// =============================================================================
// test_convert.cpp — CConvert 类型转换单元测试
// 对应源文件: HttpUnit/convert.cpp
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <climits>

// ═══════════════════════════════════════════════════════════════
//  提取 CConvert 核心逻辑（避免 include 依赖链）
// ═══════════════════════════════════════════════════════════════

namespace ConvertSim {

std::string IntToStr(unsigned long iValue) {
    char szBuf[80];
    sprintf(szBuf, "%u", iValue);
    return szBuf;
}

unsigned long StrToInt(const std::string& strValue) {
    return atol(strValue.c_str());
}

} // namespace ConvertSim

// ═══════════════ IntToStr ═══════════════

// CVT-01
TEST(ConvertIntToStrTest, Zero) {
    EXPECT_EQ(ConvertSim::IntToStr(0), "0");
}

// CVT-02
TEST(ConvertIntToStrTest, Normal) {
    EXPECT_EQ(ConvertSim::IntToStr(12345), "12345");
}

// CVT-03
TEST(ConvertIntToStrTest, MaxUint32) {
    EXPECT_EQ(ConvertSim::IntToStr(4294967295UL), "4294967295");
}

// CVT-04
TEST(ConvertIntToStrTest, One) {
    EXPECT_EQ(ConvertSim::IntToStr(1), "1");
}

// 额外: 端口常用值
TEST(ConvertIntToStrTest, TypicalPort) {
    EXPECT_EQ(ConvertSim::IntToStr(8080), "8080");
    EXPECT_EQ(ConvertSim::IntToStr(443), "443");
    EXPECT_EQ(ConvertSim::IntToStr(80), "80");
}

// ═══════════════ StrToInt ═══════════════

// CVT-05
TEST(ConvertStrToIntTest, Zero) {
    EXPECT_EQ(ConvertSim::StrToInt("0"), 0u);
}

// CVT-06
TEST(ConvertStrToIntTest, Normal) {
    EXPECT_EQ(ConvertSim::StrToInt("12345"), 12345u);
}

// CVT-07: 空串 atol 返回 0
TEST(ConvertStrToIntTest, Empty) {
    EXPECT_EQ(ConvertSim::StrToInt(""), 0u);
}

// CVT-08: 前导零
TEST(ConvertStrToIntTest, LeadingZeros) {
    EXPECT_EQ(ConvertSim::StrToInt("007"), 7u);
}

// 额外: 含非数字尾缀
TEST(ConvertStrToIntTest, TrailingChars) {
    // atol("123abc") == 123
    EXPECT_EQ(ConvertSim::StrToInt("123abc"), 123u);
}

// 额外: 纯字母
TEST(ConvertStrToIntTest, PureLetters) {
    EXPECT_EQ(ConvertSim::StrToInt("hello"), 0u);
}

// ═══════════════ 往返一致性 ═══════════════

// CVT-09
TEST(ConvertRoundTripTest, Small) {
    unsigned long val = 42;
    EXPECT_EQ(ConvertSim::StrToInt(ConvertSim::IntToStr(val)), val);
}

// CVT-10
TEST(ConvertRoundTripTest, Large) {
    unsigned long val = 999999;
    EXPECT_EQ(ConvertSim::StrToInt(ConvertSim::IntToStr(val)), val);
}

// CVT-11: 批量往返
TEST(ConvertRoundTripTest, Batch) {
    unsigned long values[] = {0, 1, 100, 255, 1024, 65535, 1000000, 4294967295UL};
    for (auto v : values) {
        EXPECT_EQ(ConvertSim::StrToInt(ConvertSim::IntToStr(v)), v) << "Failed for " << v;
    }
}
