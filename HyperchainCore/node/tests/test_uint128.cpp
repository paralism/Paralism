// =============================================================================
// test_uint128.cpp — CUInt128 128 位整数单元测试
// 对应源文件: node/UInt128.cpp
// =============================================================================
#include <gtest/gtest.h>
#include "node/UInt128.h"
#include <sstream>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

class UInt128Test : public ::testing::Test {
protected:
    CUInt128 zero{(uint32_t)0};
    CUInt128 one{(uint32_t)1};
    CUInt128 val_ff{(uint32_t)0xFF};
    CUInt128 val_0f{(uint32_t)0x0F};
    CUInt128 big{(uint32_t)0xDEADBEEF};
};

// ═══════════════ 构造 ═══════════════

// U128-01
TEST_F(UInt128Test, ZeroConstruct) {
    EXPECT_TRUE(zero.IsZero());
}

// U128-02
TEST_F(UInt128Test, NonZeroConstruct) {
    EXPECT_FALSE(one.IsZero());
    EXPECT_FALSE(big.IsZero());
}

// ═══════════════ 比较 ═══════════════

// U128-03
TEST_F(UInt128Test, Equality) {
    CUInt128 one_dup{(uint32_t)1};
    EXPECT_TRUE(one == one_dup);
    EXPECT_TRUE(one == one);
}

// U128-04
TEST_F(UInt128Test, Inequality) {
    EXPECT_TRUE(zero != one);
    EXPECT_TRUE(one != big);
}

// U128-05
TEST_F(UInt128Test, LessThan) {
    EXPECT_TRUE(zero < one);
    EXPECT_FALSE(one < zero);
    EXPECT_FALSE(one < one);
}

// U128-10: 拷贝构造
TEST_F(UInt128Test, CopyConstruct) {
    CUInt128 copy(big);
    EXPECT_TRUE(copy == big);
}

// ═══════════════ XOR 距离 ═══════════════

// U128-06
TEST_F(UInt128Test, XORDistance) {
    CUInt128 result = val_ff ^ val_0f;
    CUInt128 expected{(uint32_t)0xF0};
    EXPECT_TRUE(result == expected);
}

// XOR 自身 = 0
TEST_F(UInt128Test, XORSelfIsZero) {
    CUInt128 result = big ^ big;
    EXPECT_TRUE(result.IsZero());
}

// ═══════════════ 字符串 ═══════════════

// U128-07
TEST_F(UInt128Test, HexStringLength) {
    std::string hex = one.ToHexString();
    EXPECT_EQ(hex.length(), 32u); // 128 bit = 32 hex chars
}

// ═══════════════ 位移 ═══════════════

// U128-08
TEST_F(UInt128Test, ShiftLeft) {
    CUInt128 val{(uint32_t)1};
    CUInt128 shifted = val << 8;
    CUInt128 expected{(uint32_t)256};
    EXPECT_TRUE(shifted == expected);
}

// ═══════════════ 序列化 ═══════════════

// U128-09
TEST_F(UInt128Test, BoostSerRoundTrip) {
    std::stringstream ss;
    {
        boost::archive::binary_oarchive oa(ss, boost::archive::archive_flags::no_header);
        oa << big;
    }
    CUInt128 restored{(uint32_t)0};
    {
        boost::archive::binary_iarchive ia(ss, boost::archive::archive_flags::no_header);
        ia >> restored;
    }
    EXPECT_TRUE(big == restored);
}
