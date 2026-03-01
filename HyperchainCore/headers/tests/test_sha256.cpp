// =============================================================================
// test_sha256.cpp — T_SHA256 哈希结构单元测试
// 对应源文件: headers/shastruct.h
// =============================================================================
#include <gtest/gtest.h>
#include "headers/shastruct.h"
#include <map>
#include <set>
#include <cstring>
#include <sstream>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

class SHA256Test : public ::testing::Test {
protected:
    T_SHA256 zero{0};
    T_SHA256 one{1};
    T_SHA256 hash_a, hash_b, hash_c;

    void SetUp() override {
        memset(hash_a.pID, 0xAA, DEF_SHA256_LEN);
        memset(hash_b.pID, 0xBB, DEF_SHA256_LEN);
        memset(hash_c.pID, 0xCC, DEF_SHA256_LEN);
    }
};

// ═══════════════ 构造测试 ═══════════════

// SHA-01: 零值构造
TEST_F(SHA256Test, ZeroConstruct) {
    for (int i = 0; i < DEF_SHA256_LEN; ++i) {
        EXPECT_EQ(zero.pID[i], 0) << "Byte " << i;
    }
}

// SHA-02: 填充值构造
TEST_F(SHA256Test, FillConstruct) {
    for (int i = 0; i < DEF_SHA256_LEN; ++i) {
        EXPECT_EQ(one.pID[i], 1) << "Byte " << i;
    }
}

// ═══════════════ 相等比较 ═══════════════

// SHA-03: 内容相同
TEST_F(SHA256Test, EqualitySameContent) {
    T_SHA256 copy;
    memcpy(copy.pID, hash_a.pID, DEF_SHA256_LEN);
    EXPECT_TRUE(hash_a == copy);
    EXPECT_FALSE(hash_a != copy);
}

// SHA-04: 内容不同
TEST_F(SHA256Test, EqualityDifferent) {
    EXPECT_FALSE(hash_a == hash_b);
    EXPECT_TRUE(hash_a != hash_b);
}

// ═══════════════ 排序比较 ═══════════════

// SHA-05: 小于
TEST_F(SHA256Test, LessThanOrdering) {
    EXPECT_TRUE(hash_a < hash_b);   // 0xAA < 0xBB
    EXPECT_FALSE(hash_b < hash_a);
}

// SHA-06: 大于对称性
TEST_F(SHA256Test, GreaterThanSymmetry) {
    EXPECT_TRUE(hash_b > hash_a);
    EXPECT_FALSE(hash_a > hash_b);
}

// SHA-07: 自比较
TEST_F(SHA256Test, SelfComparison) {
    EXPECT_TRUE(hash_a == hash_a);
    EXPECT_FALSE(hash_a < hash_a);
    EXPECT_FALSE(hash_a > hash_a);
    EXPECT_FALSE(hash_a != hash_a);
}

// SHA-17: 传递性 a < b, b < c → a < c
TEST_F(SHA256Test, TransitiveOrdering) {
    EXPECT_TRUE(hash_a < hash_b);
    EXPECT_TRUE(hash_b < hash_c);
    EXPECT_TRUE(hash_a < hash_c);
}

// ═══════════════ 字符串转换 ═══════════════

// SHA-08: HexString 长度
TEST_F(SHA256Test, HexStringLength) {
    EXPECT_EQ(hash_a.toHexString().length(), static_cast<size_t>(DEF_SHA256_LEN * 2));
}

// SHA-09: HexString 内容
TEST_F(SHA256Test, HexStringContent) {
    T_SHA256 h(0);
    h.pID[0] = 0xDE;
    h.pID[1] = 0xAD;
    std::string hex = h.toHexString();
    EXPECT_EQ(hex.substr(0, 4), "dead");
}

// ═══════════════ isNull 检测 ═══════════════

// SHA-10
TEST_F(SHA256Test, IsNullZero) {
    EXPECT_TRUE(zero.isNull());
}

// SHA-11
TEST_F(SHA256Test, IsNullNonZero) {
    EXPECT_FALSE(hash_a.isNull());
}

// ═══════════════ 拷贝赋值 ═══════════════

// SHA-12
TEST_F(SHA256Test, CopyAssignment) {
    T_SHA256 copy = hash_a;
    EXPECT_TRUE(copy == hash_a);
    copy.pID[0] = 0xFF;
    EXPECT_FALSE(copy == hash_a);  // 修改副本不影响原值
}

// ═══════════════ 容器行为 ═══════════════

// SHA-13: map 键查找
TEST_F(SHA256Test, MapKeyLookup) {
    std::map<T_SHA256, int> m;
    m[hash_a] = 100;
    m[hash_b] = 200;
    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ(m[hash_a], 100);
    EXPECT_EQ(m[hash_b], 200);
}

// SHA-14: map 键覆盖
TEST_F(SHA256Test, MapKeyOverwrite) {
    std::map<T_SHA256, int> m;
    m[hash_a] = 100;
    T_SHA256 dup;
    memcpy(dup.pID, hash_a.pID, DEF_SHA256_LEN);
    m[dup] = 999;
    EXPECT_EQ(m.size(), 1u);
    EXPECT_EQ(m[hash_a], 999);
}

// SHA-15: set 去重
TEST_F(SHA256Test, SetUniqueness) {
    std::set<T_SHA256> s;
    s.insert(hash_a);
    T_SHA256 dup;
    memcpy(dup.pID, hash_a.pID, DEF_SHA256_LEN);
    s.insert(dup);
    EXPECT_EQ(s.size(), 1u);
}

// ═══════════════ 序列化 ═══════════════

// SHA-16: Boost 序列化往返
TEST_F(SHA256Test, BoostSerRoundTrip) {
    std::stringstream ss;
    {
        boost::archive::binary_oarchive oa(ss, boost::archive::archive_flags::no_header);
        oa << hash_a;
    }
    T_SHA256 restored;
    {
        boost::archive::binary_iarchive ia(ss, boost::archive::archive_flags::no_header);
        ia >> restored;
    }
    EXPECT_TRUE(hash_a == restored);
}
