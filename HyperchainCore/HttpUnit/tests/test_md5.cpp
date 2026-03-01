// =============================================================================
// test_md5.cpp — CMD5 MD5 摘要算法单元测试
// 对应源文件: HttpUnit/md5.cpp
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <cctype>

// ═══════════════════════════════════════════════════════════════
//  直接引入 CMD5 (独立编译单元，无外部依赖)
// ═══════════════════════════════════════════════════════════════
#include "HttpUnit/md5.h"

// ═══════════════ 构造函数 ═══════════════

// MD5-01: 默认构造 → 全零
TEST(CMD5Test, DefaultConstruct) {
    CMD5 md;
    std::string s = md.ToString();
    EXPECT_EQ(s, "00000000000000000000000000000000");
}

// ═══════════════ 已知测试向量 (RFC 1321) ═══════════════

// MD5-02: MD5("") = d41d8cd98f00b204e9800998ecf8427e
TEST(CMD5Test, KnownVector_Empty) {
    CMD5 md;
    unsigned char empty[] = "";
    md.GenerateMD5(empty, 0);
    EXPECT_EQ(md.ToString(), "d41d8cd98f00b204e9800998ecf8427e");
}

// MD5-03: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
TEST(CMD5Test, KnownVector_abc) {
    CMD5 md;
    unsigned char data[] = "abc";
    md.GenerateMD5(data, 3);
    EXPECT_EQ(md.ToString(), "900150983cd24fb0d6963f7d28e17f72");
}

// MD5-04: MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
TEST(CMD5Test, KnownVector_MessageDigest) {
    CMD5 md;
    unsigned char data[] = "message digest";
    md.GenerateMD5(data, 14);
    EXPECT_EQ(md.ToString(), "f96b697d7cb7938d525a2f31aaf161d0");
}

// 额外: MD5("a") = 0cc175b9c0f1b6a831c399e269772661
TEST(CMD5Test, KnownVector_a) {
    CMD5 md;
    unsigned char data[] = "a";
    md.GenerateMD5(data, 1);
    EXPECT_EQ(md.ToString(), "0cc175b9c0f1b6a831c399e269772661");
}

// 额外: MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
TEST(CMD5Test, KnownVector_Alphabet) {
    CMD5 md;
    unsigned char data[] = "abcdefghijklmnopqrstuvwxyz";
    md.GenerateMD5(data, 26);
    EXPECT_EQ(md.ToString(), "c3fcd3d76192e4007dfb496cca67e13b");
}

// ═══════════════ 确定性 ═══════════════

// MD5-05
TEST(CMD5Test, Deterministic) {
    CMD5 a, b;
    unsigned char data[] = "hyperchain_test_data_12345";
    a.GenerateMD5(data, strlen((char*)data));
    b.GenerateMD5(data, strlen((char*)data));
    EXPECT_EQ(a.ToString(), b.ToString());
    EXPECT_TRUE(a == b);
}

// MD5-06: 不同输入 → 不同哈希
TEST(CMD5Test, DifferentInput) {
    CMD5 a, b;
    unsigned char d1[] = "hello";
    unsigned char d2[] = "world";
    a.GenerateMD5(d1, 5);
    b.GenerateMD5(d2, 5);
    EXPECT_NE(a.ToString(), b.ToString());
    EXPECT_FALSE(a == b);
}

// ═══════════════ 运算符 ═══════════════

// MD5-07: operator==
TEST(CMD5Test, EqualityOperator) {
    CMD5 a, b;
    unsigned char data[] = "same_input";
    a.GenerateMD5(data, strlen((char*)data));
    b.GenerateMD5(data, strlen((char*)data));
    EXPECT_TRUE(a == b);
}

// MD5-08: operator+ (XOR)
TEST(CMD5Test, XorOperator) {
    CMD5 a, b;
    unsigned char d1[] = "data_a";
    unsigned char d2[] = "data_b";
    a.GenerateMD5(d1, strlen((char*)d1));
    b.GenerateMD5(d2, strlen((char*)d2));

    CMD5 xored = a + b;

    // XOR 属性: a + a = 0
    CMD5 selfXor = a + a;
    CMD5 zero;
    EXPECT_TRUE(selfXor == zero);

    // XOR 非零 (不同输入)
    EXPECT_FALSE(xored == zero);
}

// ═══════════════ ToString 格式 ═══════════════

// MD5-09: 长度 32
TEST(CMD5Test, ToStringLength) {
    CMD5 md;
    unsigned char data[] = "test";
    md.GenerateMD5(data, 4);
    EXPECT_EQ(md.ToString().length(), 32u);
}

// MD5-10: 仅包含 hex 字符
TEST(CMD5Test, ToStringHexChars) {
    CMD5 md;
    unsigned char data[] = "hex_check";
    md.GenerateMD5(data, strlen((char*)data));
    std::string hex = md.ToString();
    for (char c : hex) {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)))
            << "Non-hex char: " << c;
    }
}

// ═══════════════ 构造：从 hex string ═══════════════

// MD5-11: hex 字符串 → CMD5 → ToString 往返
TEST(CMD5Test, FromHexStringRoundTrip) {
    CMD5 original;
    unsigned char data[] = "roundtrip_test";
    original.GenerateMD5(data, strlen((char*)data));
    std::string hexStr = original.ToString();

    CMD5 restored(hexStr.c_str());
    EXPECT_EQ(restored.ToString(), hexStr);
    EXPECT_TRUE(restored == original);
}

// MD5-12: 从 ulong 数组构造
TEST(CMD5Test, FromUlongArray) {
    unsigned long src[4] = {0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210};
    CMD5 md(src);
    // m_data 应该匹配
    EXPECT_EQ(md.m_data[0], 0x12345678u);
    EXPECT_EQ(md.m_data[1], 0x9ABCDEF0u);
    EXPECT_EQ(md.m_data[2], 0xFEDCBA98u);
    EXPECT_EQ(md.m_data[3], 0x76543210u);
}

// MD5-13: 大缓冲区
TEST(CMD5Test, LargeBuffer) {
    CMD5 md;
    std::string big(1024 * 1024, 'Z');
    md.GenerateMD5(reinterpret_cast<unsigned char*>(big.data()),
                   static_cast<int>(big.size()));
    std::string result = md.ToString();
    EXPECT_EQ(result.length(), 32u);
    EXPECT_NE(result, "00000000000000000000000000000000");
}

// 额外: 空字符串构造 CMD5
TEST(CMD5Test, FromEmptyHexString) {
    CMD5 md("");
    CMD5 zero;
    EXPECT_TRUE(md == zero);
}
