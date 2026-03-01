// =============================================================================
// test_basesock.cpp — BaseSock 底层 Socket 单元测试
// 对应源文件: HttpUnit/sock.cpp
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <cstring>

// ═══════════════════════════════════════════════════════════════
//  直接引入 BaseSock（需链接系统 socket 库）
//  对于不依赖网络的逻辑（isIp、状态管理）使用实际类
//  对于需要网络的逻辑使用模拟或 loopback
// ═══════════════════════════════════════════════════════════════
#include "HttpUnit/sock.h"

// ═══════════════ 构造/析构状态 ═══════════════

// SOK-01: 初始状态
TEST(BaseSockTest, InitialState) {
    BaseSock sock;
    EXPECT_EQ(sock.GetHandle(), -1);
    EXPECT_FALSE(sock.isConnected());
}

// SOK-02: 创建 TCP socket
TEST(BaseSockTest, CreateTCP) {
    BaseSock sock;
    ASSERT_TRUE(sock.Create(false));
    EXPECT_NE(sock.GetHandle(), -1);
    EXPECT_FALSE(sock.isUDP());
    sock.Close();
}

// SOK-03: 创建 UDP socket
TEST(BaseSockTest, CreateUDP) {
    BaseSock sock;
    ASSERT_TRUE(sock.Create(true));
    EXPECT_NE(sock.GetHandle(), -1);
    EXPECT_TRUE(sock.isUDP());
    sock.Close();
}

// SOK-04: Close 重置状态
TEST(BaseSockTest, CloseResets) {
    BaseSock sock;
    sock.Create(false);
    EXPECT_NE(sock.GetHandle(), -1);
    sock.Close();
    EXPECT_EQ(sock.GetHandle(), -1);
    EXPECT_FALSE(sock.isConnected());
}

// SOK-05: 双重 Close
TEST(BaseSockTest, DoubleClose) {
    BaseSock sock;
    sock.Create(false);
    sock.Close();
    sock.Close(); // 不应崩溃
    EXPECT_EQ(sock.GetHandle(), -1);
    SUCCEED();
}

// SOK-06: 未连接时 Send 返回 -1
TEST(BaseSockTest, SendWithoutConnect) {
    BaseSock sock; // m_sock == -1
    const char* data = "test";
    EXPECT_EQ(sock.Send(data, 4), -1);
}

// SOK-07: 未连接时 Recv 返回 -1
TEST(BaseSockTest, RecvWithoutConnect) {
    BaseSock sock; // m_sock == -1
    char buf[64];
    EXPECT_EQ(sock.Recv(buf, sizeof(buf), 1), -1);
}

// ═══════════════ isIp 验证 ═══════════════

// SOK-08: 有效 IP
TEST(BaseSockIsIpTest, Valid_Normal) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("192.168.1.1"), 0);
}

// SOK-09: 无效 - 字母
TEST(BaseSockIsIpTest, Invalid_Letters) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("abc.def.ghi.jkl"), -1);
}

// SOK-10: 无效 - 超范围
TEST(BaseSockIsIpTest, Invalid_Range) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("256.1.1.1"), -1);
}

// SOK-11: 无效 - 过短
TEST(BaseSockIsIpTest, Invalid_TooShort) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("1.1"), -1);
}

// SOK-12: 边界值 0.0.0.0
TEST(BaseSockIsIpTest, Boundary_AllZero) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("0.0.0.0"), 0);
}

// SOK-13: 边界值 255.255.255.255
TEST(BaseSockIsIpTest, Boundary_AllMax) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("255.255.255.255"), 0);
}

// 额外: localhost
TEST(BaseSockIsIpTest, Loopback) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("127.0.0.1"), 0);
}

// 额外: 有效 10.x
TEST(BaseSockIsIpTest, PrivateNetwork) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("10.0.0.1"), 0);
}

// 额外: 负值
TEST(BaseSockIsIpTest, Invalid_Negative) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("-1.0.0.1"), -1);
}

// 额外: 过长字符串 (>15)
TEST(BaseSockIsIpTest, Invalid_TooLong) {
    BaseSock sock;
    EXPECT_EQ(sock.isIp("1234.1234.1234.1234"), -1);
}

// ═══════════════ Loopback 回环测试 ═══════════════

// SOK-14: TCP Loopback Send/Recv (集成级)
TEST(BaseSockIntegrationTest, LoopbackTCP) {
    BaseSock server, client;
    ASSERT_TRUE(server.Create(false));

    // 绑定到随机端口
    unsigned short port = 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // 系统分配

    ASSERT_TRUE(server.Bind(0));

    // 获取分配的端口
    std::string ip;
    server.GetLocalName(ip, port);
    ASSERT_GT(port, 0);

    // 客户端连接
    ASSERT_TRUE(client.Create(false));
    bool connected = client.Connect("127.0.0.1", port);

    if (connected) {
        BaseSock accepted;
        if (server.Accept(accepted)) {
            const char* msg = "hello_hyperchain";
            client.Send(msg, strlen(msg));

            char buf[128] = {0};
            long n = accepted.Recv(buf, sizeof(buf), 2);
            if (n > 0) {
                EXPECT_STREQ(buf, "hello_hyperchain");
            }
            accepted.Close();
        }
    }
    client.Close();
    server.Close();
}
