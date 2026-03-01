// =============================================================================
// test_switchsock.cpp — SwitchSock::_ParseParam 参数解析单元测试
// 对应源文件: HttpUnit/switchsock.cpp
//
// 注意: SwitchSock 的网络相关函数（Create/Connect/Send/Recv）深度耦合
//       HTTP Switch 代理服务器。此处仅测试可独立提取的纯逻辑。
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <map>

// ═══════════════════════════════════════════════════════════════
//  提取 _ParseParam 核心逻辑（原函数为 private，此处复刻源码）
// ═══════════════════════════════════════════════════════════════

namespace SwitchSockLogic {

void ParseParam(const std::string& param, std::map<std::string, std::string>& paramlist) {
    paramlist.clear();
    int start = 0;
    auto endpos = std::string::npos;

    do {
        int valuepos = param.find('=', start);
        if (valuepos == (int)std::string::npos)
            break;

        endpos = param.find('&', start);
        if (endpos == std::string::npos) {
            paramlist[param.substr(start, valuepos - start)] =
                param.substr(valuepos + 1, param.length());
        } else {
            paramlist[param.substr(start, valuepos - start)] =
                param.substr(valuepos + 1, endpos - valuepos - 1);
            start = endpos + 1;
        }
    } while (endpos != std::string::npos);
}

// 提取 HTTP 请求命令构建逻辑
std::string BuildHttpCmd(const std::string& remotepath, const std::string& host,
                          const std::string& post, const std::string& additionHead,
                          bool isHead, int contentLen) {
    std::string cmd;
    if (post.empty()) {
        if (isHead) cmd = "HEAD ";
        else cmd = "GET ";
        cmd += remotepath + " HTTP/1.1\r\nAccept: */* \r\nHost: " + host +
               "\r\nConnection: Keep-Alive\r\n\r\n";
    } else if (post == "DELETE") {
        cmd = "DELETE " + remotepath + " HTTP/1.1\r\nHost: " + host +
              "\r\nContent-Length: " + std::to_string(contentLen) +
              "\r\n" + additionHead + "\r\n\r\n";
    } else {
        cmd = "POST " + remotepath + " HTTP/1.1\r\nHost: " + host +
              "\r\nContent-Length: " + std::to_string(contentLen) +
              "\r\n" + additionHead + "\r\n\r\n" + post;
    }
    return cmd;
}

// 提取 HTTP 响应状态码解析
int ParseStatusCode(const char* buf) {
    const char* pStatue = strchr(buf, ' ');
    if (pStatue == nullptr) return -1;
    return atol(pStatue);
}

// 提取 Content-Length 解析
unsigned int ParseContentLength(const char* buf) {
    const char* temp_total = strstr(buf, "Content-Length:");
    if (temp_total == nullptr) return 0;
    temp_total += 15;
    return atol(temp_total);
}

} // namespace SwitchSockLogic

// ═══════════════ _ParseParam 测试 ═══════════════

class ParseParamTest : public ::testing::Test {
protected:
    std::map<std::string, std::string> result;
};

// SSK-01: 单一参数
TEST_F(ParseParamTest, Single) {
    SwitchSockLogic::ParseParam("Cmd=Create", result);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result["Cmd"], "Create");
}

// SSK-02: 多参数
TEST_F(ParseParamTest, Multiple) {
    SwitchSockLogic::ParseParam("Cmd=Connect&Host=1.2.3.4&Port=80", result);
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result["Cmd"], "Connect");
    EXPECT_EQ(result["Host"], "1.2.3.4");
    EXPECT_EQ(result["Port"], "80");
}

// SSK-03: 空串
TEST_F(ParseParamTest, Empty) {
    SwitchSockLogic::ParseParam("", result);
    EXPECT_TRUE(result.empty());
}

// SSK-04: 空值
TEST_F(ParseParamTest, EmptyValue) {
    SwitchSockLogic::ParseParam("Cmd=", result);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result["Cmd"], "");
}

// SSK-05: 含路径分隔符
TEST_F(ParseParamTest, SpecialChars) {
    SwitchSockLogic::ParseParam("Path=/a/b/c&Name=test_file", result);
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result["Path"], "/a/b/c");
    EXPECT_EQ(result["Name"], "test_file");
}

// SSK-06: 典型 SwitchSock 命令
TEST_F(ParseParamTest, TypicalSwitchCmd) {
    SwitchSockLogic::ParseParam("Cmd=SendTo&IP=3232235777&Port=8080", result);
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result["Cmd"], "SendTo");
    EXPECT_EQ(result["IP"], "3232235777");
    EXPECT_EQ(result["Port"], "8080");
}

// 额外: GetPeerName 响应
TEST_F(ParseParamTest, PeerNameResponse) {
    SwitchSockLogic::ParseParam("PeerIP=10.0.0.1&PeerPort=9090", result);
    EXPECT_EQ(result["PeerIP"], "10.0.0.1");
    EXPECT_EQ(result["PeerPort"], "9090");
}

// 额外: 无等号
TEST_F(ParseParamTest, NoEquals) {
    SwitchSockLogic::ParseParam("justkey", result);
    EXPECT_TRUE(result.empty());
}

// ═══════════════ HTTP 请求构建测试 ═══════════════

// HTU-05: GET 请求
TEST(BuildHttpCmdTest, GetRequest) {
    auto cmd = SwitchSockLogic::BuildHttpCmd("/api/data", "example.com", "", "", false, 0);
    EXPECT_NE(cmd.find("GET /api/data HTTP/1.1"), std::string::npos);
    EXPECT_NE(cmd.find("Host: example.com"), std::string::npos);
}

// HTU-06: POST 请求
TEST(BuildHttpCmdTest, PostRequest) {
    std::string body = "{\"key\":\"value\"}";
    auto cmd = SwitchSockLogic::BuildHttpCmd("/api/submit", "host.com",
               body, "Content-Type: application/json\r\n", false, body.length());
    EXPECT_NE(cmd.find("POST /api/submit HTTP/1.1"), std::string::npos);
    EXPECT_NE(cmd.find("Content-Length: 15"), std::string::npos);
    EXPECT_NE(cmd.find(body), std::string::npos);
}

// HTU-07: DELETE 请求
TEST(BuildHttpCmdTest, DeleteRequest) {
    auto cmd = SwitchSockLogic::BuildHttpCmd("/api/item/42", "host.com",
               "DELETE", "", false, 6);
    EXPECT_NE(cmd.find("DELETE /api/item/42 HTTP/1.1"), std::string::npos);
}

// HTU-08: HEAD 请求
TEST(BuildHttpCmdTest, HeadRequest) {
    auto cmd = SwitchSockLogic::BuildHttpCmd("/status", "host.com", "", "", true, 0);
    EXPECT_NE(cmd.find("HEAD /status HTTP/1.1"), std::string::npos);
}

// ═══════════════ HTTP 响应解析测试 ═══════════════

// HTU-09: 200 OK
TEST(ParseStatusCodeTest, Code200) {
    EXPECT_EQ(SwitchSockLogic::ParseStatusCode("HTTP/1.1 200 OK\r\n"), 200);
}

// HTU-10: 404
TEST(ParseStatusCodeTest, Code404) {
    EXPECT_EQ(SwitchSockLogic::ParseStatusCode("HTTP/1.1 404 Not Found\r\n"), 404);
}

// HTU-11: 302
TEST(ParseStatusCodeTest, Code302) {
    EXPECT_EQ(SwitchSockLogic::ParseStatusCode("HTTP/1.1 302 Found\r\n"), 302);
}

// 额外: 500
TEST(ParseStatusCodeTest, Code500) {
    EXPECT_EQ(SwitchSockLogic::ParseStatusCode("HTTP/1.1 500 Internal Server Error\r\n"), 500);
}

// HTU-12: Content-Length 解析
TEST(ParseContentLengthTest, Normal) {
    EXPECT_EQ(SwitchSockLogic::ParseContentLength(
        "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"), 1024u);
}

TEST(ParseContentLengthTest, Zero) {
    EXPECT_EQ(SwitchSockLogic::ParseContentLength(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 0u);
}

TEST(ParseContentLengthTest, Missing) {
    EXPECT_EQ(SwitchSockLogic::ParseContentLength(
        "HTTP/1.1 200 OK\r\n\r\n"), 0u);
}

TEST(ParseContentLengthTest, Large) {
    EXPECT_EQ(SwitchSockLogic::ParseContentLength(
        "HTTP/1.1 200 OK\r\nContent-Length: 10485760\r\n\r\n"), 10485760u);
}
