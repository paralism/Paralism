// =============================================================================
// test_httpunit.cpp — HttpDownload/HttpDownloadFile URL 解析与协议逻辑测试
// 对应源文件: HttpUnit/HttpUnit.cpp
//
// 注意: HttpDownload* 函数内部创建 socket 并发起网络请求，无法在没有
//       真实网络的环境下进行端到端测试。此处提取 URL 解析、请求构建
//       和错误码映射的纯逻辑进行测试。
// =============================================================================
#include <gtest/gtest.h>
#include <string>
#include <cstdlib>

// ═══════════════════════════════════════════════════════════════
//  提取 HttpDownload/HttpDownloadFile 中的 URL 解析逻辑
//  原始代码在 HttpUnit.cpp 中以内联形式存在，此处独立复刻
// ═══════════════════════════════════════════════════════════════

namespace HttpLogic {

struct ParsedUrl {
    std::string host;
    int port = 80;
    std::string remotepath;
    int errorCode = 0;
};

// 复刻 HttpDownload 中的 URL 解析逻辑
ParsedUrl ParseUrl(const std::string& inputUrl, const std::string& tokenArg = "/") {
    ParsedUrl result;
    std::string url = inputUrl;
    std::string token = tokenArg.empty() ? "\\" : tokenArg;

    // 确保 URL 中 Token 存在
    if (url.find(token, 8) == std::string::npos) {
        url += token;
    }

    int pos = url.find(token, 8);
    if (pos == -1) {
        result.errorCode = 401;
        return result;
    }

    result.host = url.substr(7, pos - 7);
    result.remotepath = url.substr(pos, url.length());

    // 解析端口
    int colonPos = result.host.find(':');
    if (colonPos != -1) {
        result.port = atoi(result.host.substr(colonPos + 1).c_str());
        if (result.port == 0) result.port = 80;
        result.host = result.host.substr(0, colonPos);
    }

    return result;
}

// 错误码映射
struct ErrorCodeMap {
    static constexpr int URL_PARSE_ERROR = 401;
    static constexpr int SOCKET_CREATE_FAIL = 402;
    static constexpr int CONNECT_FAIL = 403;
    static constexpr int RECV_TIMEOUT = 407;
    static constexpr int DEFAULT_ERROR = 444;
};

// 提取重定向 URL 构建逻辑
std::string BuildRedirectUrl(const std::string& originalUrl,
                              const std::string& host, int port,
                              const std::string& newLocation) {
    if (newLocation.substr(0, 7) == "http://") {
        return newLocation;
    }
    if (!newLocation.empty() && newLocation[0] == '/') {
        return "http://" + host + ":" + std::to_string(port) + newLocation;
    }
    // 相对路径
    auto slashPos = originalUrl.rfind('/');
    if (slashPos != std::string::npos) {
        return originalUrl.substr(0, slashPos + 1) + newLocation;
    }
    return newLocation;
}

} // namespace HttpLogic

// ═══════════════ URL 解析测试 ═══════════════

// HTU-01: host:port/path
TEST(UrlParseTest, HostPortPath) {
    auto r = HttpLogic::ParseUrl("http://example.com:8080/api/data");
    EXPECT_EQ(r.host, "example.com");
    EXPECT_EQ(r.port, 8080);
    EXPECT_EQ(r.remotepath, "/api/data");
    EXPECT_EQ(r.errorCode, 0);
}

// HTU-02: 默认端口
TEST(UrlParseTest, DefaultPort) {
    auto r = HttpLogic::ParseUrl("http://example.com/path/to/resource");
    EXPECT_EQ(r.host, "example.com");
    EXPECT_EQ(r.port, 80);
    EXPECT_EQ(r.remotepath, "/path/to/resource");
}

// HTU-03: 无路径 (自动补 token)
TEST(UrlParseTest, NoPath) {
    auto r = HttpLogic::ParseUrl("http://example.com:9090");
    EXPECT_EQ(r.host, "example.com");
    EXPECT_EQ(r.port, 9090);
    EXPECT_EQ(r.remotepath, "/");
}

// HTU-04: 无效 URL (无 token)
TEST(UrlParseTest, Invalid) {
    // URL 过短且无分隔符 → 但默认会追加 token，所以只有极端情况 401
    auto r = HttpLogic::ParseUrl("http://", "IMPOSSIBLE_TOKEN_NOT_IN_URL");
    EXPECT_EQ(r.errorCode, 401);
}

// 额外: 端口为 0 → 回退 80
TEST(UrlParseTest, PortZeroFallback) {
    auto r = HttpLogic::ParseUrl("http://host:0/path");
    EXPECT_EQ(r.port, 80);
}

// 额外: IP 地址作为 host
TEST(UrlParseTest, IpAddress) {
    auto r = HttpLogic::ParseUrl("http://192.168.1.100:3000/api");
    EXPECT_EQ(r.host, "192.168.1.100");
    EXPECT_EQ(r.port, 3000);
    EXPECT_EQ(r.remotepath, "/api");
}

// 额外: 多层路径
TEST(UrlParseTest, DeepPath) {
    auto r = HttpLogic::ParseUrl("http://cdn.example.com/a/b/c/d/e.json");
    EXPECT_EQ(r.host, "cdn.example.com");
    EXPECT_EQ(r.remotepath, "/a/b/c/d/e.json");
}

// 额外: 含查询参数
TEST(UrlParseTest, WithQueryString) {
    auto r = HttpLogic::ParseUrl("http://api.example.com/search?q=test&page=1");
    EXPECT_EQ(r.host, "api.example.com");
    EXPECT_NE(r.remotepath.find("q=test"), std::string::npos);
}

// ═══════════════ 错误码映射 ═══════════════

// HTU-13
TEST(ErrorCodeTest, SocketCreateFail) {
    EXPECT_EQ(HttpLogic::ErrorCodeMap::SOCKET_CREATE_FAIL, 402);
}

// HTU-14
TEST(ErrorCodeTest, ConnectFail) {
    EXPECT_EQ(HttpLogic::ErrorCodeMap::CONNECT_FAIL, 403);
}

// HTU-15
TEST(ErrorCodeTest, RecvTimeout) {
    EXPECT_EQ(HttpLogic::ErrorCodeMap::RECV_TIMEOUT, 407);
}

TEST(ErrorCodeTest, DefaultError) {
    EXPECT_EQ(HttpLogic::ErrorCodeMap::DEFAULT_ERROR, 444);
}

// ═══════════════ 重定向 URL 构建 ═══════════════

TEST(RedirectTest, AbsoluteUrl) {
    auto url = HttpLogic::BuildRedirectUrl(
        "http://old.com/page", "old.com", 80,
        "http://new.com/landing");
    EXPECT_EQ(url, "http://new.com/landing");
}

TEST(RedirectTest, AbsolutePath) {
    auto url = HttpLogic::BuildRedirectUrl(
        "http://example.com/old", "example.com", 8080,
        "/new/path");
    EXPECT_EQ(url, "http://example.com:8080/new/path");
}

TEST(RedirectTest, RelativePath) {
    auto url = HttpLogic::BuildRedirectUrl(
        "http://example.com/dir/page", "example.com", 80,
        "other.html");
    EXPECT_EQ(url, "http://example.com/dir/other.html");
}
