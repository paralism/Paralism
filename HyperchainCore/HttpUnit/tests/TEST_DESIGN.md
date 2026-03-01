# HttpUnit 模块测试设计方案

## 模块概述

`HttpUnit/` 是 HyperchainCore 的 HTTP 通信与工具层，提供底层 Socket 封装、HTTP 代理穿透、
HTTP 请求构建与响应解析、类型转换和 MD5 摘要算法。

## 源文件清单

| 文件 | 关键类/函数 | 职责 |
|------|-----------|------|
| sock.h/cpp | `BaseSock` | 底层 TCP/UDP socket 封装 (Create, Connect, Send, Recv, Close, Bind, Accept, isIp) |
| switchsock.h/cpp | `SwitchSock` | HTTP Switch 代理 socket (_ParseParam, _SendHttpPacket, _RecvHttpPacket) |
| HttpUnit.h/cpp | `HttpDownload`, `HttpDownloadFile`, `HttpDownloadT/F` | HTTP GET/POST/DELETE/HEAD 请求构建, URL 解析, HTTP 响应码提取, 重定向跟随 |
| convert.h/cpp | `CConvert` | IntToStr / StrToInt 类型转换 |
| md5.h/cpp | `CMD5` | MD5 摘要算法 (GenerateMD5, ToString, operator==, operator+) |
| mutex.h | `MMutex` | 跨平台互斥锁 (Lock/Unlock) |

## 测试文件

| 测试文件 | 对应源文件 | 测试内容 |
|---------|-----------|---------|
| test_convert.cpp | convert.cpp | IntToStr / StrToInt 类型转换 |
| test_md5.cpp | md5.cpp | MD5 摘要算法完整性 |
| test_basesock.cpp | sock.cpp | BaseSock 生命周期、isIp 验证 |
| test_switchsock.cpp | switchsock.cpp | _ParseParam 参数解析逻辑 |
| test_httpunit.cpp | HttpUnit.cpp | URL 解析、HTTP 请求构建、响应码提取 |
| test_mutex.cpp | mutex.h | MMutex 锁语义 |

---

## test_convert.cpp 测试矩阵 (CConvert)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| CVT-01 | IntToStr_Zero | 0 | "0" | P0 |
| CVT-02 | IntToStr_Normal | 12345 | "12345" | P0 |
| CVT-03 | IntToStr_MaxUint | 4294967295 | "4294967295" | P0 |
| CVT-04 | IntToStr_One | 1 | "1" | P1 |
| CVT-05 | StrToInt_Zero | "0" | 0 | P0 |
| CVT-06 | StrToInt_Normal | "12345" | 12345 | P0 |
| CVT-07 | StrToInt_Empty | "" | 0 (atol行为) | P1 |
| CVT-08 | StrToInt_Leading | "007" | 7 | P1 |
| CVT-09 | RoundTrip | 42→str→int | 42 | P0 |
| CVT-10 | RoundTrip_Large | 999999→str→int | 999999 | P0 |

## test_md5.cpp 测试矩阵 (CMD5)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| MD5-01 | DefaultConstruct | CMD5() | ToString 全零 | P0 |
| MD5-02 | KnownVector_Empty | "" (0字节) | d41d8cd98f00b204e9800998ecf8427e | P0 |
| MD5-03 | KnownVector_abc | "abc" | 900150983cd24fb0d6963f7d28e17f72 | P0 |
| MD5-04 | KnownVector_123 | "123456789..." | 已知值 | P0 |
| MD5-05 | Deterministic | 同输入两次 | 结果相等 | P0 |
| MD5-06 | DifferentInput | 不同输入 | 结果不等 | P0 |
| MD5-07 | EqualityOperator | 同数据两个 CMD5 | operator== true | P0 |
| MD5-08 | XorOperator | a + b | XOR 正确 | P1 |
| MD5-09 | ToStringLength | 任意 | 长度==32 | P0 |
| MD5-10 | ToStringHexChars | 任意 | 仅 [0-9a-f] | P1 |
| MD5-11 | FromHexString | hex→CMD5→ToString | 往返一致 | P0 |
| MD5-12 | FromUlongArray | ulong[4]→CMD5 | m_data 正确 | P1 |
| MD5-13 | LargeBuffer | 1MB 数据 | 不崩溃且非零 | P1 |

## test_basesock.cpp 测试矩阵 (BaseSock)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| SOK-01 | InitialState | 构造后 | m_sock==-1, isConnected==false | P0 |
| SOK-02 | CreateTCP | Create(false) | GetHandle()!=-1 | P0 |
| SOK-03 | CreateUDP | Create(true) | isUDP()==true | P0 |
| SOK-04 | CloseResets | Create→Close | GetHandle()==-1, isConnected==false | P0 |
| SOK-05 | DoubleClose | Close→Close | 不崩溃 | P0 |
| SOK-06 | SendWithoutConnect | Send on -1 | 返回 -1 | P0 |
| SOK-07 | RecvWithoutConnect | Recv on -1 | 返回 -1 | P0 |
| SOK-08 | isIp_Valid | "192.168.1.1" | 返回 0 | P0 |
| SOK-09 | isIp_Invalid_Letters | "abc.def.ghi" | 返回 -1 | P0 |
| SOK-10 | isIp_Invalid_Range | "256.1.1.1" | 返回 -1 | P0 |
| SOK-11 | isIp_TooShort | "1.1" | 返回 -1 | P1 |
| SOK-12 | isIp_Boundary | "0.0.0.0" | 返回 0 | P1 |
| SOK-13 | isIp_Max | "255.255.255.255" | 返回 0 | P1 |
| SOK-14 | LoopbackConnect | Connect("127.0.0.1", port) | 视环境 | P2 |

## test_switchsock.cpp 测试矩阵 (SwitchSock::_ParseParam)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| SSK-01 | ParseSingle | "Cmd=Create" | {Cmd:Create} | P0 |
| SSK-02 | ParseMulti | "Cmd=Connect&Host=1.2.3.4&Port=80" | 3 对 kv | P0 |
| SSK-03 | ParseEmpty | "" | 空 map | P0 |
| SSK-04 | ParseNoValue | "Cmd=" | {Cmd:""} | P1 |
| SSK-05 | ParseSpecialChars | "Path=/a/b/c&Name=test" | 正确解析 | P1 |
| SSK-06 | ParseTrailingAmp | "A=1&B=2&" | 解析 A,B | P1 |

## test_httpunit.cpp 测试矩阵 (URL解析/请求构建)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| HTU-01 | ParseUrl_HostPort | "http://host:8080/path" | host, 8080, /path | P0 |
| HTU-02 | ParseUrl_DefaultPort | "http://host/path" | host, 80, /path | P0 |
| HTU-03 | ParseUrl_NoPath | "http://host:9090" | 添加 Token | P0 |
| HTU-04 | ParseUrl_Invalid | 无 Token | 返回 401 | P0 |
| HTU-05 | BuildGetRequest | GET /path | 包含 "GET /path HTTP/1.1" | P0 |
| HTU-06 | BuildPostRequest | POST + body | 包含 Content-Length | P0 |
| HTU-07 | BuildDeleteRequest | post="DELETE" | 包含 "DELETE" | P0 |
| HTU-08 | BuildHeadRequest | IsHead=true | 包含 "HEAD " | P0 |
| HTU-09 | ParseStatusCode_200 | "HTTP/1.1 200 OK" | 200 | P0 |
| HTU-10 | ParseStatusCode_404 | "HTTP/1.1 404 Not Found" | 404 | P0 |
| HTU-11 | ParseStatusCode_302 | "HTTP/1.1 302 Found" | 302 | P0 |
| HTU-12 | ParseContentLength | "Content-Length: 1024" | 1024 | P0 |
| HTU-13 | ErrorCode_402 | socket Create 失败 | 402 | P1 |
| HTU-14 | ErrorCode_403 | Connect 失败 | 403 | P1 |
| HTU-15 | ErrorCode_407 | Recv 超时 | 407 | P1 |

## test_mutex.cpp 测试矩阵 (MMutex)

| 编号 | 测试用例 | 输入 | 预期输出 | 优先级 |
|------|---------|------|---------|--------|
| MUT-01 | LockUnlock | Lock→Unlock | 不死锁 | P0 |
| MUT-02 | MultithreadSafety | 2 线程各+5000 | counter==10000 | P0 |
| MUT-03 | DestructorSafe | 构造→析构 | 不崩溃 | P0 |
