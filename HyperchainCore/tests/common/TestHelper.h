#pragma once
// =============================================================================
// TestHelper.h — HyperchainCore 全局测试辅助工具
// =============================================================================

#include "headers/commonstruct.h"
#include <random>
#include <chrono>
#include <string>
#include <vector>
#include <list>
#include <sstream>
#include <cstring>
#include <ctime>

namespace TestHelper {

// ─────────────── SHA256 辅助 ───────────────

inline T_SHA256 RandomHash() {
    T_SHA256 hash;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (int i = 0; i < DEF_SHA256_LEN; ++i) {
        hash.pID[i] = dist(gen);
    }
    return hash;
}

inline T_SHA256 ZeroHash() {
    return T_SHA256(0);
}

inline T_SHA256 FilledHash(uint8_t val) {
    T_SHA256 hash;
    memset(hash.pID, val, DEF_SHA256_LEN);
    return hash;
}

// ─────────────── 局部块工厂 ───────────────

inline T_LOCALBLOCK MakeLocalBlock(
    uint16 id,
    const std::string& payload = "test_payload",
    uint64 preHID = 0)
{
    T_LOCALBLOCK block;
    block.header.uiID = id;
    block.header.uiTime = static_cast<uint64>(time(nullptr));
    block.header.uiNonce = 42;
    block.header.tPreHash = ZeroHash();
    block.header.tPreHHash = ZeroHash();
    block.body.payload = payload;
    block._prehid = preHID;
    block.BuildBlockBodyHash();
    return block;
}

// ─────────────── 超块工厂 ───────────────

inline T_HYPERBLOCK MakeHyperBlock(
    uint64 id,
    const T_SHA256& preHash = T_SHA256(0),
    int numLocalBlocks = 2)
{
    T_HYPERBLOCK hblock;
    hblock.header.uiID = id;
    hblock.header.uiTime = static_cast<uint64>(time(nullptr));
    hblock.header.tPreHash = preHash;
    hblock.header.uiWeight = numLocalBlocks;

    std::list<T_LOCALBLOCK> chain;
    for (int i = 0; i < numLocalBlocks; ++i) {
        chain.push_back(MakeLocalBlock(i, "payload_" + std::to_string(i), id > 0 ? id - 1 : 0));
    }
    hblock.AddChildChain(std::move(chain));
    hblock.Rebuild();
    return hblock;
}

// 构造超块链 (genesis → ... → tip)
inline std::vector<T_HYPERBLOCK> MakeChain(int length, int blocksPerHyper = 2) {
    std::vector<T_HYPERBLOCK> chain;
    T_SHA256 prevHash = ZeroHash();
    for (int i = 0; i < length; ++i) {
        auto hb = MakeHyperBlock(i, prevHash, blocksPerHyper);
        hb.calculateHashSelf();
        prevHash = hb.GetHashSelf();
        chain.push_back(std::move(hb));
    }
    return chain;
}

// ─────────────── 数据库辅助 ───────────────

inline std::string TempDBPath() {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return "/tmp/hctest_" + std::to_string(now) + ".db";
}

// ─────────────── 字符串辅助 ───────────────

inline std::string RandomString(size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string s(len, 0);
    for (size_t i = 0; i < len; ++i) s[i] = charset[dist(gen)];
    return s;
}

} // namespace TestHelper
