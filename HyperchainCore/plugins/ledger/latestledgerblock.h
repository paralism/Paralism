/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include "ledgermain.h"
#include "bignum.h"
#include "net.h"
#include "key.h"
#include "script.h"
#include "db.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "headers/inter_public.h"

#include "../common/bloomfilter.h"

#include "cryptotoken.h"

#include <list>
#include <algorithm>
#include <future>

class CBlockIndexSimplified;
class CBlockBloomFilter;
class CBlockDiskLocator;


extern map<uint256, CBlockIndex*> mapBlockIndex;
extern std::atomic<uint32_t> g_nHeightCheckPoint;
extern std::atomic<uint256> g_hashCheckPoint;

class CBlockCacheLocator;

extern HyperBlockMsgs hyperblockMsgs;


class CBlockIndexSimplified
{
public:
    const uint256* phashBlock = nullptr;  //HC: 块hash指针
    CBlockIndexSimplified* pprev = nullptr;
    CBlockIndexSimplified* pnext = nullptr;
    uint32_t nHeight = -1;

    BLOCKTRIPLEADDRESS addr;

public:
    void Set(const BLOCKTRIPLEADDRESS& addrIn, const CBlock& block)
    {
        addr = addrIn;
        nHeight = block.nHeight;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndexSimplified: \n"
            "\tHeight=%d"
            "\tAddr=%s\n"
            "\thashBlock=%s ******\n"
            "\thashPrevBlock=%s\n"
            "\thashNextBlock=%s\n",
            nHeight,
            addr.ToString().c_str(),
            phashBlock ? (phashBlock->ToString().c_str()) : "null",
            pprev ? (pprev->GetBlockHash().ToString().c_str()) : "null",
            pnext ? (pnext->GetBlockHash().ToString().c_str()) : "null");
    }

};


class BlockCheckPoint
{
public:
    BlockCheckPoint() = default;
    BlockCheckPoint(const BlockCheckPoint&) = delete;
    BlockCheckPoint& operator =(const BlockCheckPoint&) = delete;

    void Get(uint32_t& nHeight, uint256& hashblock)
    {
        std::lock_guard<std::mutex> guard(_mutex);
        nHeight = _nHeightCheckPoint;
        hashblock = _hashCheckPoint;
    }

    void Set(uint32_t nHeight, const uint256& hashblock)
    {
        std::lock_guard<std::mutex> guard(_mutex);
        _nHeightCheckPoint = nHeight;
        _hashCheckPoint = hashblock;
    }

private:
    std::mutex _mutex;
    uint32_t _nHeightCheckPoint = 0;
    uint256 _hashCheckPoint = 0;
};


class LatestHyperBlock {

public:
    static void Sync()
    {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        uint64 hid;
        T_SHA256 thhash;
        uint64 ctm;

        hyperchainspace->GetLatestHyperBlockIDAndHash(hid, thhash, ctm);
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            _hid = hid;
            _hhash = uint256S(thhash.toHexString());
        }
    }

    static void CompareAndUpdate(uint32_t hid, const T_SHA256& thhash, bool isLatest)
    {
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            if (isLatest || _hid < hid) {
                _hid = hid;
                _hhash = uint256S(thhash.toHexString());
            }
        }
    }

    static uint32_t GetHID(uint256* hhash = nullptr)
    {
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            if (hhash) {
                *hhash = _hhash;
            }
            return _hid;
        }
    }
private:
    static uint32_t _hid;
    static uint256 _hhash;
    static CCriticalSection _cs_latestHyperBlock;
};


typedef struct BackTrackingProgress
{
    int nLatestBlockHeight = 0;
    std::string strLatestBlockTripleAddr;
    int nBackTrackingBlockHeight = 0;
    std::string strBackTrackingBlockHash;

} BackTrackingProgress;

class LatestLedgerBlock
{

public:
    static void Load();
    static void CompareAndUpdate(const vector<T_PAYLOADADDR>& vecPA, bool isLatest);
    static void CompareAndUpdate(const vector<BLOCKTRIPLEADDRESS>& vecAddrIn, const vector<CBlock>& vecBlockIn, bool isLatest);

    static CBlockIndexSimplified* Get()
    {
        return _pindexLatest;
    }

    static int GetHeight()
    {
        return _nLatestLedgerHeight;
    }

    static uint256 GetBackSearchHash()
    {
        if (_pindexLatestRoot) {
            return *_pindexLatestRoot->phashBlock;
        }
        return 0;
    }

    static uint32 GetBackSearchHeight()
    {
        if (_pindexLatestRoot && _pindexLatestRoot->pnext && _pindexLatestRoot->pnext->nHeight >= 1) {
            return _pindexLatestRoot->pnext->nHeight - 1;
        }
        return 0;
    }

    static string GetMemoryInfo();

    //HC: try switch to _indexLatest
    static void Switch();
    static bool IsOnChain();
    static bool IsLackingBlock(std::function<void(const BackTrackingProgress&)> notiprogress);

    static bool Count(const uint256& hastblock);

    static void AddBlockTripleAddress(const uint256& hastblock, const BLOCKTRIPLEADDRESS& tripleaddr);

    static bool GetBlockTripleAddr(const uint256& hashblock, BLOCKTRIPLEADDRESS& tripleaddr);
    static bool GetBlock(const uint256& hastblock, CBlock& block, BLOCKTRIPLEADDRESS& tripleaddr);

private:

    static bool LoadLatestBlock(uint32& maxhid);
    static void SetBestIndex(CBlockIndexSimplified* pIndex)
    {
        _pindexLatest = pIndex;
        _nLatestLedgerHeight = _pindexLatest->nHeight;
    }

    static CBlockIndexSimplified* AddBlockIndex(const BLOCKTRIPLEADDRESS& addrIn, const CBlock& block);
    static CBlockIndexSimplified* InsertBlockIndex(uint256 hash);

    static void PullingPrevBlocks();

private:
    //HC: The latest block is contained by latest hyper block
    static CBlockIndexSimplified* _pindexLatest;
    static int  _nLatestLedgerHeight;

    static map<uint256, CBlockIndexSimplified*> _mapBlockIndexLatest;
    static CBlockDiskLocator _mapBlockAddressOnDisk;

    static CBlockIndexSimplified* _pindexLatestRoot;
};


extern BlockCheckPoint g_blockChckPnt;

class ChainReadyCondition
{
public:
    ChainReadyCondition() = default;
    ChainReadyCondition(const ChainReadyCondition&) = delete;
    ChainReadyCondition& operator =(const ChainReadyCondition&) = delete;

    void ProgressChanged(const BackTrackingProgress& progress) {
        _backTrackingProgress = progress;
        _eStatusCode = chainstatuscode::ChainIncomplete;
    }

    bool EvaluateIsAllowed(bool NeighborIsMust = true) {

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        CRITICAL_BLOCK_T_MAIN(cs_main)
            CRITICAL_BLOCK(_cs_chainstatus)
        {
            if (!hyperchainspace->IsLatestHyperBlockReady()) {
                _eStatusCode = chainstatuscode::HyperBlockNotReady;
                return false;
            }
            //else if (IsInitialBlockDownload()) {
            //    _reason += "Initial Block is downloading";
            //    return false;
            //}
            else if (g_cryptoToken.IsSysToken() || !g_cryptoToken.CheckGenesisBlock()) {
                _eStatusCode = chainstatuscode::InvalidGenesisBlock;
                return false;
            }

            //HC: if Latest hyper block has changed, process them.
            hyperblockMsgs.process();

            if (!LatestLedgerBlock::IsOnChain()) {
                auto f = std::bind(&ChainReadyCondition::ProgressChanged, this, std::placeholders::_1);
                if (!LatestLedgerBlock::IsLackingBlock(f)) {
                    //HC: Try to switch chain
                    _eStatusCode = chainstatuscode::Switching;
                    LatestLedgerBlock::Switch();
                }
                return false;
            }
            else if (NeighborIsMust && vNodes.empty()) {
                _eStatusCode = chainstatuscode::NoAnyNeighbor;
                return false;
            }

            string reason;
            if (IsTooFar(reason)) {
                return false;
            }
            _eStatusCode = chainstatuscode::Ready;
        }

        return true;
    }

    bool IsReady()
    {
        if (vnThreadsRunning[3] <= 0) {
            _eStatusCode = chainstatuscode::MonitorThreadExit;
            return false;
        }

        return  _eStatusCode > chainstatuscode::Switching;
    }

    string GetReadyStatus(bool* isAllowed) {

        if (isAllowed)
            *isAllowed = IsReady();

        return StatusCodeToReason();
    }

    int MiningStatusCode() const { return (int)(_eStatusCode); }
    bool IsBackTracking() const { return (_eStatusCode == chainstatuscode::ChainIncomplete); }
    bool IsSwitching() const { return (_eStatusCode == chainstatuscode::Switching); }

    BackTrackingProgress GetBackTrackingProcess() const { return _backTrackingProgress; }

private:
    bool IsTooFar(std::string& reason);

    string StatusCodeToReason()
    {
        string rs;

        if (_eStatusCode == chainstatuscode::ChainIncomplete) {
            return strprintf("The chain is incomplete, latest block height: %u(%s), backtracking block: %u(hash: %s)",
                _backTrackingProgress.nLatestBlockHeight, _backTrackingProgress.strLatestBlockTripleAddr.c_str(),
                _backTrackingProgress.nBackTrackingBlockHeight, _backTrackingProgress.strBackTrackingBlockHash.c_str());
        }

        if (_mapStatusDescription.count(_eStatusCode)) {
            return _mapStatusDescription.at(_eStatusCode);
        }

        return "";
    }

private:
    CCriticalSection _cs_chainstatus;

    enum class chainstatuscode : char {
        Ready = 1,
        ReadyWithWarning1 = 2,
        ReadyWithWarning2 = 3,
        ReadyWithWarning3 = 4,

        Switching = 0,

        Unready = -1,
        HyperBlockNotReady = -2,
        NoAnyNeighbor = -3,
        InvalidGenesisBlock = -4,
        MiningSettingClosed = -5,
        ManyBlocksNonChained = -6,
        ChainIncomplete = -7,
        MonitorThreadExit = -8,
    };

    chainstatuscode _eStatusCode = chainstatuscode::Unready;

    const map<chainstatuscode, string> _mapStatusDescription = {
        {chainstatuscode::Ready,               "Ready"},
        {chainstatuscode::ReadyWithWarning1,   "Warning: Seed server's block information is unknown"},
        {chainstatuscode::ReadyWithWarning2,   "Warning: Block height less than seed server's"},
        {chainstatuscode::ReadyWithWarning3,   "Warning: Block hash different from seed server's"},
        {chainstatuscode::Switching,           "Switching to the best chain"},
        {chainstatuscode::Unready,             "Unready"},
        {chainstatuscode::HyperBlockNotReady,  "My latest hyper block isn't ready"},
        {chainstatuscode::NoAnyNeighbor,       "No neighbor found"},
        {chainstatuscode::InvalidGenesisBlock, "Genesis block error"},
        {chainstatuscode::ManyBlocksNonChained,"More than 40 blocks is non-chained"},
        {chainstatuscode::ChainIncomplete,     "The chain is incomplete"},
        {chainstatuscode::MonitorThreadExit,   "Monitor thread has exited"},
    };

    BackTrackingProgress _backTrackingProgress;
};


class CBlockBloomFilter
{
public:
    CBlockBloomFilter();
    virtual ~CBlockBloomFilter() {};

    bool contain(const uint256& hashBlock)
    {
        return _filter.contain((char*)hashBlock.begin(), 32);
    }

    bool insert(const uint256& hashBlock)
    {
        _filter.insert((char*)hashBlock.begin(), 32);
        return true;
    }

    void clear()
    {
        _filter.clear();
    }

    CBlockBloomFilter& operator =(const CBlockBloomFilter& fl)
    {
        if (&fl == this) {
            return *this;
        }
        _filter = fl._filter;
        return *this;
    }

    CBlockBloomFilter& operator |(const CBlockBloomFilter& fl)
    {
        _filter | fl._filter;
        return *this;
    }


protected:
    BloomFilter _filter;
};

class CBlockCacheLocator
{
public:
    CBlockCacheLocator() {}
    ~CBlockCacheLocator() {}

    void setFilterReadCompleted();

    bool contain(const uint256& hashBlock);

    bool insert(const uint256& hashBlock)
    {
        return _filterBlock.insert(hashBlock);
    }

    bool insert(const uint256& hashBlock, const CBlock& blk);

    void clear();

    //HC: how to clean the bit flag?
    bool erase(const uint256& hashBlock);

    const CBlock& operator[](const uint256& hashBlock);

    std::future<CBlockBloomFilter> blk_bf_future;

private:
    const size_t _capacity = 200;
    CBlockBloomFilter _filterBlock;

    std::atomic_bool _filterCacheReadReady = false;

    bool _filterReady = false;

    std::map<uint256, CBlock> _mapBlock;
    std::map<int64, uint256> _mapTmJoined;
};

class CBlockDiskLocator
{
public:
    CBlockDiskLocator() {}
    ~CBlockDiskLocator() {}

    bool contain(const uint256& hashBlock);

    size_t size()
    {
        return _sizeInserted;
    }

    bool insert(CBlockTripleAddressDB& btadb, const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr);
    bool insert(const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr);
    bool insertBloomFilter(const uint256& hashBlock);

    void clear();

    //HC: how to clean the bit flag?
    bool erase(const uint256& hashBlock);

    const BLOCKTRIPLEADDRESS& operator[](const uint256& hashBlock);

private:

    const size_t _capacity = 3000;

    size_t _sizeInserted = 0;
    CBlockBloomFilter _filterBlock;

    std::map<uint256, BLOCKTRIPLEADDRESS> _mapBlockTripleAddr;
    std::map<int64, uint256> _mapTmJoined;

    std::set<uint256> _setRemoved;

};


