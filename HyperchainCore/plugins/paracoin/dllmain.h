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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "block.h"
#include "bignum.h"
#include "net.h"
#include "key.h"
#include "script.h"
#include "db.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "headers/inter_public.h"

#include "cryptocurrency.h"

#include <list>
#include <algorithm>
#include <unordered_map>


class CBlock;
class CBlockIndex;
class CWalletTx;
class CWallet;
class CKeyItem;
class CReserveKey;
class CWalletDB;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;
class CBlockIndexSimplified;
class CBlockBloomFilter;
class CBlockDiskLocator;

template<class T>
class shared_ptr_proxy;

using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;

template<class Storage>
class CCacheLocator;


#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif

extern CCriticalSection cs_main;
extern CCacheLocator<CTxDB_Wrapper> mapBlockIndex;
extern map<uint256, CBlockSP> mapOrphanBlocks;
extern uint256 hashGenesisBlock;
extern CBlockIndexSP pindexGenesisBlock;
extern int nBestHeight;
extern CBigNum bnBestChainWork;
extern CBigNum bnBestInvalidWork;
extern uint256 hashBestChain;
extern CBlockIndexSP pindexBest;

extern unsigned int nTransactionsUpdated;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern int fLimitProcessors;
extern int nLimitProcessors;
extern int fMinimizeToTray;
extern int fMinimizeOnClose;
extern int fUseUPnP;

extern std::atomic<uint32_t> g_nHeightCheckPoint;
extern std::atomic<uint256> g_hashCheckPoint;

class CBlockCacheLocator;
extern CBlockCacheLocator mapBlocks;

extern HyperBlockMsgs hyperblockMsgs;



class CReserveKey;
class CTxDB;
class CTxIndex;

void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
bool CheckDiskSpace(uint64 nAdditionalBytes = 0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode = "rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew = true);
bool LoadBlockUnChained();
void PrintBlockTree();
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
CBlock* CreateNewBlock(CReserveKey& reservekey, const char* pszAddress = NULL);

bool CommitGenesisToConsensus(CBlock* pblock, std::string& requestid, std::string& errmsg);
bool CommitChainToConsensus(deque<CBlock>& deqblock, string& requestid, string& errmsg);

void IncrementExtraNonce(CBlock* pblock, unsigned int& nExtraNonce);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
int GetTotalBlocksEstimate();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool ProcessBlock(CNode* pfrom, CBlock* pblock, T_LOCALBLOCKADDRESS* pblockaddr);
bool ProcessBlockWithTriaddr(CNode* pfrom, CBlock* pblock, BLOCKTRIPLEADDRESS* pblockaddr);

bool GetWalletFile(CWallet* pwallet, std::string& strWalletFileOut);
bool GetBlockData(const uint256& hashBlock, CBlock& block, BLOCKTRIPLEADDRESS& addrblock, char** pWhere);
void UpgradeBlockIndex(CTxDB_Wrapper& txdb, int height_util);
void FixBlockIndexByHyperBlock(CTxDB_Wrapper& txdb, int begin_height, int end_height);

bool CheckBlockTriAddr(const BLOCKTRIPLEADDRESS* pblktriaddr);

CBlockIndexSP LatestBlockIndexOnChained();

T_SHA256 to_T_SHA256(const uint256& uhash);
uint256 to_uint256(const T_SHA256& hash);

extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

template<typename T>
bool WriteSetting(const std::string& strKey, const T& value)
{
    bool fOk = false;
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
    {
        std::string strWalletFile;
        if (!GetWalletFile(pwallet, strWalletFile))
            continue;
        fOk |= CWalletDB_Wrapper(strWalletFile).WriteSetting(strKey, value);
    }
    return fOk;
}


template<typename... Args, typename Func>
void AOPInvokeOutputCost(Func&& f, Args&&... args)
{
    AOPInvokeWithCost([&](const char* funcname, int nCost) {
        if (nCost > 1000) {
            cout << StringFormat("%s: cost: %d\n",
                funcname, nCost);
        }
        }, [&]() {
            f(args...);
        });
}



/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash.
 */

class CEquihashInput : private CBlock
{
public:
    CEquihashInput(const CBlock& header)
    {
        CBlock::SetNull();
        *((CBlock*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nHeight);
        for (size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
            READWRITE(nReserved[i]);
        }

        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);
        READWRITE(hashExternData);
    )

};

class CBlockIndexSimplified;

using CBlockIndexSSP = std::shared_ptr<CBlockIndexSimplified>;

class CBlockIndexSimplified : public std::enable_shared_from_this<CBlockIndexSimplified>
{
public:
    uint256 hashBlock;  //HC: 块hash指针
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
        return hashBlock;
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndexSimplified: \n"
            "\tHeight=%d"
            "\tAddr=%s\n"
            "\thashBlock=%s ******\n",
            nHeight,
            addr.ToString().c_str(),
            hashBlock.ToString().c_str());
    }
};



//
// Used to marshal pointers into hashes for db storage.
//
//HC: Change implement of CDiskBlockIndex in order to improve the performance for CBlockIndex serialize
//HC: from CBlockIndex inherit child class to inner owner pointer
class CDiskBlockIndex
{
public:

    explicit CDiskBlockIndex(CBlockIndex* pindex) : _pblkindex(pindex)
    {
    }

    explicit CDiskBlockIndex() : _pblkindex(nullptr)
    {
    }


    CBlockIndex* GetBlockIndex()
    {
        return _pblkindex;
    }


    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(_pblkindex->nVersion);

        READWRITE(_pblkindex->hashNext);
        READWRITE(_pblkindex->nHeight);
        READWRITE(_pblkindex->bnChainWork);

        READWRITE(_pblkindex->triaddr);

        // block header

        READWRITE(_pblkindex->hashPrev);
        READWRITE(_pblkindex->hashMerkleRoot);

        READWRITE(_pblkindex->nTime);
        READWRITE(_pblkindex->nBits);
        READWRITE(_pblkindex->nNonce);
        READWRITE(_pblkindex->nSolution);
        READWRITE(_pblkindex->nPrevHID);
        READWRITE(_pblkindex->hashPrevHyperBlock);
        READWRITE(_pblkindex->hashExternData);

        READWRITE(_pblkindex->ownerNodeID.Lower64());
        READWRITE(_pblkindex->ownerNodeID.High64());
    )

    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion        = _pblkindex->nVersion;
        block.hashPrevBlock   = _pblkindex->hashPrev;
        block.hashMerkleRoot  = _pblkindex->hashMerkleRoot;
        block.nHeight         = _pblkindex->nHeight;

        block.nTime           = _pblkindex->nTime;
        block.nBits           = _pblkindex->nBits;
        block.nNonce          = _pblkindex->nNonce;
        block.nPrevHID        = _pblkindex->nPrevHID;
        block.nSolution       = _pblkindex->nSolution;
        block.hashPrevHyperBlock = _pblkindex->hashPrevHyperBlock;
        block.nNonce          = _pblkindex->nNonce;
        block.hashExternData = _pblkindex->hashExternData;

        return block.GetHash();
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += _pblkindex->ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            _pblkindex->hashPrev.ToString().substr(0, 20).c_str(),
            _pblkindex->hashNext.ToString().substr(0, 20).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

private:
    CBlockIndex* _pblkindex;

};


//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(CBlockIndexSP pindex)
    {
        Set(pindex);
    }


    explicit CBlockLocator(uint256 hashBlock);

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
    READWRITE(vHave);
    )

        void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(CBlockIndexSP pindex);

    //HC:
    void SetBrief(const CBlockIndexSP& pindex, const uint256& hashchk);

    int GetDistanceBack();

    CBlockIndexSP GetBlockIndex();

    uint256 GetBlockHash();

    int GetHeight()
    {
        CBlockIndexSP pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};



//
// Alerts are for notifying old versions if they become too obsolete and
// need to upgrade.  The message is displayed in the status bar.
// Alert messages are broadcast as a vector of signed data.  Unserializing may
// not read the entire buffer if the alert is for a newer version, but older
// versions can still relay the original data.
//
class CUnsignedAlert
{
public:
    int nVersion;
    int64 nRelayUntil;      // when newer nodes stop relaying to newer nodes
    int64 nExpiration;
    int nID;
    int nCancel;
    std::set<int> setCancel;
    int nMinVer;            // lowest version inclusive
    int nMaxVer;            // highest version inclusive
    std::set<std::string> setSubVer;  // empty matches all
    int nPriority;

    // Actions
    std::string strComment;
    std::string strStatusBar;
    std::string strReserved;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nRelayUntil);
        READWRITE(nExpiration);
        READWRITE(nID);
        READWRITE(nCancel);
        READWRITE(setCancel);
        READWRITE(nMinVer);
        READWRITE(nMaxVer);
        READWRITE(setSubVer);
        READWRITE(nPriority);

        READWRITE(strComment);
        READWRITE(strStatusBar);
        READWRITE(strReserved);
    )

    void SetNull()
    {
        nVersion = 1;
        nRelayUntil = 0;
        nExpiration = 0;
        nID = 0;
        nCancel = 0;
        setCancel.clear();
        nMinVer = 0;
        nMaxVer = 0;
        setSubVer.clear();
        nPriority = 0;

        strComment.clear();
        strStatusBar.clear();
        strReserved.clear();
    }

    std::string ToString() const
    {
        std::string strSetCancel;
        BOOST_FOREACH(int n, setCancel)
            strSetCancel += strprintf("%d ", n);
        std::string strSetSubVer;
        BOOST_FOREACH(std::string str, setSubVer)
            strSetSubVer += "\"" + str + "\" ";
        return strprintf(
            "CAlert(\n"
            "    nVersion     = %d\n"

            "    nRelayUntil  = %" PRI64d "\n"
            "    nExpiration  = %" PRI64d "\n"
            "    nID          = %d\n"
            "    nCancel      = %d\n"
            "    setCancel    = %s\n"
            "    nMinVer      = %d\n"
            "    nMaxVer      = %d\n"
            "    setSubVer    = %s\n"
            "    nPriority    = %d\n"
            "    strComment   = \"%s\"\n"
            "    strStatusBar = \"%s\"\n"
            ")\n",
            nVersion,
            nRelayUntil,
            nExpiration,
            nID,
            nCancel,
            strSetCancel.c_str(),
            nMinVer,
            nMaxVer,
            strSetSubVer.c_str(),
            nPriority,
            strComment.c_str(),
            strStatusBar.c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CAlert : public CUnsignedAlert
{
public:
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAlert()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
    READWRITE(vchSig);
    )

        void SetNull()
    {
        CUnsignedAlert::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (nExpiration == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsInEffect() const
    {
        return (GetAdjustedTime() < nExpiration);
    }

    bool Cancels(const CAlert& alert) const
    {
        if (!IsInEffect())
            return false; // this was a no-op before 31403
        return (alert.nID <= nCancel || setCancel.count(alert.nID));
    }

    bool AppliesTo(int nVersion, std::string strSubVerIn) const
    {
        return (IsInEffect() &&
            nMinVer <= nVersion && nVersion <= nMaxVer &&
            (setSubVer.empty() || setSubVer.count(strSubVerIn)));
    }

    bool AppliesToMe() const
    {
        return AppliesTo(VERSION, ::pszSubVer);
    }

    bool RelayTo(CNode* pnode) const
    {
        if (!IsInEffect())
            return false;
        // returns true if wasn't already contained in the set
        if (pnode->setKnown.insert(GetHash()).second)
        {
            if (AppliesTo(pnode->nVersion, pnode->strSubVer) ||
                AppliesToMe() ||
                GetAdjustedTime() < nRelayUntil)
            {
                pnode->PushMessage("alert", *this);
                return true;
            }
        }
        return false;
    }

    bool CheckSignature()
    {
        CPubKey key;
        std::vector<unsigned char> vec =
            ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        key.Set(vec.begin(), vec.end());
        if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
            return ERROR_FL("CAlert::CheckSignature() : verify signature failed");

        // Now unserialize the data
        CDataStream sMsg(vchMsg);
        sMsg >> *(CUnsignedAlert*)this;
        return true;
    }

    bool ProcessAlert();
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


typedef struct SyncingChainProgress
{
    string pullingInvnodeinfo;
    vector<string> vecPullingDatanode;
    int64_t pullingtm = 0;
    int nPullingRetry = 0;
    CInv pullinginvStart;
    CInv pullinginvEnd;
    int nGotNum;

    string ToString(int indentation) const
    {
        if (pullingtm == 0) {
            return "preparing";
        }
        string strindent;
        for (int i = 0; i < indentation; i++) {
            strindent += "\t";
        }

        string nodes;
        for (auto& n : vecPullingDatanode) {
            nodes += strprintf("%s\n%s\t\t", n.c_str(), strindent.c_str());
        }

        return strprintf("pulling inventory: %s [%d(%s)...%d(%s) got:%d] (%s, retry:%d)" "\n%s"
            "pulling data: %s", pullingInvnodeinfo.c_str(),
            pullinginvStart.height, pullinginvStart.hash.ToPreViewString().c_str(),
            pullinginvEnd.height, pullinginvEnd.hash.ToPreViewString().c_str(),
            nGotNum,
            time2string(pullingtm).c_str(), nPullingRetry,
            strindent.c_str(),
            nodes.c_str());
    }
} SyncingChainProgress;



class SeedServers;

class LatestParaBlock {

public:
    static void Load();
    static void CompareAndUpdate(const vector<BLOCKTRIPLEADDRESS>& vecAddrIn, const vector<CBlock>& vecBlockIn, bool isLatest);

    static CBlockIndexSSP Get()
    {
        return _pindexLatest;
    }

    static int GetHeight()
    {
        if (_pindexLatest)
            return _pindexLatest->nHeight;
        return 0;
    }

    static string GetMemoryInfo();

    static bool Count(const uint256& hastblock);

    static void AddBlockTripleAddress(const uint256& hastblock, const BLOCKTRIPLEADDRESS& tripleaddr);

    static bool GetBlockTripleAddr(const uint256& hashblock, BLOCKTRIPLEADDRESS& tripleaddr);
    static bool GetBlock(const uint256& hastblock, CBlock& block, BLOCKTRIPLEADDRESS& tripleaddr);

    static void PullingNextBlocks(std::function<void(const SyncingChainProgress&)> notiprogress);

private:
    LatestParaBlock(const LatestParaBlock&) = delete;
    LatestParaBlock& operator=(const LatestParaBlock&) = delete;

    static bool LoadLatestBlock(uint32& maxhid);

    static CBlockIndexSSP AddBlockIndex(const BLOCKTRIPLEADDRESS& addrIn, const CBlock& block);

    static void HandleBlock(const BLOCKTRIPLEADDRESS& addrIn, const CBlock& block);
private:
    //HC: The latest block is contained by latest hyper block
    static CBlockIndexSSP _pindexLatest;
    static CBlockDiskLocator _mapBlockAddressOnDisk;
};



class MiningCondition
{
public:
    MiningCondition() = default;
    MiningCondition(const MiningCondition&) = delete;
    MiningCondition& operator =(const MiningCondition&) = delete;

    void ProgressChanged(const BackTrackingProgress& progress) {
        _backTrackingProgress = progress;
        _eStatusCode = miningstatuscode::ChainIncomplete;
    }

    void SyncingProgressChanged(const SyncingChainProgress& progress)
    {
        _syncingChainProgress = progress;
        _eStatusCode = miningstatuscode::SyncingChain;
    }


    bool EvaluateIsAllowed(bool NeighborIsMust = true);

    bool IsMining()
    {
        if (vnThreadsRunning[3] <= 0) {
            _eStatusCode = miningstatuscode::MiningThreadExit;
            return false;
        }
        return  _eStatusCode > miningstatuscode::Switching;
    }

    string GetMiningStatus(bool* isAllowed) {

        if (isAllowed)
            *isAllowed = IsMining();

        return StatusCodeToReason();
    }

    int MiningStatusCode() const { return (int)(_eStatusCode); }
    bool IsBackTracking() const { return (_eStatusCode == miningstatuscode::ChainIncomplete); }
    bool IsSwitching() const { return (_eStatusCode == miningstatuscode::Switching); }

    BackTrackingProgress GetBackTrackingProcess() const { return _backTrackingProgress; }

private:
    //HC: check if my local Para chain data is different from seed server
    bool IsTooFar();

    string StatusCodeToReason()
    {
        string rs;

        if (_eStatusCode == miningstatuscode::SyncingChain) {
            rs = strprintf("%s \n%s \nSync details: \n\t%s", _mapStatusDescription.at(_eStatusCode).c_str(),
                _mapSSDescription.at(_eSSStatusCode).c_str(),
                _syncingChainProgress.ToString(1).c_str());
        }
        else if (_eStatusCode == miningstatuscode::ChainIncomplete) {
            rs = strprintf("The chain is incomplete, latest block height: %u(%s), backtracking block: %u(hash: %s)",
                _backTrackingProgress.nLatestBlockHeight, _backTrackingProgress.strLatestBlockTripleAddr.c_str(),
                _backTrackingProgress.nBackTrackingBlockHeight, _backTrackingProgress.strBackTrackingBlockHash.c_str());
        }
        else if (_mapStatusDescription.count(_eStatusCode)) {
            rs = _mapStatusDescription.at(_eStatusCode);
        }

        return rs;
    }

    friend class SeedServers;

    enum class seedserverstatuscode : char {
        chain_data_same = 0,
        seed_server_unknown = -1,
        height_too_less = -2,
        local_chain_fork = -3,
        non_seed_server = -4,
    };

public:
    enum class miningstatuscode : char {
        Mining = 2,
        ManyBlocksNonChained = 1,
        Switching = 0,

        GenDisabled = -1,
        HyperBlockNotReady = -2,
        NoAnyNeighbor = -3,
        InvalidGenesisBlock = -4,
        MiningSettingClosed = -5,
        ChainIncomplete = -6,
        SyncingChain = -7,
        MiningThreadExit = -8,
        UnloadWallet = -9,
        VersionLow = -10,
    };

    void SetMiningStatusCode(miningstatuscode code) {
        _eStatusCode = code;
    }

private:
    miningstatuscode _eStatusCode = miningstatuscode::GenDisabled;
    seedserverstatuscode _eSSStatusCode = seedserverstatuscode::seed_server_unknown;

    const map<miningstatuscode, string> _mapStatusDescription = {
        {miningstatuscode::Mining,              "Mining"},
        {miningstatuscode::Switching,           "Switching to the best chain"},
        {miningstatuscode::GenDisabled,         "Mining disabled, use command 'coin e' to enable"},
        {miningstatuscode::HyperBlockNotReady,  "My latest hyper block isn't ready"},
        {miningstatuscode::NoAnyNeighbor,       "No neighbor found"},
        {miningstatuscode::InvalidGenesisBlock, "Genesis block error"},
        {miningstatuscode::ManyBlocksNonChained, "Many blocks is non-chained"}, //"More than 40 blocks is non-chained"},
        {miningstatuscode::ChainIncomplete,     "The chain is incomplete"},
        {miningstatuscode::SyncingChain,        "Synchronizing chain data"},
        {miningstatuscode::MiningThreadExit,     "Mining thread has exited"},
        {miningstatuscode::UnloadWallet,         "Wallet unloaded"},
        {miningstatuscode::VersionLow,           "Mining stopped because version is too low"},
    };

    const map<seedserverstatuscode, string> _mapSSDescription = {
       {seedserverstatuscode::chain_data_same,       "Chain data is basically consistent with seed server"},
       {seedserverstatuscode::seed_server_unknown,  "Retrieving seed server's chain information"},
       {seedserverstatuscode::height_too_less,  "Warning: local block height less than seed server's"},
       {seedserverstatuscode::local_chain_fork,  "Warning: local chain is different from seed server's"},
       {seedserverstatuscode::non_seed_server,  "Warning: seed server is none"},
    };


    BackTrackingProgress _backTrackingProgress;
    SyncingChainProgress _syncingChainProgress;

};

typedef struct SSState
{
    ChkPoint chkp;
    bool online = false;
} SSState;

class SeedServers
{
public:
    SeedServers()
    { }

    void addServer(const string& ipaddr, int nPort);

    //HC: update seed server check point
    void updateSSCheckPoint(const CAddress& netaddr, const ChkPoint& cp);

    bool isSeedServer(const CAddress& netaddr);

    size_t size();

    bool checkData(MiningCondition::seedserverstatuscode& StatusCode);

    static bool getMyCheckPoint(ChkPoint& chkpoint);

    int containChain(const ChkPoint& cp);

    bool bestChain(CBlockLocatorEx** bestloc)
    {
        CRITICAL_BLOCK(_cs_seedserver)
        {
            auto best = bestServer();
            if (best != _mapserver.end()) {
                *bestloc = &(best->second.chkp.chainloc);
                return true;
            }
            return false;
        }
    }

    bool isBestServer(const CAddress& netaddr)
    {
        CRITICAL_BLOCK(_cs_seedserver)
        {
            auto best = bestServer();
            if (best != _mapserver.end()) {
                if (netaddr == best->first) {
                    return true;
                }
            }
            return false;
        }
    }

    void RefreshOnlineState()
    {
        CRITICAL_BLOCK(cs_vNodes)
            CRITICAL_BLOCK(_cs_seedserver)
        {
            for (auto& s : _mapserver) {
                s.second.online = false;
            }

            for (auto& node : vNodes) {
                if (_mapserver.count(node->addr)) {
                    _mapserver[node->addr].online = true;
                }
            }
        }
    }

private:
    map<CAddress, SSState>::iterator bestServer();

public:
    static int nBackBlockCount;

private:
    //HC: seed servers' check point
    map<CAddress, SSState> _mapserver;
    CCriticalSection _cs_seedserver;
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

    void clear();

    //HC: how to clean the bit flag?
    bool erase(const uint256& hashBlock);

    const BLOCKTRIPLEADDRESS& operator[](const uint256& hashBlock);

private:

    const size_t _capacity = 3000;

    size_t _sizeInserted = 0;
    std::map<uint256, BLOCKTRIPLEADDRESS> _mapBlockTripleAddr;
    std::map<int64, uint256> _mapTmJoined;

};

//HC: LRU policy
//T is non-pointer type
template<class Storage>
class CCacheLocator
{
public:
    using key_type = uint256;
    using v_value_type = CBlockIndexSP;
    using value_type = std::pair<const key_type, v_value_type>;
    using iterator = typename std::list<pair<key_type, v_value_type>>::iterator;

    iterator begin() { return _cacheDatas.begin(); }
    iterator end() { return _cacheDatas.end(); }

    size_t size() const noexcept { return _cacheDatas.size(); }
    bool empty() const { return _cacheDatas.empty(); }

    size_t capacity() const noexcept { return _capacity; }

    v_value_type fromcache(const key_type& hashT)
    {
        v_value_type t;

        CRITICAL_BLOCK(_mutex)
        {
            if (_mapLocator.count(hashT)) {
                t = _mapLocator.at(hashT)->second;
                _cacheDatas.push_back({ hashT, t });
                _cacheDatas.erase(_mapLocator.at(hashT));
                _mapLocator[hashT] = --_cacheDatas.end();
            }
        }
        return t;
    }

    size_t count(const key_type& hashT)
    {
        if (hashT == 0)
            return 0;

        CRITICAL_BLOCK(_mutex)
        {
            if (_mapLocator.count(hashT)) {
                return 1;
            }
        }

        //HC: Is it in storage?
        Storage db;
        CBlockIndex blkindex;
        CDiskBlockIndex diskindex(&blkindex);

        if (!db.ReadSP(hashT, diskindex)) {
            return 0;
        }

        //put it into cache
        db.GetPtr()->ConstructBlockIndex(hashT, diskindex);
        return 1;
    }

    inline
        bool insert(const value_type& value)
    {
        return insert(value, true);
    }

    //HC: Notice!!! don't access first of returning value(type std::pair), which maybe has changed, else it will cause crash
    //HC: Notice!!! don't access first of returning value(type std::pair), which maybe has changed, else it will cause crash
    //HC: Notice!!! don't access first of returning value(type std::pair), which maybe has changed, else it will cause crash
    bool insert(const value_type& value, bool newstorageelem)
    {
        const key_type& hashT = value.first;
        const v_value_type& t = value.second;

        CRITICAL_BLOCK(_mutex)
        {
            if (newstorageelem) {
                Storage db;
                //HC: only for debug
                if (db.GetPtr()->GetTxn() != NULL) {
                    cerr << "Debug: Error occured, here why not null\n";
                }
                if (!db.WriteSP(t.get())) {
                    ERROR_FL("%s : WriteSP failed", __FUNCTION__);
                    return false;
                }
            }
            return put_new(hashT, t);
        }
        return false;
    }

    std::size_t erase(const key_type& hashT)
    {
        CRITICAL_BLOCK(_mutex)
        {
            if (_mapLocator.count(hashT)) {
                auto v = _mapLocator.at(hashT);
                _cacheDatas.erase(v);
                return _mapLocator.erase(hashT);
            }
        }
        return 0;
    }

    void clear()
    {
        CRITICAL_BLOCK(_mutex)
        {
            _mapLocator.clear();
            _cacheDatas.clear();
        }
    }

    v_value_type operator[](const key_type& hashT)
    {
        v_value_type t;
        t = fromcache(hashT);
        if (t) {
            return t;
        }

        Storage db;

        if (hashT != 0) {
            CBlockIndex blkindex;
            CDiskBlockIndex diskindex(&blkindex);
            if (!db.ReadSP(hashT, diskindex)) {
                TRACE_FL("Failed to Read : %s", hashT.ToPreViewString().c_str());
                return t;
            }

            //HC: put it into cache
            db.GetPtr()->ConstructBlockIndex(hashT, diskindex);
            //HC: must return a index in block index cache
            return fromcache(hashT);
        }
        return t;
    }

    v_value_type get(const key_type& hashT, Storage& db)
    {
        v_value_type t;
        t = fromcache(hashT);
        if (t) {
            return t;
        }

        if (hashT != 0) {
            CBlockIndex blkindex;
            CDiskBlockIndex diskindex(&blkindex);
            if (!db.ReadSP(hashT, diskindex)) {
                TRACE_FL("Failed to Read : %s", hashT.ToPreViewString().c_str());
                return t;
            }

            //HC: put it into cache
            db.GetPtr()->ConstructBlockIndex(hashT, diskindex);
            //HC: must return a index in block index cache
            return fromcache(hashT);
        }
        return t;
    }

private:
    const size_t _capacity = 20000;

    std::list<pair<key_type, v_value_type>> _cacheDatas;

    class KeyHash
    {
    public:
        std::size_t operator()(const key_type& c) const
        {
            return c.GetLow64();
        }
    };

    class KeyEqual
    {
    public:
        bool operator()(const key_type& c1, const key_type& c2) const
        {
            return c1 == c2;
        }
    };

    std::unordered_map<key_type, iterator, KeyHash, KeyEqual> _mapLocator;
    CCriticalSection _mutex;


private:

    bool put_new(const key_type& hashT, const v_value_type& t)
    {
        //Limit the memory capacity
        if (_cacheDatas.size() > _capacity) {
            _mapLocator.erase(_cacheDatas.begin()->first);
            _cacheDatas.pop_front();
        }

        _cacheDatas.push_back({ hashT, t });
        //std::pair<std::unordered_map<key_type, iterator, KeyHash, KeyEqual>::iterator, bool> ret = _mapLocator.insert({ hashT, --_cacheDatas.end() });
        bool ret = _mapLocator.insert({ hashT, --_cacheDatas.end() }).second;


        if (!ret) {
            _cacheDatas.erase(--_cacheDatas.end());
            return false;
        }

        return true;
    }
};

class ParaMQCenter
{
public:
    void start()
    {
        startMQHandler();
        _isStarted = true;
    }

    void stop()
    {
        MTC_Save();

        _msghandler.stop();
        _isStarted = false;
    }

    std::string MQID()
    {
        return _msghandler.details();
    }

    MsgHandler& GetMsgHandler() { return _msghandler; }
    CBlockLocatorEx& GetMTC() { return _maintrunkchain; }

    //HC: Notice: set and at the same time return hash of check point
    void MTC_Set(uint256& hashchk);
    void MTC_Save();
    bool MTC_Have(const CBlockIndexSP& pindex);
    CBlockLocatorEx::ForkIndex MTC_FindForkIndex(const CBlockLocatorEx& blkloc, uint256& hashfork);
    bool MTC_GetRange(int nBlkHeight, uint256& hashbegin, uint256& hashEnd);

    void MTC_ComputeDiff(const uint256& hash_end_vhave, const uint256& hash_end_vhavetail, CBlockLocatorExIncr& incr);

    int MTC_GetChkPoint(uint256& hashchkp);

    int MTC_GetChain(vector<uint256>& chains);

    bool MTC_IsInMain(int nheight, const uint256& hash);
    std::string MTC_ToString(int idx);
    std::string MTC_ToDetailString(int idx, int idxTail);


private:
    enum class SERVICE : short
    {
        //MainTrunkChain
        MTC_Set = 1,
        MTC_Have,
        MTC_Save,
        MTC_GetRange,
        MTC_FindForkIndex,
        MTC_ComputeDiff,
        MTC_GetChkPoint,
        MTC_IsInMain,
        MTC_ToString,
        MTC_ToDetailString,
        MTC_GetChain,
    };

    MsgHandler _msghandler;

    CBlockLocatorEx _maintrunkchain;
    bool _isStarted = false;


private:

    void startMQHandler();
    void DispatchService(void* wrk, zmsg* msg);
};

extern SeedServers g_seedserver;

#endif
