/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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

#include "cryptopp/sha.h"
#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"
#include "node/NodeManager.h"


#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "ledgermain.h"
#include "cryptotoken.h"
#include "latestledgerblock.h"
#include "ledger_rpc.h"
#include "plshared.h"

#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/fiber/all.hpp>


using namespace std;
using namespace boost;

boost::fibers::mutex g_fibermtx;

#define FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(t) \
    std::lock_guard<boost::fibers::mutex> lk(g_fibermtx); \
    CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__); \
    while (!criticalblock.TryEnter(__FILE__, __LINE__)) { \
        boost::this_fiber::sleep_for(std::chrono::milliseconds(t)); \
    }

extern CBlockCacheLocator mapBlocks;
extern ChainReadyCondition g_chainReadyCond;

extern HyperBlockMsgs hyperblockMsgs;

bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);
extern bool CommitToConsensus(CBlock* pblock, string& requestid, string& errmsg);
extern void ProcessOrphanBlocks(const uint256& hash);
extern CBlockIndex* LatestBlockIndexOnChained();
extern void CreateNewChain();

typedef struct tagConsensusBlock
{
    CBlock* block = nullptr;
    uint256 hash = { 0 };

    tagConsensusBlock(CBlock* b) : block(b)
    {
        hash = block->GetHash();
    }
} ConsensusBlock;

CAddress g_seedserver;
std::mutex g_muxConsensusBlock;
std::shared_ptr<ConsensusBlock> g_spConsensusBlock;

PBFT g_PBFT;

bool IsGenesisBlock(const T_APPTYPE& t)
{
    uint32_t hid = 0;
    uint16 chainnum = 0;
    uint16 localid = 0;
    t.get(hid, chainnum, localid);

    if (hid == 0 && chainnum == 0 && localid == 0) {
        //genesis block
        return true;
    }
    return false;
}


std::map<uint32_t, time_t> mapPullingHyperBlock;
CCriticalSection cs_pullingHyperBlock;
void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "")
{
    CRITICAL_BLOCK(cs_pullingHyperBlock)
    {
        time_t now = time(nullptr);
        if (mapPullingHyperBlock.count(hid) == 0) {
            mapPullingHyperBlock.insert({ hid, now });
        }
        else {
            if (now - mapPullingHyperBlock[hid] < 20) {

                return;
            }
            else {
                mapPullingHyperBlock[hid] = now;
            }
        }
        auto bg = mapPullingHyperBlock.begin();
        for (; bg != mapPullingHyperBlock.end();) {
            if (bg->second + 300 < now) {
                bg = mapPullingHyperBlock.erase(bg);
            }
            else {
                ++bg;
            }
        }
    }
    std::thread t([hid, nodeid]() {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        if (hyperchainspace) {
            if (nodeid.empty()) {
                hyperchainspace->GetRemoteHyperBlockByID(hid);
                INFO_FL("GetRemoteHyperBlockByID: %d", hid);
            }
            else {
                hyperchainspace->GetRemoteHyperBlockByID(hid, nodeid);
                INFO_FL("GetRemoteHyperBlockByID: %d, from node: %s", hid, nodeid.c_str());
            }
        }
    });
    t.detach();
}

bool UpdateAppAddress(const CBlock& genesisblock, const T_LOCALBLOCKADDRESS& addr)
{
    CryptoToken cryptoToken(false);
    cryptoToken.ParseToken(genesisblock);

    CryptoToken cryptoTokenFromLocal(false);
    cryptoTokenFromLocal.SetName(cryptoToken.GetName());

    string tokenhash = cryptoToken.GetHashPrefixOfGenesis();
    string errmsg;
    if (!cryptoTokenFromLocal.ReadTokenFile(cryptoToken.GetName(), tokenhash, errmsg)) {

        return WARNING_FL("%s", errmsg.c_str());
    }

    uint256 hash = genesisblock.GetHash();
    if (cryptoTokenFromLocal.GetHashGenesisBlock() == hash) {
        if (!cryptoTokenFromLocal.SetGenesisAddr(addr.hid, addr.chainnum, addr.id)) {
            ERROR_FL("SetGenesisAddr failed");
        }
    }
    return true;
}

bool IsMyBlock(const T_APPTYPE& t)
{
    uint32_t hid = 0;
    uint16 chainnum = 0;
    uint16 localid = 0;
    t.get(hid, chainnum, localid);

    if (hid != g_cryptoToken.GetHID() ||
        chainnum != g_cryptoToken.GetChainNum() ||
        localid != g_cryptoToken.GetLocalID()) {
        return false;
    }

    return true;
}

bool HandleGenesisBlockCb(vector<T_PAYLOADADDR>& vecPA)
{
    for (auto& b : vecPA) {

        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        UpdateAppAddress(block, b.addr);
    }
    return true;
}


bool PutTxsChainCb()
{
    if (!g_chainReadyCond.IsReady())
        return false;

    std::lock_guard<std::mutex> lck(g_muxConsensusBlock);
    if (g_spConsensusBlock) {

        return false;
    }


    CReserveKey reservekey(pwalletMain);
    CBlock* pBlock = CreateNewBlock(reservekey);
    if (!pBlock) {
        //no transactions need to commit
        return false;
    }

    std::shared_ptr<ConsensusBlock> spBlock(new ConsensusBlock(pBlock),
        [](ConsensusBlock* p) {
        delete p->block;
        delete p;
    });

    if (spBlock && spBlock->block->vtx.size() >= 1) {
        string requestid, errmsg;
        if (!CommitToConsensus(spBlock.get()->block, requestid, errmsg)) {
            return ERROR_FL("CommitToConsensus() Error: %s", errmsg.c_str());
        }
        g_spConsensusBlock = spBlock;
        return true;
    }
    return false;
}

bool GetNeighborNodes(list<string>& listNodes)
{
    CRITICAL_BLOCK(cs_vNodes)
        for (auto& n : vNodes) {
            listNodes.push_back(n->nodeid);
        }
    return true;
}


bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    return true;
}

bool SwitchChainTo(CBlockIndex *pindexBlock)
{
    CBlock block;
    if (!block.ReadFromDisk(pindexBlock)) {
        return ERROR_FL("Failed to Read Ledger block: %s", pindexBlock->addr.tostring().c_str());
    }

    CTxDB_Wrapper txdb;
    block.SetBestChain(txdb, pindexBlock);

    INFO_FL("Switch to: %d,hid:%d,%s, %s, BestIndex: %d hid:%d,%s, %s LastHID: %u", pindexBlock->Height(),
        pindexBlock->nPrevHID,
        pindexBlock->addr.tostring().c_str(),
        pindexBlock->GetBlockHash().ToPreViewString().c_str(),
        pindexBest->Height(), pindexBest->nPrevHID,
        pindexBest->addr.tostring().c_str(),
        pindexBest->GetBlockHash().ToPreViewString().c_str(),
        LatestHyperBlock::GetHID());

    ProcessOrphanBlocks(pindexBlock->GetBlockHash());
    return true;
}

bool AcceptBlocks(vector<T_PAYLOADADDR>& vecPA, bool isLatest)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<CBlock> vecBlock;
    vector<BLOCKTRIPLEADDRESS> vecBlockAddr;
    for (auto b : vecPA) {
        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
        vecBlockAddr.push_back(b.addr);
    }

    LatestLedgerBlock::CompareAndUpdate(vecBlockAddr,vecBlock, isLatest);
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (ProcessBlockFromAcceptedHyperBlock(&vecBlock[i], &vecPA[i].addr)) {
            uint256 hash = vecBlock[i].GetHash();
            TRACE_FL("AcceptBlocks() : (%s) %s is accepted\n\n", vecPA[i].addr.tostring().c_str(),
                hash.ToString().substr(0, 20).c_str());
        }
        else {
            WARNING_FL("(%s) cannot be accepted\n", vecPA[i].addr.tostring().c_str());
        }
    }


    auto& lastblock = vecBlock.back();
    uint32_t hid = lastblock.nPrevHID;
    uint256 hash = lastblock.GetHash();

    CBlockIndex *pindexLast;
    if (!mapBlockIndex.count(hash)) {
        return false;
    }

    pindexLast = mapBlockIndex[hash];


    bool bchainSwitch = true;
    if (pindexBest->nPrevHID > hid && !isLatest) {
        CBlockIndex *pfork = pindexBest;
        if (pindexBest->nHeight >= pindexLast->nHeight) {
            uint32 nHeight = pindexLast->nHeight;
            while (pfork->nHeight > nHeight)
                if (!(pfork = pfork->pprev))
                    break;

            if (pfork == pindexLast) {
                bchainSwitch = false;
            }
        }
    }

    if (bchainSwitch && g_chainReadyCond.IsReady()) {
        SwitchChainTo(pindexLast);
    }

    return true;
}

extern HyperBlockMsgs hyperblockMsgs;

bool AcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    CHAINCBDATA cbdata(mapPayload, hidFork, hid, thhash, isLatest);
    hyperblockMsgs.insert(std::move(cbdata));
    return true;
}


bool ProcessChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    //CSpentTime spentt;
    //defer {
    //    cout << strprintf("Para ProcessChainCb spent million seconds : %ld\n", spentt.Elapse());
    //};


    LatestHyperBlock::CompareAndUpdate(hid, thhash, isLatest);
    T_APPTYPE meApp(APPTYPE::ledger, g_cryptoToken.GetHID(),
                                     g_cryptoToken.GetChainNum(),
                                     g_cryptoToken.GetLocalID());
    if (mapPayload.count(meApp)) {
        vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
        return AcceptBlocks(vecPA, isLatest);
    }

    if (isLatest) {

        CBlockIndex* pStart = pindexBest;
        while (pStart && pStart->nPrevHID >= hidFork) {
            pStart = pStart->pprev;
        }

        if (!pStart) {
            pStart = pindexGenesisBlock;
        }

        pStart = pStart->pnext;
        if (!pStart) {
            return true;
        }



        uint256 hhash(thhash.toHexString());
        CBlockIndex *pEnd = pStart;
        while (pEnd && pEnd->nPrevHID == hid && pEnd->hashPrevHyperBlock == hhash) {
            pEnd = pEnd->pnext;
        }

        if (pEnd) {
            auto spprev = pEnd->pprev;
            if (spprev) {
                SwitchChainTo(spprev);
            }
        }
    }

    //vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
    //if (vecPA.size() == 0) {
    //    return false;
    //}
    //vector<CBlock> vecBlock;

    //for (auto b : vecPA) {
    //    CBlock block;
    //    if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
    //        return ERROR_FL("ResolveBlock FAILED");
    //    }
    //    vecBlock.push_back(std::move(block));
    //}

    //CRITICAL_BLOCK(cs_main)
    //{
    //    for (size_t i = 0; i < vecBlock.size(); i++) {
    //        if (vecBlock[i].AcceptBlock(vecPA[i].addr)) {
    //            uint256 hash = vecBlock[i].GetHash();
    //            printf("LedgerAcceptChainCb() : (%s) %s is accepted\n", vecPA[i].addr.tostring().c_str(),
    //                hash.ToString().substr(0, 20).c_str());
    //        }
    //        else {
    //            return ERROR_FL("(%s) cannot be accepted", vecPA[i].addr.tostring().c_str());
    //        }
    //    }
    //}

    //{
    //    std::lock_guard<std::mutex> lck(g_muxConsensusBlock);
    //    if (g_spConsensusBlock) {
    //        for (auto& elm : vecBlock) {
    //            if (elm.GetHash() == g_spConsensusBlock->hash) {
    //                //BOOST_FOREACH(CTransaction& tx, g_spConsensusBlock->block->vtx)
    //                //    tx.RemoveFromMemoryPool();

    //                g_spConsensusBlock = nullptr;
    //                break;
    //            }
    //        }
    //    }
    //}


    //PutTxsChainCb();

    return true;
}


void HyperBlockMsgs::insert(CHAINCBDATA&& cb)
{
    CRITICAL_BLOCK(m_cs_list)
    {
        m_list.push_back(std::move(cb));
    }
}

void HyperBlockMsgs::process()
{
    CRITICAL_BLOCK(m_cs_list)
    {
        auto it = m_list.begin();
        for (; it != m_list.end(); ) {
            ProcessChainCb(it->m_mapPayload, it->m_hidFork, it->m_hid, it->m_thhash, it->m_isLatest);
            m_list.erase(it++);
        }
    }
}

namespace boost {
    bool operator<(const boost::any& _Left, const boost::any& _Right)
    {
        if (_Left.type() != _Right.type())
            throw logic_error("type error");
        if (_Left.type() == typeid(COutPoint)) {
            return any_cast<COutPoint>(_Left) < any_cast<COutPoint>(_Right);
        }
        throw logic_error("unimplemented");
    }
}



bool ValidateDataCb(T_PAYLOADADDR& payloadaddr,
    map<boost::any, T_LOCALBLOCKADDRESS>& mapOutPt,
    boost::any& hashPrevBlock)
{
    CBlock block;
    if (!ResolveBlock(block, payloadaddr.payload.c_str(), payloadaddr.payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }
    if (hashPrevBlock.empty()) {
        hashPrevBlock = block.hashPrevBlock;
    }
    else if (block.hashPrevBlock != any_cast<uint256>(hashPrevBlock)) {
        return ERROR_FL("hashPrevBlock is different");
    }

    // Preliminary checks
    if (!block.CheckBlock())
        return ERROR_FL("CheckBlock FAILED");

    if (!block.CheckTrans())
        return ERROR_FL("CheckTrans FAILED");


    for (auto tx : block.vtx) {
        if (tx.IsCoinBase()) {
            continue;
        }
        for (auto vin : tx.vin) {
            if (mapOutPt.count(vin.prevout)) {
                return ERROR_FL("localblock %s confilicts with localblock %s,try to take over the same tx.",
                    payloadaddr.addr.tostring().c_str(),
                    mapOutPt[vin.prevout].tostring().c_str());
            }
            else {
                mapOutPt.insert(std::make_pair(vin.prevout, payloadaddr.addr));
            }
        }
    }

    return true;
}

bool UpdateDataCb(string& payload, string& newpaylod)
{
    CBlock block;
    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    CBlockIndex* pindexPrev = pindexBest;
    if (block.hashPrevBlock == pindexBest->GetBlockHash()) {
        //don't need update.
        return false;
    }

    block.hashPrevBlock = pindexPrev->GetBlockHash();
    //block.nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    CDataStream datastream(SER_BUDDYCONSENSUS);
    try {
        datastream << block;
        newpaylod = datastream.str();
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Cannot extract ledger block data, %s\n", e.what());
    }
    return true;
}

bool IsProducingNode()
{
    if (vNodes.size() < 1) {
        return false;
    }


    if(!g_cryptoToken.AmIConsensusNode()) {
        return false;
    }

    CBlockIndex* pStart = LatestBlockIndexOnChained();

    uint256 hashblk = pStart->GetBlockHash();

    static uint256 hashMyNodeID = 0;
    if (hashMyNodeID == 0) {
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

        string nodeid = nodemgr->getMyNodeId<string>();
        hashMyNodeID = Hash(nodeid.begin(), nodeid.end());
    }



    uint256 hhash;
    LatestHyperBlock::GetHID(&hhash);


    std::time_t t = std::time(nullptr);
    char mbstr[64] = {0};

    tm now = *std::gmtime(&t);
    now.tm_min = now.tm_min / 10 * 10;
    std::strftime(mbstr, sizeof(mbstr), "%Y%m%d %H%M", &now);
    auto hashtm = Hash(mbstr, mbstr+64);

    uint256 ndistance = hashblk ^ hashMyNodeID ^ hhash ^ hashtm;
    for (auto &n : vNodes) {
        if(n->nPKeyIdx < 0)
            continue;
        auto h = Hash(n->nodeid.begin(), n->nodeid.end());
        uint256 ndist = hashblk ^ h ^ hhash ^ hashtm;
        if (ndist < ndistance) {
            return false;
        }
    }
    return true;
}

PBFT::PBFT()
{
}

PBFT::~PBFT()
{
}

void PBFT::Init()
{
    _n = g_cryptoToken.GetNumbersOfConsensusNodes();
    _f = (_n - 1) / 3;
}

bool PBFT::Preprepare(vector<CBlock>&& vblk)
{
    _vblock = std::move(vblk);
    _s_verified.clear();

    vector<unsigned char> vchSig;
    if (!g_cryptoToken.SignBlocks(_vblock, vchSig)) {
        ERROR_FL("Failed to SignBlocks\n", __FUNCTION__);
        return false;
    }

    DEBUG_FL("Call %s to send blocks to consensus nodes\n", __FUNCTION__);

    CRITICAL_BLOCK(cs_vNodes)
    {
        for (auto& node : vNodes) {
            if (node->IsPBFTSealer()) {
                node->PushMessage("PBFTPP", _vblock, vchSig);
            }
        }
    }

    _waitforcommit = true;
    return true;
}

bool PBFT::Prepare(int pkidx, const vector<unsigned char>& vchSig)
{
    if (_s_verified.count(pkidx)) {
        return true;
    }

    DEBUG_FL("Received sign from Idx: %d\n", pkidx);

    if (!g_cryptoToken.VerifyBlocks(pkidx, vchSig, _vblock)) {
        ERROR_FL("Failed to VerifyBlocks in %s\n", __FUNCTION__);
        return false;
    }

    _s_verified.insert(pkidx);
    return true;
}

bool PBFT::Commit()
{
    if (!_waitforcommit) {
        return false;
    }

    _waitforcommit = false;
    auto nblk = _vblock.size();
    if (nblk < 2) {
        return false;
    }

    if (!IsSignEnough()) {
        DEBUG_FL("Verified signs aren't enough(verified: %u, f: %u, n: %u). %s\n", _s_verified.size(), _f, _n, __FUNCTION__);
        return false;
    }

    if (pindexBest->GetBlockHash() != _vblock[nblk-1].GetHash()) {
        DEBUG_FL("pindexBest changed, cannot commit blocks. %s\n", __FUNCTION__);
        return false;
    }

    CBlockIndex *pStart = LatestBlockIndexOnChained();
    pStart = pStart->pnext;
    if (!pStart) {
        DEBUG_FL("no any block need to commit. %s\n", __FUNCTION__);
        return false;
    }

    if (pStart->GetBlockHash() != _vblock[0].GetHash()) {
        DEBUG_FL("Chain has changed, cannot commit blocks. %s\n", __FUNCTION__);
        return false;
    }

    string requestid, errmsg;
    if (!CommitChainToConsensus(_vblock, requestid, errmsg)) {
        ERROR_FL("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

    _s_verified.clear();
    return true;
}



bool PutBlockCb()
{
    vector<CBlock> vblock;
    uint256 hhash;

    bool isSwithBestToValid = false;
    CBlockIndex* pindexValidStarting = nullptr;


    if (!fGenerateBitcoins)
        return false;

    if (!g_chainReadyCond.IsReady()) {
        return false;
    }

    DEBUG_FL("Prepare to create blocks\n");
    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {

        hyperblockMsgs.process();

        if (!LatestLedgerBlock::IsOnChain()) {
            CBlockIndexSimplified* pIndex = LatestLedgerBlock::Get();
            if (pIndex) {
                WARNING_FL("Best chain is behind, cannot commit Ledger block onto chain, should be height: %u", pIndex->nHeight);
            }
            return false;
        }

        if (!IsProducingNode())
            return false;


        CBlockIndex* pStart = LatestBlockIndexOnChained();
        SwitchChainTo(pStart);

        DEBUG_FL("I will generate blocks, Call CreateNewChain\n");
        CreateNewChain();

        uint64 nHID = LatestHyperBlock::GetHID(&hhash);
        pStart = LatestBlockIndexOnChained();
        pStart = pStart->pnext;
        if (!pStart) {

            return false;
        }


        CBlockIndex* pEnd = pStart;
        while (pEnd && pEnd->nPrevHID == nHID && pEnd->hashPrevHyperBlock == hhash) {
            if (!mapBlocks.contain(pEnd->GetBlockHash())) {
                break;
            }
            vblock.push_back(mapBlocks[pEnd->GetBlockHash()]);
            pEnd = pEnd->pnext;
        }

        if (vblock.size() < 2) {

            isSwithBestToValid = true;
            pindexValidStarting = pStart->pprev;
        }


        if (isSwithBestToValid) {
            for (; pindexValidStarting; pindexValidStarting = pindexValidStarting->pprev) {
                if (SwitchChainTo(pindexValidStarting))
                    break;
            }
            return false;
        }
        return g_PBFT.Preprepare(std::move(vblock));
    }
    return false;
}


bool PutChainCb()
{

    if (!fGenerateBitcoins)
        return false;

    if (!g_chainReadyCond.IsReady()) {
        return false;
    }

    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {

        hyperblockMsgs.process();
        g_PBFT.Commit();
    }

    return true;
}


bool BlockUUIDCb(string& payload, string& uuidpayload)
{


    uuidpayload = payload.substr(0, sizeof(int));

    uuidpayload += payload.substr(sizeof(int) + sizeof(uint256));
    return true;
}



/*
void checkLedger()
{
    vector<uint256> vWorkQueue;
    CDataStream vMsg(vRecv);
    CTransaction tx;
    vRecv >> tx;

    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    bool fMissingInputs = false;
    if (tx.AcceptToMemoryPool(true, &fMissingInputs))
    {
        SyncWithWallets(tx, NULL, true);
        mapAlreadyAskedFor.erase(inv);
        vWorkQueue.push_back(inv.hash);

        // Recursively process any orphan transactions that depended on this one
        for (int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hashPrev = vWorkQueue[i];
            for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                ++mi)
            {
                const CDataStream& vMsg = *((*mi).second);
                CTransaction tx;
                CDataStream(vMsg) >> tx;
                CInv inv(MSG_TX, tx.GetHash());

                if (tx.AcceptToMemoryPool(true))
                {
                    printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
                    SyncWithWallets(tx, NULL, true);
                    RelayMessage(inv, vMsg);
                    mapAlreadyAskedFor.erase(inv);
                    vWorkQueue.push_back(inv.hash);
                }
            }
        }

        BOOST_FOREACH(uint256 hash, vWorkQueue)
            EraseOrphanTx(hash);
    }
    else if (fMissingInputs)
    {
        printf("storing orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
        AddOrphanTx(vMsg);
    }
}
*/

std::function<void(int)> SleepFn = [](int sleepseconds) {
    int i = 0;
    int maxtimes = sleepseconds * 1000 / 200;
    while (i++ < maxtimes) {
        if (fShutdown) {
            break;
        }
        Sleep(200);
    }
};

#define one_hour 60 * 60
void ThreadBlockPool(void* parg)
{

    while (!fShutdown) {

        SleepFn(one_hour);
        if (fShutdown) {
            break;
        }

        INFO_FL("Removing expired blocks in the block pool\n");

        std::vector<uint256> vWillBeRemoved;
        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            CSpentTime spentt;
            CBlockDB_Wrapper blockdb;



            blockdb.LoadBlockUnChained(uint256(0), [&vWillBeRemoved, &spentt](CDataStream& ssKey, CDataStream& ssValue) -> bool {

                CBlock block;
                ssValue >> block;

                uint256 hash;
                ssKey >> hash;


                if (block.nHeight + 5000 < pindexBest->nHeight && mapBlockIndex.count(hash)) {
                    auto p = mapBlockIndex[hash];
                    if (p->addr.isValid()) {
                        CBlock blk;
                        if (blk.ReadFromDisk(pindexBest->addr)) {
                            vWillBeRemoved.push_back(hash);
                            return true;
                        }
                    }
                }
                if (spentt.Elapse() > 10) {

                    return false;
                }
                return true;
            } );


            for (auto& elm: vWillBeRemoved) {
                blockdb.EraseBlock(elm);
            }
        }
        INFO_FL("Removed %d expired blocks in the block pool\n", vWillBeRemoved.size());
    }
}

void UpdateMaxBlockAddr(const T_LOCALBLOCKADDRESS& addr)
{
    if (addrMaxChain < addr) {
        addrMaxChain = addr;
        CTxDB_Wrapper txdb;
        if (!txdb.WriteAddrMaxChain(addrMaxChain)) {
            ERROR_FL("WriteAddrMaxChain failed");
        }
    }
}


void ThreadGetNeighbourChkBlockInfo(void* parg)
{
    time_t tbest = 0;
    int nRequestingNodes = 0;

    while (!fShutdown) {

        CRITICAL_BLOCK(cs_vNodes)
        {
            nRequestingNodes = 0;
            for (auto& node : vNodes) {
                if (g_seedserver.IsValid() && node->addr == g_seedserver) {
                    node->GetChkBlock();
                    g_blockChckPnt.Set(node->nHeightCheckPointBlock, node->hashCheckPointBlock);
                }
                else {
                    node->GetChkBlock();
                }
            }
        }

        SleepFn(60);
    }
}

void ThreadRSyncGetBlock(void* parg)
{
    while (!fShutdown) {
        time_t now = time(nullptr);
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        CRITICAL_BLOCK(cs_pullingHyperBlock)
        {
            auto bg = mapPullingHyperBlock.begin();
            for (; bg != mapPullingHyperBlock.end();) {
                if (bg->second + 120 < now) {
                    T_HYPERBLOCK h;
                    if (hyperchainspace->getHyperBlock(bg->first, h)) {
                        bg = mapPullingHyperBlock.erase(bg);
                    }
                    else {
                        hyperchainspace->GetRemoteHyperBlockByID(bg->first);
                        bg->second = now;
                    }
                }
                else {
                    ++bg;
                }
            }
        }
        SleepFn(20);
    }
}


void AppRunningArg(int& app_argc, string& app_argv)
{
    app_argc = mapArgs.size();

    for (auto& elm : mapArgs) {
        string stroption = elm.first;
        if (!elm.second.empty()) {
            stroption += "=";
            stroption += elm.second;
        }
        stroption += " ";
        app_argv += stroption;
    }
}

extern MsgHandler ledgermsghandler;

void AppInfo(string& info)
{
    if (CryptoToken::IsSysToken(g_cryptoToken.GetHashPrefixOfGenesis())) {
        info = "Ledger module's current token: (null)";
        return;
    }

    ostringstream oss;
    string strNodes;
    TRY_CRITICAL_BLOCK(cs_vNodes)
    {
        int num = 0;
        for (auto& node : vNodes) {
            if (num++ > 20) {
                break;
            }
            strNodes += strprintf("\t%s    version: %d  PKIdx: %d  height: %d(%s)\n",
                node->addr.ToStringIPPort().c_str(), node->nVersion, node->nPKeyIdx,
                node->nHeightCheckPointBlock,
                node->hashCheckPointBlock.ToPreViewString().c_str());
        }
    }
    oss << "Ledger module's current token: " << g_cryptoToken.GetName() << " - "
        << g_cryptoToken.GetHashPrefixOfGenesis() << endl
        << "Block message: " << g_cryptoToken.GetDesc() << endl
        << "Genesis block address: " << g_cryptoToken.GetHID() << " "
        << g_cryptoToken.GetChainNum() << " "
        << g_cryptoToken.GetLocalID() << endl
        << "PKIdx: " << g_cryptoToken.GetPKIdx() << endl
        << "Neighbor node amounts: " << vNodes.size() << endl
        << strNodes << endl;

    oss << "MQID: " << ledgermsghandler.details() << endl << endl;

    bool isAllowed;
    string reason = g_chainReadyCond.GetReadyStatus(&isAllowed);
    oss << "Chain status: " << (isAllowed ? "Ready" : "Unready");

    if (!isAllowed && !reason.empty()) {
        oss << ", " << reason;
    }

    oss << endl;

    if (fGenerateBitcoins) {
        oss << "Block generate enabled\n";
    }
    else {
        oss << "Block generate disabled, use command 'token e' to enable\n";
    }

    if (fShutdown) {
        oss << "Ledger module has been in shutdown state, please restart\n";
    }

    info = oss.str();

    TRY_CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        info += "Best block's ";
        if (pindexBest) {
            info += pindexBest->ToString();
        }
        else {
            info += "CBlockIndex: null\n";
        }
        info += "Latest Ledger block's(HyperChainSpace) ";
        CBlockIndexSimplified* p = LatestLedgerBlock::Get();
        if (p) {
            info += p->ToString();
        }
        else {
            info += "CBlockIndex: null\n";
        }
        info += LatestLedgerBlock::GetMemoryInfo();

        //info += strprintf("OrphanBlocks: %u\n", mapOrphanBlocks.size() );
        return;

    }

    info += strprintf("Best block height: %d, Latest Ledger block height: %d\n", nBestHeight, LatestLedgerBlock::GetHeight());
    info += strprintf("Cannot retrieve the details informations for best block and latest Ledger block,\n\tbecause the lock: %s, try again after a while",
                       CCriticalBlockT<pcstName>::ToString().c_str());

}


bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen)
{
    CDataStream datastream(payload, payload + payloadlen);
    try {
        datastream >> block;
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot resolve ledger block data, %s\n", e.what());
    }
    return true;
}

bool ResolveHeight(int height, string& info)
{
    CBlockIndex* p = pindexBest;
    while (p) {
        if (p->Height() == height) {
            break;
        }
        p = p->pprev;
    }
    if (!p) {
        return false;
    }
    info = p->ToString();

    return true;
}


bool ResolvePayload(const string& payload, string& info)
{
    CBlock block;
    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    info = block.ToString();
    return true;
}



#define likely_no_token \
{ \
    if (g_cryptoToken.IsSysToken()) { \
        return "Token isn't specified"; \
    } \
}


string showTokenUsage()
{
    ostringstream oss;
    oss << "Usage: token ls       : list all local imported tokens \n";
    oss << "       token ll [NO.] : display the default/specified token details \n";
    oss << "       token df [NO.] : query or set the default token, after restarting ledger it will take effect\n";
    oss << "       token iss [...]                     : issue a token, 'token iss' for help\n";
    oss << "       token imp <hid chainid localid>     : import a token\n";
    oss << "       token acc                           : query account balances\n";
    oss << "       token addr [account]                : query account addresses\n";
    oss << "       token sendfrom <fromaccount> <toaddress> <amount> : transfer\n";
    oss << "       token sendtoaddr <address> <amount> : transfer\n";
    oss << "       token e                             : enable to generate blocks\n";
    oss << "       token d                             : disable to generate blocks\n";
    oss << "       token tx <txid>                     : Get detailed information about <txid>\n";
    oss << "       token txs [account] [count=10] [from=0] : list transactions\n";
    oss << "       token sfee <amount>                 : set fee for transaction\n";
    oss << "       token ginfo                         : query various state info\n";

    oss << "       token encw <passphrase>             : encrypts the wallet with <passphrase>\n";
    oss << "       token wpass <passphrase> <timeout=10>  : stores the wallet decryption key in memory for <timeout> seconds\n";
    oss << "       token chwpass <old> <new>           : change the wallet passphrase from <old> to <new>\n";

    oss << "       token gkp                           : generate a public-private key pair\n";
    oss << "       token ikp <private key>             : import a public-private key pair(support WIF, WIF-compressed and hex format)\n";
    oss << "       token ekp <address>                 : export the public-private key pair corresponding to <address> to console\n";
    oss << "       token ikpf <filename>               : import public-private key pairs from <filename>\n";
    oss << "       token ekpf <filename> [WIF|WIFC]    : export private keys to <filename>, default format is WIFC\n";
    oss << "       token dkp <address>                 : specify the key pair corresponding to <address> as default key\n";
    oss << "       token sacc <address> <account>      : sets the account associated with the given address\n";

    return oss.str();
}


bool ConsoleCmd(const list<string>& cmdlist, string& info, string& savingcommand)
{
    if (cmdlist.size() == 1) {
        info = showTokenUsage();
        return true;
    }

    list<string> cpycmdlist = cmdlist;
    auto cmd = ++cpycmdlist.begin();
    string childcmd = *cmd;
    cpycmdlist.pop_front();
    cpycmdlist.pop_front();

    std::unordered_map<string, std::function<string(const list<string>&, bool)>> mapcmds = {
            {"ls",[](const list<string>&, bool fhelp) ->string {
                vector<CryptoToken> tokens;
                CryptoToken::GetAllTokens(tokens);

                uint256 currhash = g_cryptoToken.GetHashGenesisBlock();

                ostringstream oss;
                size_t i = 0;

                for (auto& t : tokens) {
                    bool iscurrtoken = false;
                    if (currhash == t.GetHashGenesisBlock()) {

                        iscurrtoken = true;
                    }

                    oss << strprintf("%c %d\t%-26s %s\t[%u,%u,%u]\n",
                        iscurrtoken ? '*' : ' ',
                        i++, t.GetName().c_str(),
                        t.GetHashPrefixOfGenesis().c_str(),
                        t.GetHID(), t.GetChainNum(), t.GetLocalID());
                }

                oss << "use 'token ll [NO.]' for token details\n";
                return oss.str();
            }},

            {"ll",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 1) {
                    likely_no_token
                    return g_cryptoToken.ToString();
                }

                size_t i = std::atoi(l.begin()->c_str());

                vector<CryptoToken> tokens;
                CryptoToken::GetAllTokens(tokens);
                if (i > tokens.size()) {
                    return "out of range";
                }

                auto& t = tokens[i];
                return t.ToString();
            }},

            {"df",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 1) {
                    likely_no_token
                    return strprintf("current token: %s - %s [%u,%u,%u] PKIdx: %d\n", g_cryptoToken.GetName().c_str(),
                            g_cryptoToken.GetHashPrefixOfGenesis().c_str(),
                            g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID(),
                            g_cryptoToken.GetPKIdx());
                }

                size_t i = std::atoi(l.begin()->c_str());

                vector<CryptoToken> tokens;
                CryptoToken::GetAllTokens(tokens);
                if (i + 1 > tokens.size()) {
                    return "out of range";
                }

                auto& t = tokens[i];

                CApplicationSettings appini;
                appini.WriteDefaultApp(t.GetHashPrefixOfGenesis());

                return strprintf("set '%s' as current token, please restart ledger\n", t.GetName().c_str());
            }},

            {"iss",[](const list<string>& l, bool fhelp) ->string {
                return doAction(issuetoken, l, fhelp);
            }},

            {"imp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(importtoken, l, fhelp);
            }},

            {"acc",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(listaccounts, l, fhelp);
            }},

            {"addr",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                if (l.size() < 1) {
                    list<string> ll;
                    ll.push_back("");
                    return doAction(getaddressesbyaccount, ll, fhelp);
                }
                return doAction(getaddressesbyaccount, l, fhelp);
            }},

            {"sendfrom",[](const list<string>& l, bool fhelp) ->string {
                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    do {
                        if (cmd == cmdlist.end()) break;
                        arr.push_back(*cmd);
                        cmd++;

                        if (cmd == cmdlist.end()) break;
                        arr.push_back(*cmd);
                        cmd++;

                        if (cmd == cmdlist.end()) break;
                        char* end = nullptr;
                        double amount = std::strtod(cmd->c_str(), &end);
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };
                return doAction(sendfrom, l, fhelp, conv);
            } },

            {"sendtoaddr",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token

                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                     Array arr;
                    auto cmd = cmdlist.begin();
                    do {
                        if (cmd == cmdlist.end()) break;
                        arr.push_back(*cmd);
                        cmd++;

                        if (cmd == cmdlist.end()) break;
                        char* end = nullptr;
                        double amount = std::strtod(cmd->c_str(), &end);
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };
                return doAction(sendtoaddress, l, fhelp, conv);
            }},

            { "e",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token

                Array arr;
                arr.push_back(true);
                Value ret = setgenerate(arr, false);
                if (ret.is_null()) {
                    return "Enabled";
                }
                return write_string(ret, true);
            }},

            { "d",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token

                Array arr;
                arr.push_back(false);
                Value ret = setgenerate(arr, false);
                if (ret.is_null()) {
                    return "Disabled";
                }
                return write_string(ret, true);
            }},

            { "tx",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(gettransaction, l, fhelp);
            }},

            { "txs",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(listtransactions, l, fhelp);
            } },

            { "sfee",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    do {
                        if (cmd == cmdlist.end()) break;
                        char* end = nullptr;
                        double amount = std::strtod(cmd->c_str(), &end);
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };

                return doAction(settxfee, l, fhelp, conv);
            } },

            { "ginfo",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(getinfo, l, fhelp);
            } },

            { "gkp",[](const list<string>& l, bool fhelp) ->string {

                CKey keyPair;
                try {
                    keyPair.MakeNewKey();
                }
                catch (std::exception& e) {
                    return e.what();
                }

                CPrivKey pr = keyPair.GetPrivKey();
                std::vector<unsigned char> vPr(pr.begin(), pr.end());
                return StringFormat("Public key: %s\nPrivate key(WIF, WIF-compressed): \n\t%s\n\t%s", ToHexString(keyPair.GetPubKey()),
                    PrKey2WIF(keyPair.GetPrivKey(), false),
                    PrKey2WIF(keyPair.GetPrivKey(), true));
            }},


            { "ikp",[](const list<string>& l, bool fhelp) ->string {

                return doAction([](const Array& params, bool fHelp) ->string {
                    if (fHelp || params.size() != 1)
                        throw runtime_error(
                            "token ikp <private key>: import a public-private key pair");

                    likely_no_token

                    string msg;
                    impwalletkey(params[0].get_str(), msg);
                    return msg;

                 }, l, fhelp);
            }},


            { "ekp",[](const list<string>& l, bool fhelp) ->string {
                return doAction([](const Array& params, bool fHelp) ->string {
                    if (fHelp || params.size() != 1)
                        throw runtime_error(
                            "token ekp <address>: export the public-private key pair corresponding to <address> to console");

                    likely_no_token
                    likely_wallet_locked

                    string ret;
                    CPrivKey privkey;
                    CKey keyPair;
                    CRITICAL_BLOCK(pwalletMain->cs_wallet)
                    {
                        CBitcoinAddress coinaddress = CBitcoinAddress(params[0].get_str());
                        if (pwalletMain->GetKey(coinaddress, keyPair)) {

                            return StringFormat("Public key: %s\nPrivate key(WIF, WIF-compressed): \n\t%s\n\t%s", ToHexString(keyPair.GetPubKey()),
                                PrKey2WIF(keyPair.GetPrivKey(), false),
                                PrKey2WIF(keyPair.GetPrivKey(), true));
                        }
                    }
                    return "Failed to export key pair, maybe address is invalid";
                }, l, fhelp);
            }},

            { "sacc",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(setaccount, l, fhelp);
            } },


            {"ikpf",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(impwalletkeysfromfile, l, fhelp);
            }},


            { "ekpf",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(expwalletkeystofile, l, fhelp);
            }},


            { "dkp",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                string strRet = doAction(setdefaultkey, l, fhelp);

                CRITICAL_BLOCK(pwalletMain->cs_wallet) {
                    if (g_cryptoToken.SearchPublicKeyIdx()) {

                        UNCRITICAL_BLOCK(pwalletMain->cs_wallet);
                        CRITICAL_BLOCK(cs_vNodes) {
                            for (auto& n : vNodes) {
                                n->PushVersion();
                            }
                        }
                    }
                }
                return strRet;
            } },


            { "encw",[](const list<string>& l, bool fhelp) ->string {
                likely_no_token
                return doAction(encryptwallet, l, fhelp);
            }},


            { "wpass",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                if (l.size() < 1) {
                    return doAction(walletpassphrase, l, true);
                }

                savingcommand = "t wpass";

                likely_no_token

                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    arr.push_back(*cmd);

                    cmd++;
                    Value v = 10; //10 seconds
                    if (cmd != cmdlist.end()) {
                        v = std::stol(*cmd);
                    }
                    arr.push_back(v);
                    return arr;
                };
                return doAction(walletpassphrase, l, fhelp, conv);
            }},


            { "chwpass",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                if(l.size() != 0)
                    savingcommand = "t chwpass";
                likely_no_token
                return doAction(walletpassphrasechange, l, fhelp);
            }},
    };

    if (mapcmds.count(childcmd)) {
        info = mapcmds[childcmd](cpycmdlist, false);
        return true;
    }

    info = strprintf("Child command '%s' doesn't exist\n", childcmd.c_str());
    return true;
}
