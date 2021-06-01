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
#include "node/defer.h"

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "random.h"
#include "dllmain.h"
#include "cryptocurrency.h"
#include "para_rpc.h"
#include "plshared.h"


#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/fiber/all.hpp>

using namespace std;

boost::fibers::mutex g_fibermtx;

#define FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(t) \
    std::lock_guard<boost::fibers::mutex> lk(g_fibermtx); \
    CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__); \
    while (!criticalblock.TryEnter(__FILE__, __LINE__)) { \
        boost::this_fiber::sleep_for(std::chrono::milliseconds(t)); \
    }


CAddress g_seedserver;

extern CBlockCacheLocator mapBlocks;
extern map<uint256, CBlockSP> mapOrphanBlocks;


extern MiningCondition g_miningCond;
extern std::atomic_bool g_isBuiltInBlocksReady;


extern const CUInt128& getMyNodeID();
extern void ProcessOrphanBlocks(const uint256& hash);
bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen);



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

void RSyncRemotePullHyperBlockAgain(uint32_t hid)
{
    CRITICAL_BLOCK(cs_pullingHyperBlock)
    {
        if (mapPullingHyperBlock.count(hid) != 0) {
            RSyncRemotePullHyperBlock(hid);
        }
    }
}

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


bool UpdateAppAddress(const CBlock& genesisblock, const T_LOCALBLOCKADDRESS& addr)
{
    CryptoCurrency cryptoCurrency(false);
    cryptoCurrency.ParseCoin(genesisblock);

    CryptoCurrency cryptoCurrencyFromLocal(false);

    string currencyhash = cryptoCurrency.GetHashPrefixOfGenesis();
    string errmsg;
    if (!cryptoCurrencyFromLocal.ReadCoinFile("", currencyhash, errmsg)) {

        return ERROR_FL("%s", errmsg.c_str());
    }

    uint256 hash = genesisblock.GetHash();
    if (cryptoCurrencyFromLocal.GetHashGenesisBlock() == hash) {
        if (!cryptoCurrencyFromLocal.SetGenesisAddr(addr.hid, addr.chainnum, addr.id)) {
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

    if (hid != g_cryptoCurrency.GetHID() ||
        chainnum != g_cryptoCurrency.GetChainNum() ||
        localid != g_cryptoCurrency.GetLocalID()) {
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

bool SwitchChainTo(CBlockIndexSP pindexBlock)
{
    CBlock block;
    if (!block.ReadFromDisk(pindexBlock)) {
        return ERROR_FL("Failed to Read paracoin block: %s", pindexBlock->addr.tostring().c_str());
    }

    CTxDB_Wrapper txdb;
    block.SetBestChain(txdb, pindexBlock);

    INFO_FL("Switch to: %d,hid:%d,%s, %s, BestIndex: %d hid:%d,%s, %s LastHID: %u", pindexBlock->nHeight,
        pindexBlock->nPrevHID,
        pindexBlock->addr.tostring().c_str(),
        pindexBlock->GetBlockHash().ToPreViewString().c_str(),
        pindexBest->nHeight, pindexBest->nPrevHID,
        pindexBest->addr.tostring().c_str(),
        pindexBest->GetBlockHash().ToPreViewString().c_str(),
        LatestHyperBlock::GetHID());

    ProcessOrphanBlocks(pindexBlock->GetBlockHash());
    return true;
}

bool SwitchChainToHyperHeight(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw runtime_error("coin s <height> : only for developers");
    }

    int32 height = std::atoi(params[0].get_str().c_str());
    auto p = pindexBest;
    while (p->nHeight > height) {
        p = p->pprev();
    }

    if (!p || height != p->nHeight) {
        return false;
    }
    return SwitchChainTo(p);
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

    LatestParaBlock::CompareAndUpdate(vecBlockAddr,vecBlock, isLatest);
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


    return true;
}

extern HyperBlockMsgs hyperblockMsgs;

bool AcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    CHAINCBDATA cbdata(mapPayload, hidFork, hid, thhash, isLatest);
    hyperblockMsgs.insert(std::move(cbdata));
    return true;
}

bool ProcessChainCb(map<T_APPTYPE,vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    //CSpentTime spentt;
    //defer {
    //    cout << strprintf("Para ProcessChainCb spent million seconds : %ld\n", spentt.Elapse());
    //};


    //FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        LatestHyperBlock::CompareAndUpdate(hid, thhash, isLatest);
        T_APPTYPE meApp(APPTYPE::paracoin, g_cryptoCurrency.GetHID(),
                                           g_cryptoCurrency.GetChainNum(),
                                           g_cryptoCurrency.GetLocalID());
        if (mapPayload.count(meApp)) {
            vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
            return AcceptBlocks(vecPA, isLatest);
        }

        if (isLatest) {

            CBlockIndexSP pStart = pindexBest;
            while (pStart && pStart->nPrevHID >= hidFork) {
                pStart = pStart->pprev();
            }

            if (!pStart) {
                pStart = pindexGenesisBlock;
            }

            pStart = pStart->pnext();
            if (!pStart) {
                return true;
            }



            uint256 hhash(thhash.toHexString());
            CBlockIndexSP pEnd = pStart;
            while (pEnd && pEnd->nPrevHID == hid && pEnd->hashPrevHyperBlock == hhash) {
                pEnd = pEnd->pnext();
            }

            if (pEnd) {
                auto spprev = pEnd->pprev();
                if (spprev) {
                    SwitchChainTo(spprev);
                }
            }
        }
    }

    return true;
}

void HyperBlockMsgs::insert(CHAINCBDATA &&cb)
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

bool CheckChainCbWhenOnChaining(vector<T_PAYLOADADDR>& vecPA, uint32_t prevhid, T_SHA256& tprevhhash)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<CBlock> vecBlock;
    for (auto b : vecPA) {
        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    uint256 prevhhash = uint256S(tprevhhash.toHexString());
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (vecBlock[i].nPrevHID != prevhid ||
            vecBlock[i].hashPrevHyperBlock != prevhhash) {
            return false;
        }
    }

    return true;
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



bool ValidateLedgerDataCb(T_PAYLOADADDR& payloadaddr,
                        map<boost::any,T_LOCALBLOCKADDRESS>& mapOutPt,
                        boost::any& hashPrevBlock)
{
    CBlock block;
    if (!ResolveBlock(block, payloadaddr.payload.c_str(), payloadaddr.payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }
    if (hashPrevBlock.empty()) {
        hashPrevBlock = block.hashPrevBlock;
    }
    else if (block.hashPrevBlock != boost::any_cast<uint256>(hashPrevBlock)) {
        return ERROR_FL("hashPrevBlock is different");
    }

    // Preliminary checks
    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        if (!block.CheckBlock())
            return ERROR_FL("CheckBlock FAILED");

        if (!block.CheckTrans())
            return ERROR_FL("CheckTrans FAILED");

        CTxDB_Wrapper txdb;
        for (auto tx : block.vtx) {
            if (tx.IsCoinBase()) {
                continue;
            }


            map<uint256, std::tuple<CTxIndex, CTransaction>> mapUnused;
            int64 nFees = 0;
            if (!tx.ConnectInputs(txdb, mapUnused, CDiskTxPos(1), pindexBest, nFees, false, false)) {
                return ERROR_FL("ConnectInputs failed %s",
                    payloadaddr.addr.tostring().c_str());
            }
        }
    }


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



bool BlockUUIDCb(string& payload, string& uuidpayload)
{


    uuidpayload = payload.substr(0, sizeof(int));

    uuidpayload += payload.substr(sizeof(int) + sizeof(uint256));
    return true;
}


bool PutChainCb()
{
    deque<CBlock> deqblock;
    uint256 hhash;

    bool isSwithBestToValid = false;
    CBlockIndexSP pindexValidStarting;

    if (mapArgs.count("-importtx")) {

        if (!g_isBuiltInBlocksReady) {
            return false;
        }
    }

    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {

        hyperblockMsgs.process();

        while (!LatestParaBlock::IsOnChain()) {

            if (!LatestParaBlock::IsLackingBlock() && !LatestParaBlock::IsBestChain()) {
                break;
            }

            CBlockIndexSSP pIndex = LatestParaBlock::Get();
            if (pIndex) {
                WARNING_FL("Best chain is behind, cannot commit Paracoin onto chain, should be height: %u", pIndex->nHeight);
            }
            return false;
        }

        uint64 nHID = LatestHyperBlock::GetHID(&hhash);

        CBlockIndexSP pStart = LatestBlockIndexOnChained();
        pStart = pStart->pnext();
        if (!pStart) {

            return false;
        }


        CBlockIndexSP pEnd = pStart;
        while (pEnd && pEnd->nPrevHID == nHID && pEnd->hashPrevHyperBlock == hhash) {
            if (!mapBlocks.contain(pEnd->GetBlockHash())) {
                break;
            }
            deqblock.push_back(mapBlocks[pEnd->GetBlockHash()]);
            pEnd = pEnd->pnext();
        }

        if (!deqblock.size()) {

            isSwithBestToValid = true;
            pindexValidStarting = pStart->pprev();
        }


        if (isSwithBestToValid) {
            for (; pindexValidStarting; pindexValidStarting = pindexValidStarting->pprev()) {
                if (SwitchChainTo(pindexValidStarting))
                    break;
            }
            return false;
        }
    }


    if (deqblock.size() < 2) {

        return false;
    }
    auto deqiter = deqblock.end();
    auto tail_block = --deqiter;
    auto tail_second_block = --tail_block;

    const CUInt128 & mynodeid = getMyNodeID();

    if (!tail_block->ownerNodeID.operator==(mynodeid) &&
        !tail_second_block->ownerNodeID.operator==(mynodeid)) {
        return false;
    }

    tail_block->ownerNodeID = mynodeid;

    string requestid, errmsg;
    if (!CommitChainToConsensus(deqblock, requestid, errmsg)) {
        ERROR_FL("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

    return true;
}

bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)
{
    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        CBlockIndexSP p = pindexBest;
        while (p) {
            if (p->addr.hid > sAddr.hid) {
                p = p->pprev();
                continue;
            } else if (p->addr.hid < sAddr.hid) {

                return false;
            }
            else {
                for (;p && p->addr.hid <= eAddr.hid;) {
                    vecVPath.push_back(p->addr.tostring());
                    p = p->pnext();
                }
                return true;
            }
        }
    }
    return false;
}

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

extern multimap<uint256, CBlockSP> mapOrphanBlocksByPrev;


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

    for (auto& elm : mapArgs)
    {
        string stroption = elm.first;
        if (!elm.second.empty()) {
            stroption += "=";
            stroption += elm.second;
        }
        stroption += " ";
        app_argv += stroption;
    }
}

extern MsgHandler paramsghandler;

void AppInfo(string& info)
{
    ostringstream oss;
    string strNodes;
    TRY_CRITICAL_BLOCK(cs_vNodes)
    {
        int num = 0;
        for (auto& node : vNodes) {
            if (num++ > 20) {
                break;
            }
            strNodes += strprintf("\t%s    version: %d    height: %d(%s)\n",
                node->addr.ToStringIPPort().c_str(), node->nVersion,
                node->nHeightCheckPointBlock,
                node->hashCheckPointBlock.ToPreViewString().c_str());
        }
    }

    oss << "Paracoin module's current coin name: " << g_cryptoCurrency.GetName() << " - "
        << g_cryptoCurrency.GetHashPrefixOfGenesis() << endl
        << "block message: " << g_cryptoCurrency.GetDesc() << endl
        << "model: " << g_cryptoCurrency.GetModel() << endl
        << "Genesis block address: " << g_cryptoCurrency.GetHID() << " "
        << g_cryptoCurrency.GetChainNum() << " "
        << g_cryptoCurrency.GetLocalID() << endl
        << "Neighbor node amounts: " << vNodes.size() << endl
        << strNodes << endl;

    oss << "MQID: " << paramsghandler.details() << endl << endl;

    bool isAllowed;
    string reason = g_miningCond.GetMiningStatus(&isAllowed);
    oss << "Mining status: " << (isAllowed ? "mining" : "stopped");

    if (!isAllowed && !reason.empty()) {
        oss << ", " << reason;
    }
    oss << endl;

    if (fGenerateBitcoins) {
        oss << "Block generate enabled\n";
    }
    else {
        oss << "Block generate disabled, use command 'coin e' to enable\n";
    }

    if (fShutdown) {
        oss << "Paracoin module has been in shutdown state, please restart\n";
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

        info += "Latest Para block's(HyperChainSpace) ";
        CBlockIndexSSP p = LatestParaBlock::Get();
        if (p) {
            info += p->ToString();
        }
        else {
            info += "CBlockIndex: null\n";
        }
        info += LatestParaBlock::GetMemoryInfo();

        info += strprintf("OrphanBlocks: %u\n", mapOrphanBlocks.size() );
        return;
    }

    info += strprintf("Best block height: %d, Latest Para block height: %d\n", nBestHeight, LatestParaBlock::GetHeight());
    info += strprintf("Cannot retrieve the details informations for best block and latest Para block,\n\tbecause the lock: %s, try again after a while",
                       CCriticalBlockT<pcstName>::ToString().c_str());
}

bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen)
{
    CDataStream datastream(payload, payload + payloadlen, SER_BUDDYCONSENSUS);
    try {
        datastream >> block;
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot resolve block data, %s\n", e.what());
    }
    return true;
}

bool ResolveHeight(int height, string& info)
{
    TRY_CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        if (height > pindexBest->nHeight) {
            info = strprintf("Invalid height value, which should <= Best block height: %d\n", nBestHeight);
            return false;
        }


        CTxDB_Wrapper txdb;

        CBlockIndexSP p = pindexBest;
        while (p) {
            if (p->nHeight == height) {
                break;
            }
            p = p->pprev();
        }
        if (!p) {
            return false;
        }

        CBlock block;
        T_LOCALBLOCKADDRESS addrblock;
        if (GetBlockData(p->GetBlockHash(), block, addrblock)) {
            info = block.ToString();
            info += p->ToString();
        }
        else {
            info = p->ToString();
        }

        return true;
    }

    info += strprintf("Best block height: %d, Latest Para block height: %d\n", nBestHeight, LatestParaBlock::GetHeight());
    info += strprintf("Cannot retrieve the details informations for best block and latest Para block,\n\tbecause the lock: %s, try again after a while",
        CCriticalBlockT<pcstName>::ToString().c_str());
    return false;
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

#define likely_mining \
{ \
   if (g_miningCond.IsSwitching() || g_miningCond.IsBackTracking()) { \
       throw runtime_error("Please stop mining firstly"); \
   } \
}


Value IsMyPublickey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error("coin myk <publickey> : check <publickey> if it is in my wallet or not");
    }

    const string & pubkey = params[0].get_str();
    CBitcoinAddress paraaddr(ParseHex(pubkey));

    Array ret;
    ret.push_back(paraaddr.ToString());

    if (pwalletMain->HaveKey(paraaddr)) {
        ret.push_back("Yes");
        return ret;
    }
    ret.push_back("No");
    return ret;
}



extern void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);

void ScanChainForTxes(const std::vector<unsigned char>& vchPriKey)
{
    likely_wallet_locked
    auto ret = CallWithLock([&vchPriKey]() ->Value {
        {
            string errinfo;
            CKey keyPair;
            //keyPair.SetPubKey(publickey);

            CPrivKey privkey;
            privkey.resize(vchPriKey.size());
            std::copy(vchPriKey.begin(), vchPriKey.end(), privkey.begin());

            if (!keyPair.SetPrivKey(privkey)) {
                return "Incorrect private key";
            }

            CBitcoinAddress coinaddress;
            coinaddress.SetPubKey(keyPair.GetPubKey());
            cout << StringFormat("Coin address: %s\n", coinaddress.ToString());

            CWallet tmpWallet;
            tmpWallet.AddKey(keyPair);

            auto pindex = pindexGenesisBlock;
            while (pindex) {
                CBlock blk;
                if (!blk.ReadFromDisk(pindex)) {
                    errinfo = StringFormat("Read Para block error: %s\n", pindex->ToString());
                    goto err;
                }
                for (CTransaction& tx : blk.vtx) {

                    if (tmpWallet.IsMine(tx)) {
                        cout << "+: " << tx.ToString();
                    }

                    if(tmpWallet.IsFromMe(tx)) {
                        cout << "-: " << tx.ToString();
                    }
                }
                pindex = pindex->pnext();
            }

            //if (!pwalletMain->GetKey(coinaddress, keyPair)) {
            //     errinfo = "The address doesn't exist";
            //     goto err;
            //}
            return "Txes scanned successfully";
        err:
            //cerr << errinfo << endl;
            return errinfo;
        }
    });

    if (ret.type() == str_type) {
        cout << ret.get_str();
    }
}

void RebuildWallet()
{
    likely_wallet_locked

    CallWithLock([]() ->Value {
        CRITICAL_BLOCK(pwalletMain->cs_wallet)
            {
                string errinfo;

                auto pindex = pindexGenesisBlock;
                while (pindex) {
                    CBlock blk;
                    if (!blk.ReadFromDisk(pindex)) {
                        errinfo = StringFormat("Read Para block error: %s\n", pindex->ToString());
                        goto err;
                    }
                    for (CTransaction& tx : blk.vtx)
                        SyncWithWallets(tx, &blk, true);
                    pindex = pindex->pnext();
                }
            err:
                cerr << errinfo << endl;
                return errinfo;
            }
    });
}


string showCoinUsage()
{
    ostringstream oss;
    oss << "Usage: coin ls       : list all local imported coins \n";
    oss << "       coin ll [NO.] : display the default/specified coin details \n";
    oss << "       coin df [NO.] : query or set the default coin, after restarting paracoin, it takes effect\n";
    oss << "       coin iss [...]                     : issue a coin, 'coin iss' for help\n";
    oss << "       coin imp <hid chainid localid>     : import a coin\n";
    oss << "       coin acc                           : query account balances\n";
    //oss << "       coin addrba [address]...           : scan wallet for addresses balances\n";
    oss << "       coin addr [account]                : query account addresses\n";
    oss << "       coin sendfrom <fromaccount> <toaddress> <amount> : transfer\n";
    oss << "       coin sendtoaddr <address> <amount> : transfer\n";
    oss << "       coin e                             : enable mining\n";
    oss << "       coin d                             : disable mining\n";
    oss << "       coin tx <txid>                     : get detailed information about <txid>\n";
    oss << "       coin txs [account] [count=10] [from=0] : list transactions, '*' means default account\n";
    oss << "       coin sfee <amount>                 : set fee for transaction\n";
    oss << "       coin ginfo                         : query various state info\n";

    oss << "       coin encw <passphrase>             : encrypts the wallet with <passphrase>\n";
    oss << "       coin wpass <passphrase> <timeout=10>  : stores the wallet decryption key in memory for <timeout> seconds\n";
    oss << "       coin chwpass <old> <new>           : change the wallet passphrase from <old> to <new>\n";

    oss << "       coin ikp <private key>             : import a public-private key pair(support WIF, WIF-compressed and hex format)\n";
    oss << "       coin ekp <address>                 : export the public-private key pair corresponding to <address> to console\n";
    oss << "       coin ikpf <filename>               : import private keys from <filename>\n";
    oss << "       coin ekpf <filename> [WIF|WIFC]    : export private keys to <filename>, default format is WIFC\n";
    oss << "       coin dkp <address>                 : specify the key pair whose address is <address> as default key\n";

    oss << "       coin sacc <address> <account>      : sets the account associated with the given address\n";

    return oss.str();
}

bool ConsoleCmd(const list<string>& cmdlist, string& info, string& savingcommand)
{
    if (cmdlist.size() == 1) {
        info = showCoinUsage();
        return true;
    }

    std::unordered_map<string, std::function<string(const list<string>&, bool)>> mapcmds = {
            {"ls",[](const list<string>&, bool fhelp) ->string {
                vector<CryptoCurrency> coins;
                CryptoCurrency::GetAllCoins(coins);

                uint256 currhash = g_cryptoCurrency.GetHashGenesisBlock();

                ostringstream oss;
                size_t i = 0;
                for (auto& t : coins) {
                    bool iscurrcoin = false;
                    if (currhash == t.GetHashGenesisBlock()) {

                        iscurrcoin = true;
                    }
                    oss << strprintf("%c %d\t%-26s %s\t[%u,%u,%u]\n",
                        iscurrcoin ? '*' : ' ',
                        i++, t.GetName().c_str(),
                        t.GetHashPrefixOfGenesis().c_str(),
                        t.GetHID(), t.GetChainNum(), t.GetLocalID());
                }
                oss << "use 'coin ll [NO.]' for coin details\n";
                return oss.str();
            } },

            {"ll",[](const list<string>& l, bool fhelp) ->string {
                if (l.size() < 1) {
                    return g_cryptoCurrency.ToString();
                }

                size_t i = std::atoi(l.begin()->c_str());

                vector<CryptoCurrency> coins;
                CryptoCurrency::GetAllCoins(coins);
                if (i >= coins.size()) {
                    return "out of range";
                }

                auto& t = coins[i];
                return t.ToString();
            } },

            {"df",[](const list<string>& l, bool fhelp) ->string {
                if (l.size() < 1) {
                    return StringFormat("current coin: %s - %s\n", g_cryptoCurrency.GetName(),
                        g_cryptoCurrency.GetHashPrefixOfGenesis());
                }

                size_t i = std::atoi(l.begin()->c_str());

                vector<CryptoCurrency> coins;
                CryptoCurrency::GetAllCoins(coins);
                if (i + 1 > coins.size()) {
                    return "out of range";
                }

                auto& t = coins[i];

                CApplicationSettings appini;
                appini.WriteDefaultApp(t.GetHashPrefixOfGenesis());

                return StringFormat("set '%s' as current coin, please restart paracoin\n", t.GetName());
            } },


            {"iss",[](const list<string>& l, bool fhelp) ->string {
                return doAction(issuecoin, l, fhelp);
            } },

            {"imp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(importcoin, l, fhelp);
            } },

            {"acc",[](const list<string>& l, bool fhelp) ->string {
                return doAction(listaccounts, l, fhelp);
            } },

            {"addr",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 1) {
                    list<string> ll;
                    ll.push_back("");
                    return doAction(getaddressesbyaccount, ll, fhelp);
                }

                return doAction(getaddressesbyaccount, l, fhelp);
            } },

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
                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    do
                    {
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
            } },

            { "e",[](const list<string>& l, bool fhelp) ->string {
                Array arr;
                arr.push_back(true);
                Value ret = setgenerate(arr, false);
                if (ret.is_null()) {
                    return "Mining is started";
                }
                return write_string(ret, true);
            } },

            { "d",[](const list<string>& l, bool fhelp) ->string {
                Array arr;
                arr.push_back(false);
                Value ret = setgenerate(arr, false);
                if (ret.is_null()) {
                    return "Mining is stopped";
                }
                return write_string(ret, true);
            } },

            { "tx",[](const list<string>& l, bool fhelp) ->string {
                return doAction(gettransaction, l, fhelp);
            } },

            { "txs",[](const list<string>& l, bool fhelp) ->string {

                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    do {
                        if (cmd == cmdlist.end()) break;
                        arr.push_back(*cmd);
                        cmd++;

                        if (cmd == cmdlist.end()) break;
                        long nCount = atol(cmd->c_str());
                        arr.push_back(nCount);
                        cmd++;

                        if (cmd == cmdlist.end()) break;
                        long nfrom = atol(cmd->c_str());
                        arr.push_back(nfrom);
                        break;
                    } while (true);
                    return arr;
                };

               return doAction(listtransactions, l, fhelp, conv);
            } },

            { "sfee",[](const list<string>& l, bool fhelp) ->string {
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
               return doAction(getinfo, l, fhelp);
            } },



            { "ikp",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                return doAction([&savingcommand](const Array& params, bool fHelp) ->string {
                    if (fHelp || params.size() != 1)
                        throw runtime_error(
                            "coin ikp <private key>: import a public-private key pair");

                    savingcommand = "c ikp";
                    string msg;
                    impwalletkey(params[0].get_str(), msg);
                    return msg;

                }, l, fhelp);
            } },


            { "ekp",[](const list<string>& l, bool fhelp) ->string {
                return doAction([](const Array& params, bool fHelp) ->string {
                    if (fHelp || params.size() != 1)
                        throw runtime_error(
                            "coin ekp <address>: export the public-private key pair corresponding to <address> to console");

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
            } },

            { "sacc",[](const list<string>& l, bool fhelp) ->string {
                return doAction(setaccount, l, fhelp);
            } },


            {"ikpf",[](const list<string>& l, bool fhelp) ->string {
                return doAction(impwalletkeysfromfile, l, fhelp);
            } },


            { "ekpf",[](const list<string>& l, bool fhelp) ->string {
                return doAction(expwalletkeystofile, l, fhelp);
            } },


            { "dkp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(setdefaultkey, l, fhelp);
            } },


            { "encw",[](const list<string>& l, bool fhelp) ->string {
                return doAction(encryptwallet, l, fhelp);
            } },


            { "wpass",[&savingcommand](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 1) {
                    return doAction(walletpassphrase, l, true);
                }

                savingcommand = "c wpass";

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
            } },


            { "chwpass",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                if(l.size() != 0)
                    savingcommand = "c chwpass";
                return doAction(walletpassphrasechange, l, fhelp);
            } },

            { "qtx",[](const list<string>& l, bool fhelp) ->string {
                 if (l.size() == 0)
                     return "c qtx <publickey>";

                 auto cmd = l.begin();
                 std::vector<unsigned char> publickey;
                 publickey = ParseHex(*cmd);
                 ScanChainForTxes(publickey);
                 return "";
            } },

            { "addrba",[](const list<string>& l, bool fhelp) ->string {
                return doAction(listaddrbalance, l, fhelp);
            } },


            { "s",[](const list<string>& l, bool fhelp) ->string {
                return doAction(SwitchChainToHyperHeight, l, fhelp);
            } },


            { "myk",[](const list<string>& l, bool fhelp) ->string {
                return doAction(IsMyPublickey, l, fhelp);
            } },

            { "db",[](const list<string>& l, bool fhelp) ->string {
                if (fhelp) {
                    return "coin db: only for developers";
                }
                return getdbenv();
            } },

    };

    list<string> cpycmdlist;
    cpycmdlist = cmdlist;
    auto cmd = ++cpycmdlist.begin();
    string childcmd = *cmd;
    cpycmdlist.pop_front();
    cpycmdlist.pop_front();

    if (mapcmds.count(childcmd)) {
        info = mapcmds[childcmd](cpycmdlist, false);
        return true;
    }
    info = strprintf("Child command '%s' doesn't exist\n", childcmd.c_str());
    return true;
}

