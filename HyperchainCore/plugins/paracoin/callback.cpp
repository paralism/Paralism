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
#include "paratask.h"
#include "key_io.h"


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



SeedServers g_seedserver;

extern ParaRecver recver;
extern ParaMQCenter paramqcenter;

extern CBlockCacheLocator mapBlocks;
extern map<uint256, CBlockSP> mapOrphanBlocks;


extern MiningCondition g_miningCond;
extern std::atomic_bool g_isBuiltInBlocksReady;

extern ChkPoint mychkp;

extern const CUInt128& getMyNodeID();
extern void ProcessOrphanBlocks(const uint256& hash);
bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);


//HC: Here should be change to pull application block in the future
std::map<uint32_t, time_t> mapPullingHyperBlock;
CCriticalSection cs_pullingHyperBlock;
void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "")
{
    CRITICAL_BLOCK(cs_pullingHyperBlock)
    {
        time_t now = time(nullptr);
        if (mapPullingHyperBlock.count(hid) == 0) {
            mapPullingHyperBlock.insert({ hid, now });
        } else {
            if (now - mapPullingHyperBlock[hid] < 60) {
                //HC: already pulled
                return;
            } else {
                mapPullingHyperBlock[hid] = now;
            }
        }
        auto bg = mapPullingHyperBlock.begin();
        for (; bg != mapPullingHyperBlock.end();) {
            if (bg->second + 300 < now) {
                bg = mapPullingHyperBlock.erase(bg);
            } else {
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
            } else {
                hyperchainspace->GetRemoteHyperBlockByID(hid, nodeid);
                INFO_FL("GetRemoteHyperBlockByID: %d, from node: %s", hid, nodeid.c_str());
            }
        }
        });
    t.detach();
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
        //HC: no this coin
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

//HC: When a hyper block receieved，chain layer calls this function to validate.
bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    return true;
}

//HC: Must getting cs_main before switching chain, else cause db dead lock
bool SwitchChainToBlock(CBlock& block, CBlockIndexSP pindexBlock)
{
    CTxDB_Wrapper txdb;
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        if (block.SetBestChain(txdb, pindexBlock)) {
            INFO_FL("Switch to: %d(%s) PreHID: %d Triaddr: %s LastHID: %u", pindexBlock->nHeight,
                pindexBlock->GetBlockHash().ToPreViewString().c_str(),
                pindexBlock->nPrevHID,
                pindexBlock->triaddr.ToString().c_str(),
                LatestHyperBlock::GetHID());
            ProcessOrphanBlocks(pindexBlock->GetBlockHash());
            return true;
        }
        return false;
    }
    return false;
}

bool SwitchChainTo(CBlockIndexSP pindexBlock)
{
    CBlock block;
    if (!block.ReadFromDisk(pindexBlock)) {
        return ERROR_FL("Failed to Read paracoin block: %s", pindexBlock->triaddr.ToString().c_str());
    }
    return SwitchChainToBlock(block, pindexBlock);
}

bool SwitchChainToHyperHeight(const Array& params, bool fHelp)
{
    string help = "coin sw <height> | <HID> <chainID> <ID>, this command only for developers";
    if (fHelp || params.size() < 1) {
        throw runtime_error(help);
    }

    if (params.size() == 1) {
        int32 height = std::atoi(params[0].get_str().c_str());
        auto p = pindexBest;
        while (p->nHeight > height) {
            p = p->pprev();
        }

        if (!p || height != p->nHeight) {
            return false;
        }
        return SwitchChainTo(p);
    } else if (params.size() == 3) {
        int hid = std::atoi(params[0].get_str().c_str());
        int chainid = std::atoi(params[1].get_str().c_str());
        int id = std::atoi(params[2].get_str().c_str());

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        T_LOCALBLOCKADDRESS addr;
        addr.set(hid, chainid, id);

        cout << StringFormat("Switching chain to block %s\n", addr.tostring());

        T_LOCALBLOCK localblock;
        if (hyperchainspace->GetLocalBlock(addr, localblock)) {
            CBlock block;
            try {
                CAutoBuffer autobuff(std::move(localblock.body.payload));
                autobuff >> block;
            }
            catch (std::ios_base::failure& e) {
                throw runtime_error(("%s", e.what()));
            }

            uint256 hash = block.GetHash();
            CBlockIndexSP pindexBlock;
            BLOCKTRIPLEADDRESS triaddr;
            char* pWhere = nullptr;

            if (GetBlockData(hash, block, triaddr, &pWhere)) {
                cout << StringFormat("Block is in %s\n", pWhere);
                ProcessBlockWithTriaddr(nullptr, &block, &triaddr);
                if (mapBlockIndex.count(hash)) {
                    pindexBlock = mapBlockIndex[hash];
                    return SwitchChainToBlock(block, pindexBlock);
                }
                throw runtime_error(StringFormat("Block:%d(%s) not in mapBlockIndex", block.nHeight, hash.ToPreViewString()));
            } else {
                throw runtime_error(StringFormat("Failed to GetBlockData %d(%s)", block.nHeight, hash.ToPreViewString()));
            }
        } else {
            throw runtime_error(StringFormat("Failed to read block %s from Hyper chain space", addr.tostring()));
        }
    }
    throw runtime_error(help);
}

bool FindBlkInMainFromBlock(const Array& params, bool fHelp)
{
    string help = "coin findblkinmain <HID> <chainID> <ID>, this command only for developers";
    if (fHelp || params.size() != 3) {
        throw runtime_error(help);
    }

    int hid = std::atoi(params[0].get_str().c_str());
    int chainid = std::atoi(params[1].get_str().c_str());
    int id = std::atoi(params[2].get_str().c_str());

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    T_LOCALBLOCKADDRESS addr;
    addr.set(hid, chainid, id);
    T_LOCALBLOCK localblock;
    if (hyperchainspace->GetLocalBlock(addr, localblock)) {
        CBlock block;
        try {
            CAutoBuffer autobuff(std::move(localblock.body.payload));
            autobuff >> block;
        }
        catch (std::ios_base::failure& e) {
            throw runtime_error(("%s", e.what()));
        }

        CommadLineProgress progress;
        progress.Start();

        CBlockIndexSP pindexBlock;
        uint256 hashPrev = block.hashPrevBlock;
        int nHeightPrev = block.nHeight;
        BLOCKTRIPLEADDRESS triaddr;
        char* pWhere = nullptr;
        int nCount = 0;

        while (1) {
            if (GetBlockData(hashPrev, block, triaddr, &pWhere)) {
                uint256 hash = block.GetHash();
                if (mapBlockIndex.count(hash)) {
                    if (mapBlockIndex[hash]->IsInMainChain()) {
                        cout << StringFormat("Found: block %d(%s) [triaddr: %s] in main chain, so skip the left blocks\n",
                            block.nHeight, hash.ToPreViewString(), triaddr.ToString());
                        break;
                    }
                }

                if (nCount++ % 10 == 0) {
                    progress.PrintStatus(10, StringFormat("Scanning block: %d(%s)", block.nHeight, hash.ToPreViewString()));
                }
            } else {
                throw runtime_error(StringFormat("block %d(%s) not found", nHeightPrev, hashPrev.ToPreViewString()));
            }
            hashPrev = block.hashPrevBlock;
        }
    } 
    throw runtime_error(StringFormat("Failed to read block %s from Hyper chain space", addr.tostring()));
}




string FixChainWork()
{
    CommadLineProgress progress;
    progress.Start();

    CBlockIndexSP pindexBlock = pindexGenesisBlock->pnext();
    CBlockIndexSP ppindexBlock = pindexGenesisBlock;

    int nCount = 0;
    int nCountChainWorkErr = 0;

    CTxDB_Wrapper txdb;

    while (pindexBlock) {

        ++nCount;
        auto work = ppindexBlock->bnChainWork + pindexBlock->GetBlockWork();
        if (work != pindexBlock->bnChainWork) {
            nCountChainWorkErr++;

            //HC: fix
            pindexBlock->bnChainWork = work;
            txdb.WriteBlockIndex(CDiskBlockIndex(pindexBlock.get()));
        }

        if (pindexBlock == pindexBest) {
            progress.PrintStatus(1, StringFormat("scanned %d, (fixed: %d)", nCount, nCountChainWorkErr));
            return "Para chain has reached best block!\n";
        }

        if (nCount % 1000 == 0) {
            progress.PrintStatus(1000, StringFormat("scanned: %d, (error: %d) %d(%s)",
                nCount, nCountChainWorkErr, pindexBlock->nHeight, pindexBlock->hashBlock.ToPreViewString()));
        }

        ppindexBlock = pindexBlock;
        pindexBlock = pindexBlock->pnext();
    }

    return StringFormat("scanned %d(%s), but cannot reach best block\n", ppindexBlock->nHeight, ppindexBlock->hashBlock.ToPreViewString());
}


typedef struct
{
    CBlock blk;
    uint256 hash;
    BLOCKTRIPLEADDRESS triaddr;
} BLOCKWITHADDR;

static string CheckMainChain_fixhlp(vector<BLOCKWITHADDR>& vecFixingBlocks)
{
    cout << StringFormat("%d blocks need to fix, start...\n", vecFixingBlocks.size());
    auto it = vecFixingBlocks.rbegin();
    for (; it != vecFixingBlocks.rend(); ++it) {
        ProcessBlockWithTriaddr(nullptr, &it->blk, &it->triaddr);
        if (mapBlockIndex.count(it->hash)) {
            cout << StringFormat("block(%d(%s) triaddr:%s) fixed\n", it->blk.nHeight, it->hash.ToString(), it->triaddr.ToString());
        } else {
            return StringFormat("block(%d(%s)) cannot fix\n", it->blk.nHeight, it->hash.ToString());
        }
    }
    return "Fixed completed\n";
}

//HC: 'isbreak' is true means when error occurs function will stop execution
string CheckMainChain(int stopheight, bool isfix, bool ischecktriaddr, bool isbreak)
{
    CommadLineProgress progress;
    progress.Start();

    CBlockIndexSP pindexBlock = pindexBest;
    CBlockIndexSP ppindexBlock;

    int nCount = 0;
    int nCountChainWorkErr = 0;
    int nCountHashNextErr = 0;
    int nCountTriAddrErr = 0;

    CTxDB_Wrapper txdb;

    vector<BLOCKWITHADDR> vecFixingBlocks;

    defer{
        //HC: Fixes the chain
        if (isfix)
            CheckMainChain_fixhlp(vecFixingBlocks);
    };

    while (pindexBlock) {

        if (ischecktriaddr && !pindexBlock->triaddr.isValid()) {
            nCountTriAddrErr++;
            cout << StringFormat("\nWarning: Block(%d %s) triaddr is invalid: %s\n",
                pindexBlock->nHeight, pindexBlock->hashBlock.ToString(), pindexBlock->triaddr.ToString());
            if (isbreak) {
                return "Check break\n";
            }
        }

        ppindexBlock = pindexBlock->pprev();
        if (!ppindexBlock) {

            progress.PrintStatus(1, StringFormat("scanned %d", nCount));
            cout << StringFormat("\nPara chain error: previous block index of block: %d(%s) is nullptr, try to read block data...\n",
                pindexBlock->nHeight, pindexBlock->hashBlock.ToString());

            bool iscontinue = false;
            uint256 hashp = pindexBlock->hashPrev;
            while (1) {
                CBlock block;
                BLOCKTRIPLEADDRESS addrblock;
                char* pWhere = nullptr;

                if (GetBlockData(hashp, block, addrblock, &pWhere)) {

                    nCount++;
                    uint256 hash = block.GetHash();

                    if (isfix) {
                        vecFixingBlocks.push_back({ block, hash, addrblock });
                    }

                    cout << StringFormat("Already got block data(%d) from '(triaddr:%s) %s'\n", block.nHeight, addrblock.ToString(), pWhere);
                    if (mapBlockIndex.count(block.hashPrevBlock)) {
                        nCount++;
                        CBlockIndexSP pindexprev = mapBlockIndex[block.hashPrevBlock];
                        if (pindexprev->hashNext != hash) {
                            //HC: fix hashNext of block index
                            pindexprev->hashNext = hash;

                            txdb.WriteBlockIndex(CDiskBlockIndex(pindexprev.get()));
                            nCountHashNextErr++;
                            cout << StringFormat("Block(%d %s) hashNext error fixed successfully, continue...\n",
                                pindexprev->nHeight, pindexprev->hashBlock.ToString());
                        }
                        pindexBlock = pindexprev;
                        break;
                    }

                    if (block.nHeight <= stopheight) {
                        return StringFormat("\nCheck of Para chain has reached block: %d", block.nHeight);
                    }

                    hashp = block.hashPrevBlock;
                } else {
                    return StringFormat("The block data(%s) cannot be found\n", hashp.ToString());
                }

                if (isbreak) {
                    break;
                }
            }

            if (isbreak) {
                return "Check break\n";
            }
        } else {
            ++nCount;
            if (ppindexBlock->bnChainWork + pindexBlock->GetBlockWork() != pindexBlock->bnChainWork) {
                nCountChainWorkErr++;
                cout << StringFormat("Block(%d %s) bnChainWork error\n",
                    pindexBlock->nHeight, pindexBlock->hashBlock.ToString());
            }

            if (ppindexBlock->hashNext != pindexBlock->hashBlock) {
                //HC: fix hashNext
                ppindexBlock->hashNext = pindexBlock->hashBlock;
                txdb.WriteBlockIndex(CDiskBlockIndex(ppindexBlock.get()));
                nCountHashNextErr++;
                cout << StringFormat("Block(%d %s) hashNext error fixed successfully, continue...\n",
                    ppindexBlock->nHeight, ppindexBlock->hashBlock.ToString());

                if (isbreak) {
                    return "Check break\n";
                }
            }

            pindexBlock = ppindexBlock;
        }

        bool isheightreached = pindexBlock->nHeight <= stopheight;
        if (ppindexBlock == pindexGenesisBlock || isheightreached) {
            progress.PrintStatus(1, StringFormat("scanned %d, (error: hash next: %d, triaddr: %d, chainwork: %d)",
                nCount, nCountHashNextErr, nCountTriAddrErr, nCountChainWorkErr));

            if (ppindexBlock == pindexGenesisBlock)
                return  "\nCheck of Para chain has reached genesis block!\n";
            return StringFormat("\nCheck of Para chain has reached block: %d", pindexBlock->nHeight);
        }

        if (nCount % 1000 == 0) {
            progress.PrintStatus(1000, StringFormat("scanned: %d, (error: hash next: %d, triaddr: %d, chainwork: %d) %d(%s)",
                nCount, nCountHashNextErr, nCountTriAddrErr, nCountChainWorkErr,
                pindexBlock->nHeight, pindexBlock->hashBlock.ToPreViewString()));
        }
    }

    return StringFormat("scanned %d, but cannot reach genesis block\n", nCount);
}


bool AcceptBlocks(vector<T_PAYLOADADDR>& vecPA, const uint256& hhash, bool isLatest)
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
        BLOCKTRIPLEADDRESS btriaddr(b.addr);
        btriaddr.hhash = hhash;
        vecBlockAddr.push_back(btriaddr);
    }

    LatestParaBlock::CompareAndUpdate(vecBlockAddr, vecBlock, isLatest);
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (ProcessBlockWithTriaddr(nullptr, &vecBlock[i], &vecBlockAddr[i])) {
            uint256 hash = vecBlock[i].GetHash();
            TRACE_FL("AcceptBlocks() : (%s) %s is accepted\n\n", vecPA[i].addr.tostring().c_str(),
                hash.ToString().substr(0, 20).c_str());
        } else {
            WARNING_FL("(%s) cannot be accepted\n", vecPA[i].addr.tostring().c_str());
        }
    }

    //HC: cannot use para block in latest hyper block as unique standard of choosing best chain
    return true;
}

extern HyperBlockMsgs hyperblockMsgs;
//HC: Accept a validated Paracoin chain in a hyper block or multiple hyper blocks
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

    //HC: Called by consensus MQ service, switching in case cannot retrieve the cs_main
    //FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        LatestHyperBlock::CompareAndUpdate(hid, thhash, isLatest);
        T_APPTYPE meApp(APPTYPE::paracoin, g_cryptoCurrency.GetHID(),
            g_cryptoCurrency.GetChainNum(),
            g_cryptoCurrency.GetLocalID());
        if (mapPayload.count(meApp)) {
            vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
            uint256 hhash(thhash.toHexString());
            AcceptBlocks(vecPA, hhash, isLatest);

            if (g_miningCond.IsMining()) {
                CBlockIndexSP pIndex = LatestBlockIndexOnChained();
                if (pIndex != pindexBest) {
                    SwitchChainTo(pIndex);
                    INFO_FL("ProcessChainCb: SwitchChainTo %d(%s) because hyper block has changed",
                        pIndex->nHeight, pIndex->hashBlock.ToPreViewString().c_str());
                }
            }
            return true;
        }

        if (isLatest) {
            //HC: Para链切换过程中，需要回退到分叉超块
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

            //HC: Forward to block matched
            //HC: Sometimes Paracoin has already done mining on base of hid, so continue forwarding to latest para block
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
        for (; it != m_list.end() && !fShutdown; ) {
            ProcessChainCb(it->m_mapPayload, it->m_hidFork, it->m_hid, it->m_thhash, it->m_isLatest);
            m_list.erase(it++);
        }
    }
}

size_t HyperBlockMsgs::size()
{
    CRITICAL_BLOCK(m_cs_list)
    {
        return m_list.size();
    }
}

//HC: The following function be called when creating Hyperblock, more see ConsensusEngine::CreateHyperBlock(T_HYPERBLOCK &tHyperBlock)
//HC: CBRET ret = _tP2pManagerStatus->AppCallback<cbindex::CHECKCHAINIDX>
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
        if (i > 0) {
            if (vecBlock[i].nHeight != vecBlock[i - 1].nHeight + 1)
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

//HC: Here why use boost::any as key?
//HC: If use class COutPoint directly, consensus layer need to include many ledger's header files.
bool ValidateLedgerDataCb(T_PAYLOADADDR& payloadaddr,
    map<boost::any, T_LOCALBLOCKADDRESS>& mapOutPt,
    boost::any& hashPrevBlock)
{
    CBlock block;
    if (!ResolveBlock(block, payloadaddr.payload.c_str(), payloadaddr.payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }
    if (hashPrevBlock.empty()) {
        hashPrevBlock = block.hashPrevBlock;
    } else if (block.hashPrevBlock != boost::any_cast<uint256>(hashPrevBlock)) {
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

            //HC: Check against previous transactions
            map<uint256, std::tuple<CTxIndex, CTransaction>> mapUnused;
            int64 nFees = 0;
            if (!tx.ConnectInputs(txdb, mapUnused, CDiskTxPos(1), pindexBest, nFees, false, false)) {
                return ERROR_FL("ConnectInputs failed %s",
                    payloadaddr.addr.tostring().c_str());
            }
        }
    }

    //HC: check the whether have conflicts with input transactions
    for (auto tx : block.vtx) {
        if (tx.IsCoinBase()) {
            continue;
        }
        for (auto vin : tx.vin) {
            if (mapOutPt.count(vin.prevout)) {
                return ERROR_FL("localblock %s confilicts with localblock %s,try to take over the same tx.",
                    payloadaddr.addr.tostring().c_str(),
                    mapOutPt[vin.prevout].tostring().c_str());
            } else {
                mapOutPt.insert(std::make_pair(vin.prevout, payloadaddr.addr));
            }
        }
    }

    return true;
}


//HC: uuidpayload
bool BlockUUIDCb(string& payload, string& uuidpayload)
{
    //HC: don't contain CBlock's hashPrevBlock when calculating the UUID.
    //HC: nVersion
    uuidpayload = payload.substr(0, sizeof(int));
    //HC: ignore hashPrevBlock
    uuidpayload += payload.substr(sizeof(int) + sizeof(uint256));
    return true;
}

//HC: Callback from HyperChain's global consensus, put the Paracoin chain to hyper chain's consensus layer.
bool PutChainCb()
{
    deque<CBlock> deqblock;
    uint256 hhash;

    bool isSwithBestToValid = false;
    CBlockIndexSP pindexValidStarting;

    if (mapArgs.count("-importtx")) {
        //HC: 预写交易模式，等待所有块准备好
        if (!g_isBuiltInBlocksReady) {
            return false;
        }
    }

    INFO_FL("Prepare for committing Para blocks to global consensus...");

    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        //HC: Process hyper block reached message firstly
        hyperblockMsgs.process();

        if (!g_miningCond.IsMining()) {
            INFO_FL("Cannot commit Para chain when it isn't mining.");
            return false;
        }

        uint64 nHID = LatestHyperBlock::GetHID(&hhash);

        //map<int, uint256> mapHIDChecked;
        //CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        //HC: Select blocks to do consensus
        CBlockIndexSP pStart = LatestBlockIndexOnChained();
        pStart = pStart->pnext();
        //while (pStart) {
        //    if (pStart->nPrevHID < nHID) {
        //        if (mapHIDChecked.count(pStart->nPrevHID) && mapHIDChecked[pStart->nPrevHID] == pStart->hashPrevHyperBlock) {
        //            pStart = pStart->pnext();
        //            continue;
        //        }

        //        if (!hyperchainspace->CheckHyperBlockHash(pStart->nPrevHID, to_T_SHA256(pStart->hashPrevHyperBlock))) {
        //            break;
        //        }
        //        mapHIDChecked[pStart->nPrevHID] = pStart->hashPrevHyperBlock;
        //        pStart = pStart->pnext();
        //    } else {
        //        break;
        //    }
        //}

        if (!pStart) {
            //HC: no any block need to commit
            return false;
        }

        INFO_FL("Committing Para blocks from: %d (HID: %d %s)", pStart->nHeight, pStart->nPrevHID, pStart->hashPrevHyperBlock.ToPreViewString().c_str());
        //HC: Get blocks need to commit
        CBlockIndexSP pEnd = pStart;
        while (pEnd && pEnd->nPrevHID == nHID && pEnd->hashPrevHyperBlock == hhash) {

            CBlock block;
            BLOCKTRIPLEADDRESS addrblock;
            char* pWhere = nullptr;
            if (!GetBlockData(pEnd->GetBlockHash(), block, addrblock, &pWhere)) {
                break;
            }

            deqblock.push_back(block);
            pEnd = pEnd->pnext();
        }

        if (!deqblock.size()) {
            //HC: The blocks starting from 'pStart' is stale
            isSwithBestToValid = true;
            pindexValidStarting = pStart->pprev();
            INFO_FL("Committing Para blocks too less: %d, and chain will switch to %d", deqblock.size(), pindexValidStarting->nHeight);
        }

        //HC: Switch chain to valid and return
        if (isSwithBestToValid) {
            SwitchChainTo(pindexValidStarting);
            return false;
        }
    }

    //HC: Commit blocks to hyper chain's consensus layer
    if (deqblock.size() < 2) {
        //HC: do nothing
        INFO_FL("Cannot commit Para chain(len:%d)", deqblock.size());
        return false;
    }
    auto deqiter = deqblock.end();
    auto tail_block = --deqiter;

    auto tail_second_block = --tail_block;
    ++tail_block;

    const CUInt128& mynodeid = getMyNodeID();

    if (!tail_block->ownerNodeID.operator==(mynodeid) &&
        !tail_second_block->ownerNodeID.operator==(mynodeid)) {
        INFO_FL("Cannot commit Para chain(len:%d) because the owner of latest two blocks isn't me.(me: %s, (%d)%s (%d)%s)",
            deqblock.size(), mynodeid.ToHexString().c_str(),
            tail_second_block->nHeight, tail_second_block->ownerNodeID.ToHexString().c_str(),
            tail_block->nHeight, tail_block->ownerNodeID.ToHexString().c_str());
        return false;
    }
    //HC: force owner of last block is me.
    tail_block->ownerNodeID = mynodeid;

    string requestid, errmsg;
    if (!CommitChainToConsensus(deqblock, requestid, errmsg)) {
        ERROR_FL("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

    INFO_FL("Committed Para chain(len:%d) for global consensus.", deqblock.size());
    return true;
}

bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)
{
    FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        CBlockIndexSP p = pindexBest;
        while (p) {
            if (p->triaddr.hid > sAddr.hid) {
                p = p->pprev();
                continue;
            } else if (p->triaddr.hid < sAddr.hid) {
                //HC: I have not data
                return false;
            } else {
                for (; p && p->triaddr.hid <= eAddr.hid;) {
                    vecVPath.push_back(p->triaddr.ToString());
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

template<typename Fn>
void SleepCBFn(int sleepseconds, Fn&& fn)
{
    int i = 0;
    int maxtimes = sleepseconds * 1000 / 200;
    while (i++ < maxtimes) {
        if (fShutdown || fn()) {
            break;
        }
        Sleep(200);
    }
};


extern multimap<uint256, CBlockSP> mapOrphanBlocksByPrev;
void ThreadGetNeighbourChkBlockInfo(void* parg)
{
    int nRequestingNodes = 0;

    while (!fShutdown) {
        CRITICAL_BLOCK(cs_vNodes)
        {
            nRequestingNodes = 0;
            for (auto& node : vNodes) {
                if (node->fSuccessfullyConnected) {
                    if (node->nVersion == 0) {
                        node->PushMessage("veragain");
                    } else {
                        if (time(nullptr) - node->tmlastgotchkp > 180) {
                            node->PushChkBlock();
                        }

                        g_seedserver.updateSSCheckPoint(node->addr, node->chkpoint);
                        node->PushMessage("ping", currentMillisecond());
                    }
                }
            }
        }
        SleepFn(30);
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
    oss << "Paracoin module's current coin name: " << g_cryptoCurrency.GetName() << " - "
        << g_cryptoCurrency.GetHashPrefixOfGenesis() << endl
        << "block message: " << g_cryptoCurrency.GetDesc() << endl
        << "model: " << g_cryptoCurrency.GetModel() << endl
        << "Genesis block address: " << g_cryptoCurrency.GetHID() << " "
        << g_cryptoCurrency.GetChainNum() << " "
        << g_cryptoCurrency.GetLocalID() << endl
        << "Version: " << VERSION << endl
        << "Neighbor node amounts: " << vNodes.size() << ", 'coin n' for details" << endl;

    oss << "Para MQID: " << paramsghandler.details() << endl;
    oss << "ParaMQCenter MQID: " << paramqcenter.MQID() << endl << endl;

    bool isAllowed;
    string reason = g_miningCond.GetMiningStatus(&isAllowed);
    oss << "Mining status: " << (isAllowed ? "mining" : "stopped");

    if (!isAllowed && !reason.empty()) {
        oss << ", " << reason;
    }
    oss << endl;

    if (fGenerateBitcoins) {
        oss << "Block generate enabled\n";
    } else {
        oss << "Block generate disabled, use command 'coin e' to enable\n";
    }

    if (fShutdown) {
        oss << "Paracoin module has been in shutdown state, please restart\n";
    }
    info = oss.str();

    //TRY_CRITICAL_BLOCK_T_MAIN(cs_main)
    try {
        info += "Best block's ";
        if (pindexBest) {
            info += pindexBest->ToString();
        } else {
            info += "CBlockIndex: null\n";
        }

        if (pindexBest && !pindexBest->triaddr.isValid()) {
            int nBacktracing = 60;
            auto pIndex = pindexBest;
            while (pIndex && nBacktracing--) {
                if (pIndex->triaddr.isValid() && pIndex != pindexBest) {
                    info += "In the storage block's ";
                    info += pIndex->ToString();
                    break;
                }
                pIndex = pIndex->pprev();
            }
        }

        info += "Latest Para block's(HyperChainSpace) ";
        CBlockIndexSSP p = LatestParaBlock::Get();
        if (p) {
            info += p->ToString();
        } else {
            info += "CBlockIndex: null\n";
        }
        info += LatestParaBlock::GetMemoryInfo();

        info += strprintf("OrphanBlocks: %u\n", mapOrphanBlocks.size());
        return;
    }
    catch (std::exception& e) {
        info = StringFormat("An exception occurs: %s\n", e.what());
        return;
    }
    catch (...) {
        info = StringFormat("An exception occurs calling %s\n", __FUNCTION__);
        return;
    }

    info += strprintf("Best block height: %d, Latest Para block height: %d\n", nBestHeight, LatestParaBlock::GetHeight());
    info += strprintf("Cannot retrieve the details informations for best block and latest Para block,\n\tbecause the lock: %s, try again after a while",
        CCriticalBlockT<pcstName>::ToString().c_str());
}

bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen)
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

bool getBlockInMain(int height, CBlock& block, string& info)
{
    if (height > pindexBest->nHeight) {
        info = strprintf("Invalid height value, which should <= Best block height: %d\n", nBestHeight);
        return false;
    }

    //HC: make calling pprev rapidly
    CTxDB_Wrapper txdb;

    uint256 hashbegin;
    uint256 hashend;
    if (!paramqcenter.MTC_GetRange(height, hashbegin, hashend)) {
        info = strprintf("The block(height %d) cannot be found in main chain\n", height);
        return false;
    }

    CBlockIndexSP p;
    if (!mapBlockIndex.count(hashend)) {
        info = strprintf("The block(%d, hashend:%s) cannot be found in main chain index\n",
            height,
            hashend.ToString().c_str());
        return false;
    }

    p = mapBlockIndex[hashend];
    while (p) {
        if (p->nHeight <= height) {
            break;
        }
        p = p->pprev();
    }

    if (!p) {
        info = strprintf("The block(%d, range:%s %s) cannot be found in main chain index\n",
            height,
            hashbegin.ToString().c_str(),
            hashend.ToString().c_str());
        return false;
    }

    BLOCKTRIPLEADDRESS addrblock;
    char* pWhere = nullptr;
    if (GetBlockData(p->GetBlockHash(), block, addrblock, &pWhere)) {
        info = block.ToString();
        info += p->ToString();
        return true;
    } else {
        info = p->ToString();
        return false;
    }
}

bool ResolveHeight(int height, string& info)
{
    //HC: Getting lock maybe be unnecessary
    //TRY_CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        CBlock block;
        getBlockInMain(height, block, info);
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

    const string& pubkey = params[0].get_str();
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
    auto ret = CallWithLock(true, [&vchPriKey]() ->Value {
        {
            string errinfo;
            CKey keyPair;
            //keyPair.SetPubKey(publickey);

            CPrivKey privkey;
            privkey.resize(vchPriKey.size());
            std::copy(vchPriKey.begin(), vchPriKey.end(), privkey.begin());

            if (privkey.size() == 0 || !keyPair.SetPrivKey(privkey)) {
                return "Incorrect private key";
            }

            CBitcoinAddress coinaddress;
            coinaddress.SetPubKey(keyPair.GetPubKey());
            cout << StringFormat("Coin address: %s\n", coinaddress.ToString());

            CWallet tmpWallet;
            tmpWallet.AddKey(keyPair.GetPubKey(), keyPair);

            auto pindex = pindexGenesisBlock;
            while (pindex) {
                CBlock blk;
                if (!blk.ReadFromDisk(pindex)) {
                    errinfo = StringFormat("Read Para block error: %s\n", pindex->ToString());
                    goto err;
                }
                for (CTransaction& tx : blk.vtx) {

                    if (tmpWallet.IsMine(tx)) {
                        cout << "+: " << tx.ToString(); //HC: send to me
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

    CallWithLock(true, []() ->Value {
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

typedef struct tagLightMiningInfo {

    string netaddress;
    std::shared_ptr<std::thread> thrd;
    std::mutex mutx;
    bool hasexception = false;
    string exceptioninfo;
    int nRequested = 0;
    int nReplied = 0;
    int nSubmitted = 0;
    bool stopped = false;
    int nStartHeight = 0;
    int nLastHeight = 0;

public:
    string ToString() {
        string str = StringFormat("work requested: %d replied: %d submitted: %d", nRequested, nReplied, nSubmitted);
        if (nSubmitted > 0) {
            str += StringFormat("(height: %d-%d)", nStartHeight, nLastHeight);
        }

        if (hasexception) {
            std::lock_guard lck(mutx);
            return StringFormat("%s: %s (%s)", netaddress, exceptioninfo, str);
        }
        return StringFormat("%s: started (%s)", netaddress, str);
    }
} LightMiningInfo;

static std::map<string, std::shared_ptr<LightMiningInfo>> mapLightNodes;

bool CBFN_LightNodeStop(void* param) {
    LightMiningInfo* LMInfo = (LightMiningInfo*)param;
    if (LMInfo->stopped) {
        return true;
    }
    return false;
}

bool LightNodeDoMining(int blockheight, uint64_t start_nonce,
    const string& strheaderhash,
    const string& strtarget,
    bool (*CBFnStopMining)(void*),
    void* param,
    int timeout,
    unsigned char nonce[8], //HC: if found, return mining result
    unsigned char mixhash[32])
{
    ethash::hash256 header_hash;
    std::vector<unsigned char> vdata = ParseHex(strheaderhash);
    std::copy(vdata.begin(), vdata.end(), header_hash.bytes);

    ethash::hash256 target;
    vdata = ParseHex(strtarget);
    std::copy(vdata.begin(), vdata.end(), target.bytes);

    //isstopmining = false;

    uint32_t epoch = ethash::get_epoch_number(blockheight);
    ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

    uint64_t nMaxTries = 1000000;
    int64 nStart = GetTime();
    progpow::search_result searchresult = progpow::search_light(epoch_ctx, blockheight, header_hash, target, start_nonce, nMaxTries,
        [&nStart, timeout, CBFnStopMining, param]() {
            //HC: Return true means stop mining.
            if (CBFnStopMining(param))
                return true;
            if (GetTime() - nStart >= timeout) {
                return true;
            }
            return false;
        });
    if (searchresult.solution_found) {
        //found, set nonce & mix hash
        memcpy(nonce, &searchresult.nonce, 8);
        memcpy(mixhash, searchresult.mix_hash.bytes, 32);
        return true;
    }
    return false;
}


void ThreadLightNode(LightMiningInfo* info, const string& address)
{
    string server;
    string strPort = "8118";

    size_t found = info->netaddress.find_first_of(':');
    if (found == std::string::npos) {
        server = info->netaddress;
    } else {
        server = info->netaddress.substr(0, found);
        strPort = info->netaddress.substr(found + 1);
    }

    string strPrint;
    int nRet = 0;

    auto FnExcep = [info](const string& excep) {
        std::lock_guard lck(info->mutx);
        info->hasexception = true;
        info->exceptioninfo = excep;
    };

    int nSleepSeconds = 5;
    auto IncreaseSleepTime = [&nSleepSeconds]() {
        if (nSleepSeconds > 120) {
            return;
        }
        nSleepSeconds += 5;
    };

    auto ResetSleepTime = [&nSleepSeconds]() {
        nSleepSeconds = 5;
    };

    while (!info->stopped) {
        Array params;
        params.push_back(address);
        try {
            Object reply = CallRPC("getwork", params, server, strPort);
            info->nRequested++;
            // Parse reply
            const Value& result = find_value(reply, "result");
            const Value& error = find_value(reply, "error");

            if (error.type() != null_type) {
                //HC: Error
                FnExcep("error: " + write_string(error, false));
            } else if (result.type() == obj_type) {
                ResetSleepTime();
                info->nReplied++;
                info->hasexception = false;
                const Object& replychild = result.get_obj();
                int height = find_value(replychild, "height").get_int();
                uint64 start_nonce = find_value(replychild, "startnonce").get_uint64();
                string strheaderhash = find_value(replychild, "headerhash").get_str();
                string strtarget = find_value(replychild, "target").get_str();

                unsigned char nonce[8];
                unsigned char mixhash[32];
                if (LightNodeDoMining(height, start_nonce, strheaderhash, strtarget, CBFN_LightNodeStop, info, 10, nonce, mixhash)) {
                    //HC: mined successfully
                    Array param_submit;
                    param_submit.push_back(strheaderhash);
                    param_submit.push_back(HexStr(BEGIN(nonce), END(nonce)));
                    param_submit.push_back(HexStr(BEGIN(mixhash), END(mixhash)));
                    //HC: commit
                    reply = CallRPC("getwork", param_submit, server, strPort);
                    const Value& resultcommit = find_value(reply, "result");
                    const Value& errorcommit = find_value(reply, "error");

                    if (resultcommit.type() == null_type && errorcommit.type() == null_type) {
                        info->nSubmitted++;
                        if (info->nSubmitted == 1) {
                            info->nStartHeight = height;
                        } else {
                            info->nLastHeight = height;
                        }
                        continue;
                    }

                    if (errorcommit.type() != null_type) {
                        FnExcep("error: " + write_string(errorcommit, false));
                    }
                }
            }
        }
        catch (std::exception& e) {
            FnExcep(e.what());
        }
        catch (...) {
            FnExcep("unknown exception occurred");
        }
        IncreaseSleepTime();
        SleepCBFn(nSleepSeconds, [info]() {
            return info->stopped;
            });
    }
    FnExcep("stopped");
}


void StartLightNodeWork(const string& netaddress)
{
    std::shared_ptr<LightMiningInfo> spInfo;
    if (mapLightNodes.count(netaddress)) {
        spInfo = mapLightNodes[netaddress];
        if (!spInfo->stopped) {
            //HC: already started
            return;
        }
    } else {
        spInfo = make_shared<LightMiningInfo>();
        spInfo->netaddress = netaddress;
        mapLightNodes[netaddress] = spInfo;
    }

    CBitcoinAddress address = pwalletMain->GetDefaultKeyAddress();
    spInfo->stopped = false;
    spInfo->thrd = make_shared<thread>(ThreadLightNode, spInfo.get(), address.ToString());
}

void StartAllLightNodesWork()
{
    for (auto& lnode : mapLightNodes) {
        StartLightNodeWork(lnode.second->netaddress);
    }
}

void StopLightNodeWork(const string& netaddress)
{
    if (mapLightNodes.count(netaddress)) {
        auto& lnode = mapLightNodes[netaddress];
        lnode->stopped = true;
        if (lnode->thrd->joinable()) {
            lnode->thrd->join();
        }
    }
}


void StopAllLightNodesWork()
{
    for (auto& lnode : mapLightNodes) {
        lnode.second->stopped = true;
        if (lnode.second->thrd->joinable()) {
            lnode.second->thrd->join();
        }
    }
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
    //oss << "       coin addrba [address]...           : scan wallet for addresses balances\n"; //HC: there are bugs to be fixed
    oss << "       coin addr [account]                : query account addresses\n";
    oss << "       coin sendfrom <fromaccount> <toaddress> <amount> : transfer\n";
    oss << "       coin sendtoaddr <address> <amount> : transfer\n";
    oss << "       coin e                             : enable mining\n";
    oss << "       coin d                             : disable mining\n";
    oss << "       coin tx <txid>                     : get detailed information about <txid>\n";
    oss << "       coin txs [account] [count=10] [from=0] : list transactions, '*' means default account\n";
    oss << "       coin sfee <amount>                 : set fee for transaction\n";
    oss << "       coin ginfo                         : query various state info\n";

    oss << "       coin n [s] [extra index]           : query my neighbors\n";

    oss << "       coin encw <passphrase>             : encrypts the wallet with <passphrase>\n";
    oss << "       coin wpass <passphrase> <timeout=10>  : stores the wallet decryption key in memory for <timeout> seconds\n";
    oss << "       coin chwpass <old> <new>           : change the wallet passphrase from <old> to <new>\n";

    oss << "       coin gkp                           : generate a public-private key pair\n";
    oss << "       coin ikp <private key>             : import a public-private key pair(support WIF, WIF-compressed and hex format)\n";
    oss << "       coin ekp <address>                 : export the public-private key pair corresponding to <address> to console\n";
    oss << "       coin ikpf <filename>               : import private keys from <filename>\n";
    oss << "       coin ekpf <filename> [WIF|WIFC]    : export private keys to <filename>, default format is WIFC\n";
    oss << "       coin dkp [address]                 : query or specify default address\n";

    oss << "       coin sacc <address> <account>      : sets the account associated with the given address\n";
    oss << "       coin ln [start|stop] [IP:Port]     : display status of work or start/stop work as a light node\n";

    return oss.str();
}

extern string GetCommandsCost();

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
                        //HC: current using coin
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

            //HC: iss
            {"iss",[](const list<string>& l, bool fhelp) ->string {
                return doAction(issuecoin, l, fhelp, false);
            } },

            {"imp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(importcoin, l, fhelp, false);
            } },

            {"getbalance",[](const list<string>& l, bool fhelp) ->string {
                //HC: add lock, else it is possible to cause deadlock when read block index
                return doAction(getbalance, l, fhelp, true);
                //return doAction(listaccounts, l, fhelp, true);
            } },

            {"acc",[](const list<string>& l, bool fhelp) ->string {
                //HC: add lock, else It is possible to cause deadlock when read block index
                return doAction(listaccounts, l, fhelp, true);
            } },


            {"addr",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 1) {
                    list<string> ll;
                    ll.push_back("");
                    return doAction(getaddressesbyaccount, ll, fhelp);
                }

                return doAction(getaddressesbyaccount, l, fhelp, false);
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
                        double amount = std::strtod(cmd->c_str(), &end); //HC: change to double type
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };
                return doAction(sendfrom, l, fhelp, true, conv);
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
                        double amount = std::strtod(cmd->c_str(), &end); //HC: change to double type
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };
                return doAction(sendtoaddress, l, fhelp, true, conv);
            } },

            //HC: light node
            { "ln",[](const list<string>& l, bool fhelp) ->string {

                for (auto iter = l.begin(); iter != l.end(); ++iter) {
                    if (*iter == "start") {
                        ++iter;
                        if (iter != l.end()) {
                            string s = *iter;
                            StartLightNodeWork(s);
                        } else {
                            StartAllLightNodesWork();
                        }
                        return "started!";
                    } else if (*iter == "stop") {
                        ++iter;
                        if (iter != l.end()) {
                            string s = *iter;
                            StopLightNodeWork(s);
                        } else {
                            StopAllLightNodesWork();
                        }
                        return "stopped!";
                    }
                }

                stringstream ss;
                for (auto& elm : mapLightNodes) {
                    ss << elm.second->ToString() << endl;
                }
                if (ss.str().empty()) {
                    return "Works of light nodes have not started";
                }
                return ss.str();
            } },

            { "e",[](const list<string>& l, bool fhelp) ->string {
                Array arr;
                arr.push_back(true);
                Value ret = setgenerate(arr, false);
                if (ret.is_null())
                     return "Mining is started";

                return write_string(ret, true);
            } },

            { "d",[](const list<string>& l, bool fhelp) ->string {
                Array arr;
                arr.push_back(false);
                Value ret = setgenerate(arr, false);
                if (ret.is_null()) {
                    if (!l.empty()) {
                        string para = l.front();
                        if (para.compare("versionlow") == 0)
                            g_miningCond.SetMiningStatusCode(MiningCondition::miningstatuscode::VersionLow);
                    }

                    return "Mining is stopped";
                }
                return write_string(ret, true);
            } },

            { "tx",[](const list<string>& l, bool fhelp) ->string {
                return doAction(gettransaction, l, fhelp, false);
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

               return doAction(listtransactions, l, fhelp, false, conv);
            } },

            { "sfee",[](const list<string>& l, bool fhelp) ->string {
                std::function<Array(const list<string>&)> conv = [](auto& cmdlist) ->Array {
                    Array arr;
                    auto cmd = cmdlist.begin();
                    do {
                        if (cmd == cmdlist.end()) break;
                        char* end = nullptr;
                        double amount = std::strtod(cmd->c_str(), &end); //HC: change to double type
                        arr.push_back(amount);
                        break;
                    } while (true);
                    return arr;
                };

               return doAction(settxfee, l, fhelp, false, conv);
            } },

            { "ginfo",[](const list<string>& l, bool fhelp) ->string {
               return doAction(getinfo, l, fhelp, false);
            } },

             //HC: ikp
            { "ikp",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                return doAction([&savingcommand](const Array& params, bool fHelp) ->string {
                    if (fHelp || params.size() < 1)
                        throw runtime_error(
                            "coin ikp <private key>: import a public-private key pair");

                    savingcommand = "c ikp";
                    string msg;
                    string label;

                    if (params.size() > 1) {
                        label = params[1].get_str();
                    }

                    impwalletkey(params[0].get_str(), label, msg);
                    return msg;

                }, l, fhelp, false);
            } },

            //HC: ekp
            { "ekp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(expwalletkey, l, fhelp, false);
            } },

            { "sacc",[](const list<string>& l, bool fhelp) ->string {
                return doAction(setaccount, l, fhelp, false);
            } },

             //HC: ikpf
            {"ikpf",[](const list<string>& l, bool fhelp) ->string {
                return doAction(impwalletkeysfromfile, l, fhelp, false);
            } },

             //HC: ekpf
            { "ekpf",[](const list<string>& l, bool fhelp) ->string {
                return doAction(expwalletkeystofile, l, fhelp, false);
            } },

            { "gkp",[](const list<string>& l, bool fhelp) ->string {
                return MakeNewKeyPair();
            } },

            //HC: dkp
            { "dkp",[](const list<string>& l, bool fhelp) ->string {
                return doAction(setdefaultkey, l, fhelp, false);
            } },

             //HC: encw
            { "encw",[](const list<string>& l, bool fhelp) ->string {
                return doAction(encryptwallet, l, fhelp, false);
            } },

            //HC: wpass
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
                return doAction(walletpassphrase, l, fhelp, false, conv);
            } },

             //HC: chwpass
            { "chwpass",[&savingcommand](const list<string>& l, bool fhelp) ->string {
                if(l.size() != 0)
                    savingcommand = "c chwpass";
                return doAction(walletpassphrasechange, l, fhelp, false);
            } },

            { "qtx",[](const list<string>& l, bool fhelp) ->string {
                 if (l.size() == 0)
                     return "c qtx <private key>";

                 auto cmd = l.begin();
                 std::vector<unsigned char> privatekey;
                 privatekey = ParseHex(*cmd);
                 ScanChainForTxes(privatekey);
                 return "";
            } },

            { "n", [](const list<string>& l, bool fhelp) ->string {

                int idx = 0;
                bool onlyshowseedserver = false;

                //HC: bExchk means show block info : idx * (CBlockLocatorEx::nHeightSpan)
                bool bExChk = false;

                for (auto iter = l.begin(); iter != l.end(); ++iter) {
                    if (*iter == "s") {
                        onlyshowseedserver = true;
                        continue;
                    }
                    idx = std::atoi(iter->c_str());
                    bExChk = true;
                }

                string strExInfo;
                string strMy = strprintf("My version: %d ", VERSION);
                //TRY_CRITICAL_BLOCK_T_MAIN(cs_main)
                {
                    ChkPoint::GetCurrent(mychkp);
                    //cp.chainloc = maintrunkchain;
                    if (bExChk) {
                        strExInfo = paramqcenter.MTC_ToString(idx);//cp.chainloc.ToString(idx);
                    }
                    strMy += strprintf("%s ex: %s", mychkp.ToString().c_str(), strExInfo.c_str());
                }

                string strNodes;

                TRY_CRITICAL_BLOCK(cs_vNodes)
                {
                    for (auto& node : vNodes) {
                        bool isss = g_seedserver.isSeedServer(node->addr);
                        if (onlyshowseedserver) {
                            if (!isss) {
                                continue;
                            }
                        }

                        if (bExChk) {
                            strExInfo = node->chkpoint.chainloc.ToString(idx);
                        } else {
                            strExInfo = " ";
                        }

                        string details = strprintf("  %s(%s)\t\tversion: %d    pingpong: %u(ms) \n\t\t%s ex: %s\n",
                            node->addr.ToStringIPPort().c_str(),
                            node->nodeid.c_str(),
                            node->nVersion, node->nAvgPingCost,
                            node->chkpoint.ToString().c_str(),
                            strExInfo.c_str());

                        if (isss) {
                            details[0] = '*';
                            strNodes.insert(0, details);
                        } else {
                            strNodes += details;
                        }
                    }
                    strNodes += strprintf("%s\nTotal neighbor number: %d", strMy.c_str(), vNodes.size());
                    return strNodes;
                }
                strNodes = strprintf("%s\nBusying", strMy.c_str());
                return strNodes;
            } },

            { "readtxbyaddr",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 4) {
                    return "Input tx's address, like: [HID ChainID ID NO.]";
                }

                auto cmd = l.begin();
                int hID = std::stoi(*cmd++);
                int chainID = std::stoi(*cmd++);
                int ID = std::stoi(*cmd++);
                int nTx = std::stoi(*cmd);

                T_LOCALBLOCKADDRESS addrblock;
                addrblock.set(hID, chainID, ID);

                CBlock blk;
                if (blk.ReadFromDisk(addrblock)) {
                    if (nTx < 0) {
                        nTx = 0;
                    }
                    if (nTx >= blk.vtx.size()) {
                        nTx = blk.vtx.size() - 1;
                    }
                    return strprintf("Address: %s tx: %d\nBlock: %s\nTx: %s", addrblock.tostring().c_str(), nTx,
                        blk.ToString().c_str(),
                        blk.vtx[nTx].ToString().c_str());
                }
                return strprintf("Failed to read block from address: %s %d", addrblock.tostring().c_str(), nTx);
            } },

            //HC: by height
            { "readtxbyh",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 2) {
                    return "Input tx's address, like: [Height NO.]";
                }

                auto cmd = l.begin();
                int height = std::stoi(*cmd++);
                int nTx = std::stoi(*cmd);

                uint256 hashbegin;
                uint256 hashend;
                if (!paramqcenter.MTC_GetRange(height, hashbegin, hashend)) {
                    return strprintf("The block(height %d) cannot be found in main chain\n", height);
                }

                auto p = mapBlockIndex[hashend];
                while (p && p->nHeight > height) {
                    p = p->pprev();
                }

                CBlock blk;
                if (blk.ReadFromDisk(p)) {
                    if (nTx < 0 || nTx >= blk.vtx.size()) {
                        return strprintf("Invalid parameter, Tx number range should be 0 ~ %d", blk.vtx.size());
                    }
                    return strprintf("Height: %d tx: %d\nBlock: %s\nTx: %s", height, nTx,
                        blk.ToString().c_str(),
                        blk.vtx[nTx].ToString().c_str());
                }
                return strprintf("Failed to read block from address: %d %d", height, nTx);
            } },


            { "readtx",[](const list<string>& l, bool fhelp) ->string {
                return doAction(getrawtransaction, l, fhelp, false);
            } },

            { "readblk",[](const list<string>& l, bool fhelp) ->string {

                string strHash;
                if (l.size() <= 0) {
                    return "Input block's hash";
                }

                strHash = *l.begin();
                uint256 hashblock(strHash);

                CBlock block;
                BLOCKTRIPLEADDRESS tripleaddr;
                string strWhere;
                bool isgot = false;

                auto mi = mapBlockIndex[hashblock];
                if (mi) {
                    if (block.ReadFromDisk(mi)) {
                        tripleaddr = mi->triaddr;
                        bool isInMain = mi->IsInMainChain();
                        strWhere = strprintf("Triaddr: %s Where: mapBlockIndex, IsInMainChain: %d, hashNext: %s\n",
                            tripleaddr.ToString().c_str(), isInMain,
                            mi->hashNext.ToPreViewString().c_str());
                        isgot = true;
                    }
                } else {
                    strWhere = "cannot found in mapBlockIndex\n";
                }

                if (!isgot && block.ReadFromMemoryPool(hashblock)) {
                    strWhere += "Triaddr: nullptr Where: block cache\n";
                }

                if (mapOrphanBlocks.count(hashblock)) {
                    block = *(mapOrphanBlocks[hashblock]);
                    isgot = true;
                    if (COrphanBlockTripleAddressDB().ReadBlockTripleAddress(hashblock, tripleaddr)) {
                        strWhere += strprintf("Triaddr: %s Where: mapOrphanBlocks\n", tripleaddr.ToString().c_str());
                    }
                }

                if (LatestParaBlock::Count(hashblock)) {
                    if (LatestParaBlock::GetBlock(hashblock, block, tripleaddr)) {
                        isgot = true;
                        strWhere += strprintf("Triaddr: %s Where: LatestParaBlock\n", tripleaddr.ToString().c_str());
                    }
                }

                if (isgot) {
                    return strprintf("%s\nLocation: %s\n", block.ToString().c_str(), strWhere.c_str());
                }
                return strprintf("Block cannot be found, %s\n", strWhere.c_str());
            } },

            { "addrba",[](const list<string>& l, bool fhelp) ->string {
                return doAction(listaddrbalance, l, fhelp, false);
            } },

            //HC: use to test,manually switch Para chain to a specified height
            { "sw",[](const list<string>& l, bool fhelp) ->string {
                if (l.size() < 1 || fhelp) {
                    return doAction(SwitchChainToHyperHeight, l, true);
                }

                cout << "Are you sure you want to switch? (y/n) ";
                string sInput;
                cin >> sInput;
                if (sInput == "y" || sInput == "Y") {
                    CRITICAL_BLOCK(cs_main)
                    {
                        return doAction(SwitchChainToHyperHeight, l, fhelp);
                    }
                }
                return "Do nothing";
            } },

            { "findblkinmain",[](const list<string>& l, bool fhelp) ->string {
                if (l.size() < 2 || fhelp) {
                    return doAction(FindBlkInMainFromBlock, l, true);
                }

                cout << "Are you sure you want to find the block in main chain? (y/n) ";
                string sInput;
                cin >> sInput;
                if (sInput == "y" || sInput == "Y") {
                    Array a = toArray(l);
                    FindBlkInMainFromBlock(a, false);
                    return "\n";
                }
                return "Do nothing";
            } },

            { "checkchain",[](const list<string>& l, bool fhelp) ->string {

                bool isfix = false;
                bool ischecktriaddr = false;
                bool isbreak = false;
                int nstopheight = 0;
                if (l.size() < 1) {
                    cout << "Check block indexes of the whole chain from best height to [h], including index's member: hashNext, bChainWork, triaddr\n" \
                        "option: 'f': check and fix chain\n" \
                        "\t'triaddr': check block's triple address\n" \
                        "\t'b': break execution when chain has an error\n" \
                        "\t[h]: once block height is [h], stop checking\n" \
                        "\tfor example: c checkchain; c checkchain f 10000; c checkchain triaddr b\n";
                } else {
                    for (auto iter = l.begin(); iter != l.end(); ++iter) {
                        if (*iter == "f") {
                            isfix = true;
                            continue;
                        }
                        if (*iter == "triaddr") {
                            ischecktriaddr = true;
                            continue;
                        }
                        if (*iter == "b") {
                            isbreak = true;
                            continue;
                        }

                        nstopheight = std::atoi(iter->c_str());
                    }
                }

                cout << StringFormat("Are you sure you want to %s the chain until block height: %d? (y/n) ", isfix ? "check and fix" : "check", nstopheight);

                string sInput;
                cin >> sInput;
                if (sInput == "y" || sInput == "Y") {
                    CRITICAL_BLOCK(cs_main)
                        return CheckMainChain(nstopheight, isfix, ischecktriaddr, isbreak);
                }
                return "Do nothing";
            } },

            { "upgradeblkidx",[](const list<string>& l, bool fhelp) ->string {
                int nH = 0;
                for (auto iter = l.begin(); iter != l.end(); ++iter) {
                     nH = std::atoi(iter->c_str());
                     break;
                }
                cout << StringFormat("Upgrading from Para block height: maximum(%d) to %d, are you sure you want to upgrade? (y/n) ",
                    pindexBest->nHeight, nH);
                string sInput;
                cin >> sInput;
                if (sInput == "y" || sInput == "Y") {
                    CRITICAL_BLOCK(cs_main)
                    {
                        CTxDB_Wrapper txdb("r+");
                        UpgradeBlockIndex(txdb, nH);
                        return "Ok";
                    }
                    return "Busying";
                }
                return "Do nothing";
            } },

            { "fixblkidx",[](const list<string>& l, bool fhelp) ->string {

                if (l.size() < 2) {
                    return "Input Hyperblock height range: h1 h2";
                }
                auto iter = l.begin();
                int nH = std::atoi(iter->c_str());
                ++iter;
                int nHEnd = std::atoi(iter->c_str());

                cout << StringFormat("Scanning HyperBlock from %d to %d, are you sure you want to continue? (y/n) ",
                     nH, nHEnd);
                string sInput;
                cin >> sInput;
                if (sInput == "y" || sInput == "Y") {
                    CRITICAL_BLOCK(cs_main)
                    {
                        CTxDB_Wrapper txdb("r+");
                        FixBlockIndexByHyperBlock(txdb, nH, nHEnd);
                        return "Ok";
                    }
                    return "Busying";
                }
                return "Do nothing";
            } },

            { "cleanblkidx",[](const list<string>& l, bool fhelp) ->string {

                CRITICAL_BLOCK(cs_main)
                {
                    CTxDB_Wrapper txdb("r+");
                    txdb.CleanaBlockIndex();
                    return "Ok, please restart Para module or the whole program.";
                }
                return "Busying";
            } },

            { "fixchainwork",[](const list<string>& l, bool fhelp) ->string {

                CRITICAL_BLOCK(cs_main)
                {
                    return FixChainWork();
                }
                return "Busying";
            } },

            { "showchain",[](const list<string>& l, bool fhelp) ->string {

                int nIdx = 0;
                int nIdxTail = 0;

                auto iter = l.begin();
                if (iter != l.end()) {
                    nIdx = std::atoi(iter->c_str());
                    ++iter;
                }
                if (iter != l.end()) {
                    nIdxTail = std::atoi(iter->c_str());
                }

                return paramqcenter.MTC_ToDetailString(nIdx, nIdxTail);
            } },

            //HC: remove tx index not in main chain
            { "cleantx",[](const list<string>& l, bool fhelp) ->string {

                TRY_CRITICAL_BLOCK(cs_main)
                {
                    cout << "Load Txes in best chain...\n";

                    CommadLineProgress progress;
                    progress.Start();

                    auto p = pindexBest;
                    map<uint256, int> mapTxes;
                    while (p && p->nHeight >= 0 && !fShutdown) {
                        CBlock blk;
                        if (blk.ReadFromDisk(p)) {
                            for (size_t i = 0; i < blk.vtx.size(); i++) 		{
                                mapTxes[blk.vtx[i].GetHash()] = p->nHeight;
                                if (mapTxes.size() % 10000 == 0) {
                                    progress.PrintStatus(10000, StringFormat("Reading from block: %d", p->nHeight));
                                }
                            }
                        }
                        p = p->pprev();
                    }

                    cout << "\nLoad Txes in database...\n";
                    progress.Start();

                    size_t nTxNum = 0;
                    vector<uint256> vtxDelete;
                    CTxDB_Wrapper txdb;
                    txdb.Load("tx", [&progress, &mapTxes, &vtxDelete, &nTxNum](CDataStream& ssKey, CDataStream& ssValue) ->bool {
                        uint256 hash;
                        ssKey >> hash;

                        if (!mapTxes.count(hash)) {
                            //HC:
                            vtxDelete.push_back(hash);
                        }

                        nTxNum++;
                        if (nTxNum % 10000 == 0) {
                            progress.PrintStatus(10000, StringFormat("Scanned: %d, invalid: %d", nTxNum, vtxDelete.size()));
                        }

                        return true;
                    });

                    cout << StringFormat("\n%d Txes will be erased, they are not in best chain...\n", vtxDelete.size());
                    txdb.TxnBegin();
                    for (auto &tx : vtxDelete) {
                        txdb.EraseTxIndex(tx);
                    }
                    txdb.TxnCommit();
                    cout << StringFormat("%d Txes have been erased\n", vtxDelete.size());
                    return "";
                }
                return "Busying";
            } },


            { "fixtxidx",[](const list<string>& l, bool fhelp) ->string {

                string strHash;
                if (l.size() < 3) {
                    return "Input <tx's hash> <nTxPos> <hashblock>";
                }

                auto cmd = l.begin();

                strHash = *cmd++;
                int nTxPos = std::stoi(*cmd++);;
                string strHashBlk = *cmd;

                CTxDB_Wrapper txdb;
                CTxIndex txindex;
                uint256 hash(strHash);
                uint256 hashB(strHashBlk);
                bool fFound = txdb.ReadTxIndex(hash, txindex);

                if (fFound) {
                    txindex.pos.nTxPos = nTxPos;
                    txindex.pos.hashBlk = hashB;
                    if (txdb.UpdateTxIndex(hash, txindex)) {
                        return "Ok";
                    }
                    return "Txindex cannot be changed";
                }
                return "Txindex no found";
            } },


            { "scantx",[](const list<string>& l, bool fhelp) ->string {

                TRY_CRITICAL_BLOCK(cs_main)
                {
                    cout << "Load Txes in best chain...\n";

                    CommadLineProgress progress;
                    progress.Start();

                    map<uint256, int> mapTxes;

                    int nLastHeight;
                    int nNonCoinBaseTx = 0;
                    auto p = pindexGenesisBlock;
                    while (p && p->nHeight <= pindexBest->nHeight && !fShutdown) {
                        CBlock blk;
                        if (blk.ReadFromDisk(p)) {
                            for (size_t i = 0; i < blk.vtx.size(); i++) {
                                auto& tx = blk.vtx[i];
                                mapTxes[tx.GetHash()] = p->nHeight;
                                if (!tx.IsCoinBase()) {
                                    for (auto & txin : tx.vin) {
                                        nNonCoinBaseTx++;
                                        if (!mapTxes.count(txin.prevout.hash)) {
                                            cout << StringFormat("Found invalid tx (height: %d) : %s (in: %s)\n",
                                                blk.nHeight, tx.GetHash().ToString(), txin.prevout.hash.ToPreViewString());
                                        }
                                    }
                                }
                                if (mapTxes.size() % 10000 == 0) {
                                    progress.PrintStatus(10000, StringFormat("Reading from block: %d, Non-coinbase Tx num: %d", p->nHeight, nNonCoinBaseTx));
                                }
                            }
                        } else {
                            cout << StringFormat("Failed to read block: %d(%s)\n", p->nHeight, p->GetBlockHash().ToPreViewString());
                        }
                        nLastHeight = p->nHeight;
                        p = p->pnext();
                    }
                    progress.PrintStatus(mapTxes.size() % 10000,
                        StringFormat("Reading from block: %d, best height: %d, Non-coinbase Tx num: %d", nLastHeight, pindexBest->nHeight, nNonCoinBaseTx));

                    return "";
                }
                return "Busying";
            } },

            { "scancoinbase",[](const list<string>& cmdlist, bool fhelp) ->string {

                if (cmdlist.size() < 1) {
                    return "c scancoinbase <height> [block count]\n";
                }

                int nH = 0;
                int nCount = 1;
                auto cmd = cmdlist.begin();
                do {
                    nH = std::atoi(cmd->c_str());

                    cmd++;
                    if (cmd == cmdlist.end()) break;
                    nCount = std::atoi(cmd->c_str());
                } while (false);

                CommadLineProgress progress;
                progress.Start();
                CRITICAL_BLOCK(cs_main) {

                    int nCoinBaseTx = 0;
                    int nCoinBaseTxErr = 0;
                    int nFixed = 0;

                    CTxDB_Wrapper txdb;
                    txdb.TxnBegin();
                    for (int iH = nH; iH < nH + nCount; iH++) {
                        string info;
                        CBlock blk;
                        if (!getBlockInMain(iH, blk, info)) {
                            cout << "not found the block:" << iH << endl;
                            continue;
                        }

                        auto& tx = blk.vtx[0];
                        if (!tx.IsCoinBase()) {
                            continue;
                        }

                        nCoinBaseTx++;

                        uint256 txhash = tx.GetHash();

                        //check if tx is in disk, if not, fix
                        CTxIndex txindex;
                        if (!txdb.ReadTxIndex(txhash, txindex)) {
                            nCoinBaseTxErr++;
                            unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 2 + GetSizeOfCompactSize(blk.vtx.size());
                            CDiskTxPos posThisTx(nTxPos, blk.nHeight, blk.GetHash());
                            txindex = CTxIndex(posThisTx, tx.vout.size());
                            if (!txdb.UpdateTxIndex(txhash, txindex)) {
                                cout << StringFormat("Cannot fix when calling UpdateTxIndex (%d: %s)\n", blk.nHeight, tx.GetHash().ToString());
                            } else {
                                nFixed++;
                            }
                        }

                        if (nCoinBaseTx % 10 == 0) {
                            progress.PrintStatus(10, StringFormat("scanning block: %d, coinbase Tx scanned: %d, error: %d, fixed: %d",
                                iH, nCoinBaseTx, nCoinBaseTxErr, nFixed));
                        }

                    }
                    txdb.TxnCommit();
                    progress.PrintStatus(nCoinBaseTx - progress.GetCount(), StringFormat("scanning block: %d, coinbase Tx scanned: %d, error: %d, fixed: %d",
                            nH + nCount - 1, nCoinBaseTx, nCoinBaseTxErr, nFixed));
                    return "";
                }
                return "Busying";
            } },

            { "recv",[](const list<string>& l, bool fhelp) ->string {
                return StringFormat("%s\n%s\n%s", recver.GetStatus(), CCriticalBlockT<pcstName>::ToDetailString(),
                    GetCommandsCost());
            } },

             //HC: query a public key if it belongs to me or not.
            { "myk",[](const list<string>& l, bool fhelp) ->string {
                return doAction(IsMyPublickey, l, fhelp, false);
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

    if (childcmd == "v") {
        for (auto& cmd : mapcmds) {
            info += StringFormat("%s\n", cmd.first);
        }
        return true;
    }

    bool isMQStopper = paramsghandler.isstopped();
    bool isCenterStopper = paramqcenter.GetMsgHandler().isstopped();
    if (isMQStopper || isCenterStopper) {
        info = strprintf("Para MQ handler(center) is %s(%s), please restart Para module\n",
            isMQStopper ? "stopped" : "started",
            isCenterStopper ? "stopped" : "started");
        return true;
    }

    if (mapcmds.count(childcmd)) {
        info = mapcmds[childcmd](cpycmdlist, false);
        return true;
    }
    info = strprintf("Child command '%s' doesn't exist\n", childcmd.c_str());
    return true;
}

