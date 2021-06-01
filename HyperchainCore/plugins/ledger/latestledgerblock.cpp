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
#include "headers.h"
#include "ledgermain.h"
#include "latestledgerblock.h"

#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"
#include "node/NodeManager.h"

#include "cryptotoken.h"


#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <cstdio>

using namespace std;
using namespace boost;

extern CWallet* pwalletMain;
ChainReadyCondition g_chainReadyCond;
BlockCheckPoint g_blockChckPnt;
extern HyperBlockMsgs hyperblockMsgs;
extern CAddress g_seedserver;
extern map<uint256, CBlockSP> mapOrphanBlocks;
extern multimap<uint256, CBlockSP> mapOrphanBlocksByPrev;
extern CBlockCacheLocator mapBlocks;

std::atomic_bool g_isBuiltInBlocksReady{ false };


extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern void CheckBlockIndex(CTxDB* txdb);
extern bool SwitchChainTo(CBlockIndex *pindexBlock);

extern void outputlog(const string& msg);

uint32_t LatestHyperBlock::_hid  = 0;
uint256 LatestHyperBlock::_hhash = 0;
CCriticalSection LatestHyperBlock::_cs_latestHyperBlock;

int LatestLedgerBlock::_nLatestLedgerHeight = 0;
CBlockIndexSimplified* LatestLedgerBlock::_pindexLatest = nullptr;
CBlockIndexSimplified* LatestLedgerBlock::_pindexLatestRoot = nullptr;

map<uint256, CBlockIndexSimplified*> LatestLedgerBlock::_mapBlockIndexLatest;
CBlockDiskLocator LatestLedgerBlock::_mapBlockAddressOnDisk;



void LatestLedgerBlock::Load()
{
    _pindexLatestRoot = nullptr;

    CBlockTripleAddressDB btadb("cr+");

    uint32 maxhidInDB = 0;
    btadb.ReadMaxHID(maxhidInDB);

    LoadLatestBlock(maxhidInDB);


    btadb.LoadBlockTripleAddress();

    btadb.Close();

    cout << StringFormat("\tLedger block indexes loaded, maximum hid %d\n", maxhidInDB);

    return;
}

void LatestLedgerBlock::CompareAndUpdate(const vector<T_PAYLOADADDR> &vecPA, bool isLatest)
{
    vector<BLOCKTRIPLEADDRESS> vecAddrIn;
    vector<CBlock> vecBlockIn;

    auto pa = vecPA.begin();
    for (; pa != vecPA.end(); ++pa) {
        CBlock block;
        if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
            continue;
        }
        vecAddrIn.push_back(BLOCKTRIPLEADDRESS(pa->addr));
        vecBlockIn.push_back(block);
    }

    CompareAndUpdate(vecAddrIn, vecBlockIn, true);
}

void LatestLedgerBlock::CompareAndUpdate(const vector<BLOCKTRIPLEADDRESS>& vecAddrIn, const vector<CBlock>& vecBlockIn, bool isLatest)
{
    CBlockTripleAddressDB btadb;

    uint32 hid = LatestHyperBlock::GetHID();
    size_t len = vecBlockIn.size();
    if (len == 0) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        uint256 hashBlock = vecBlockIn[i].GetHash();
        if (!_mapBlockAddressOnDisk.contain(hashBlock)) {
            _mapBlockAddressOnDisk.insert(btadb, hashBlock, vecAddrIn[i]);
        }

        if (_mapBlockIndexLatest.count(hashBlock)) {
            _mapBlockIndexLatest[hashBlock]->addr = vecAddrIn[i].ToAddr();
            continue;
        }
    }

    bool ishavingblkupdated = false;
    if(!isLatest)
        ishavingblkupdated = (_pindexLatest && _pindexLatest->addr < vecAddrIn.back().ToAddr());

    if (isLatest || ishavingblkupdated) {
         btadb.WriteMaxHID(vecAddrIn[0].hid);
    }

    btadb.Close();

    if (isLatest || ishavingblkupdated) {
        for (size_t i = 0; i < len; i++) {
            const uint256& hashPrev = vecBlockIn[i].hashPrevBlock;
            if ( _pindexLatest->GetBlockHash() == hashPrev) {

                SetBestIndex(AddBlockIndex(vecAddrIn[i].ToAddr(), vecBlockIn[i]));
            }
            else {

                _pindexLatestRoot = InsertBlockIndex(hashPrev);
                SetBestIndex(AddBlockIndex(vecAddrIn[i].ToAddr(), vecBlockIn[i]));
            }
        }
    }
}


string LatestLedgerBlock::GetMemoryInfo()
{
    return strprintf("LatestLedgerBlock's mapBlockAddressOnDisk size: %u\n"
        "LatestLedgerBlock's mapBlockIndexLatest size: %u\n",
        _mapBlockAddressOnDisk.size(), _mapBlockIndexLatest.size());
}


bool LatestLedgerBlock::Count(const uint256& hastblock)
{
    return _mapBlockAddressOnDisk.contain(hastblock) ||
        (_mapBlockIndexLatest.count(hastblock) && hastblock != GetBackSearchHash());
}

void LatestLedgerBlock::AddBlockTripleAddress(const uint256& hastblock, const BLOCKTRIPLEADDRESS& tripleaddr)
{
    _mapBlockAddressOnDisk.insertBloomFilter(hastblock);
}


void LatestLedgerBlock::Switch()
{
    if (!_pindexLatest || !_pindexLatestRoot) {
        return;
    }

    int64 nStartTime = GetTime();
    int nCount = 0;




    CTxDB_Wrapper txdb;
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);
    CBlockDB_Wrapper blkdb;
    COrphanBlockDB_Wrapper orphanblkdb;

    CBlockIndexSimplified* pIndex = _pindexLatestRoot;
    for (; pIndex && !fShutdown; pIndex = pIndex->pnext) {

        uint256 hash = *pIndex->phashBlock;
        bool isInOrphanPool = false;
        CBlock block;
        if (!block.ReadFromDisk(pIndex)) {
            if (mapOrphanBlocks.count(hash)) {
                block = *mapOrphanBlocks[hash];
                isInOrphanPool = true;
            }
            else {

                COrphanBlockDB_Wrapper db;
                if (!db.ReadBlock(hash, block)) {
                    ERROR_FL("Switch Failed for ReadFromDisk and ReadBlock: %d, %s, %s", pIndex->nHeight,
                        pIndex->addr.tostring().c_str(),
                        pIndex->GetBlockHash().ToPreViewString().c_str());

                    _pindexLatestRoot = pIndex;
                    return;
                }
                else {

                    db.EraseBlock(hash);
                }
            }
        }


        bool isAccepted = block.AcceptBlock();
        if (!isAccepted) {
            ERROR_FL("Block is not accepted: %s(preHID:%d)", block.GetHash().ToPreViewString().c_str(), block.nPrevHID);
            return;
        }

        if (isAccepted && isInOrphanPool) {
            mapOrphanBlocks.erase(hash);
            mapOrphanBlocksByPrev.erase(hash);
        }

        auto pIndexPool = mapBlockIndex[hash];
        if (pIndexPool) {
            block.UpdateToBlockIndex(pIndex->addr);
        }


        if (GetTime() - nStartTime > 200 || nCount++ > 600 || !pIndex->pnext) {

            if (mapBlockIndex.count(hash)) {
                CTxDB_Wrapper txdb;
                block.SetBestChain(txdb, pIndexPool);
            }
            else {

                //block.AddToBlockIndex(pIndex->addr);
            }
            _pindexLatestRoot = pIndex;

            break;
        }
    }
}

bool LatestLedgerBlock::IsLackingBlock(std::function<void(const BackTrackingProgress &)> notiprogress)
{
    if (!_pindexLatest && !_pindexLatestRoot) {
        Load();
        return true;
    }

    CSpentTime spentt;
    uint256 hashPrev = _pindexLatestRoot->GetBlockHash();
    while (!fShutdown) {

        if (spentt.Elapse() > 10 * 60 * 1000) {
            return true;
        }

        BackTrackingProgress progress;

        progress.nLatestBlockHeight = _pindexLatest->nHeight;
        progress.strLatestBlockTripleAddr = _pindexLatest->addr.tostring().c_str();
        progress.nBackTrackingBlockHeight = GetBackSearchHeight();
        progress.strBackTrackingBlockHash = GetBackSearchHash().ToPreViewString().c_str();


        notiprogress(progress);

        if (mapBlockIndex.count(hashPrev)) {
            CBlockIndexSimplified* p = _pindexLatestRoot;
            while (p) {
                if (p != _pindexLatest) {
                    p = p->pnext;
                    continue;
                }
                else {

                    _pindexLatestRoot->addr = mapBlockIndex[hashPrev]->addr;
                    return false;
                }
            }


             LogBacktracking("Warning: Cannot reach _pindexLatest from _pindexLatestRoot, so backtracking again !!!");

            _pindexLatestRoot = _pindexLatest;
            return true;
        }


        if (_mapBlockIndexLatest.count(hashPrev)) {
            CBlockIndexSimplified * pindex = _mapBlockIndexLatest[hashPrev];
            if (pindex->pprev && pindex->pprev->pprev) {
                _pindexLatestRoot = pindex->pprev;
                _pindexLatestRoot->pnext = pindex;
                hashPrev = _pindexLatestRoot->GetBlockHash();
                continue;
            }
        }


        if (mapOrphanBlocks.count(hashPrev)) {

            auto pblock = mapOrphanBlocks[hashPrev];

            _pindexLatestRoot = InsertBlockIndex(pblock->hashPrevBlock);

            T_LOCALBLOCKADDRESS addr;
            AddBlockIndex(addr, *pblock);

            while (mapOrphanBlocks.count(pblock->hashPrevBlock)) {
                pblock = mapOrphanBlocks[pblock->hashPrevBlock];
                _pindexLatestRoot = InsertBlockIndex(pblock->hashPrevBlock);
                AddBlockIndex(addr, *pblock);
            }

            hashPrev = pblock->hashPrevBlock;
            continue;
        }


        CBlock block;
        BLOCKTRIPLEADDRESS tripleaddr;
        if (GetBlock(hashPrev, block, tripleaddr)) {
            T_LOCALBLOCKADDRESS addr = tripleaddr.ToAddr();

            _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
            AddBlockIndex(addr, block);

            hashPrev = block.hashPrevBlock;
            continue;
        }

        bool isFound = false;


        if (mapBlocks.contain(hashPrev)) {
            block = mapBlocks[hashPrev];
            isFound = true;
        }
        else {

            COrphanBlockDB_Wrapper db;
            if (db.ReadBlock(hashPrev, block)) {
                isFound = true;
            }
        }

        if (isFound) {
            _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);

            T_LOCALBLOCKADDRESS addr;
            AddBlockIndex(addr, block);

            hashPrev = block.hashPrevBlock;
            continue;
        }

        break;
    }


    PullingPrevBlocks();
    return true;
}

bool LatestLedgerBlock::IsOnChain()
{
    if (!_pindexLatest) {
        return false;
    }

    uint32_t nLatestHeight = _pindexLatest->nHeight;
    if (nLatestHeight > pindexBest->Height()) {
        return false;
    }

    CBlockIndex *p = pindexBest;
    while (p && p->Height() > nLatestHeight) {
        p = p->pprev;
    }

    if (p && p->GetBlockHash() == _pindexLatest->GetBlockHash()) {

        auto iter = _mapBlockIndexLatest.begin();
        for (;iter!=_mapBlockIndexLatest.end();) {

            if (_pindexLatest->pprev == iter->second) {
                _pindexLatestRoot = iter->second;
                _pindexLatestRoot->pprev = nullptr;
                iter++;
                continue;
            }

            if (_pindexLatest == iter->second) {
                iter++;
                continue;
            }

            _mapBlockIndexLatest.erase(iter++);
        }

        return true;
    }
    return false;
}

bool LatestLedgerBlock::GetBlockTripleAddr(const uint256& hashblock, T_LOCALBLOCKADDRESS& tripleaddr)
{
    uint256 hashFromDisk;
    if (_mapBlockAddressOnDisk.contain(hashblock)) {
        tripleaddr = _mapBlockAddressOnDisk[hashblock].ToAddr();
        return true;
    }

    return false;
}

bool LatestLedgerBlock::GetBlock(const uint256 & hashblock, CBlock & block, BLOCKTRIPLEADDRESS & tripleaddr)
{
    uint256 hashFromDisk;
    if (_mapBlockAddressOnDisk.contain(hashblock)) {
        T_LOCALBLOCKADDRESS addr = _mapBlockAddressOnDisk[hashblock].ToAddr();

        if (!block.ReadFromDisk(addr)) {


            _mapBlockAddressOnDisk.erase(hashblock);

            return false;
        }

        hashFromDisk = block.GetHash();
        if (hashFromDisk != hashblock) {

            _mapBlockAddressOnDisk.erase(hashblock);
            _mapBlockAddressOnDisk.insert(hashFromDisk, addr);

            return false;
        }

        tripleaddr = addr;
        return true;
    }

    return false;
}


bool LatestLedgerBlock::LoadLatestBlock(uint32 &maxhid)
{
    vector<T_PAYLOADADDR> vecPA;
    T_SHA256 thhash;

    uint64 genesishid = g_cryptoToken.GetHID();
    T_APPTYPE app(APPTYPE::ledger, genesishid, g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID());

    if (pindexBest && maxhid <= pindexBest->nPrevHID) {
        maxhid = pindexBest->nPrevHID + 1;
    }

    if (maxhid < genesishid) {
        maxhid = genesishid;
    }

    _mapBlockIndexLatest.clear();

    CBlock block;
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    T_LOCALBLOCKADDRESS genesisaddr;
    genesisaddr.set(genesishid, g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID());

    T_LOCALBLOCKADDRESS latestblockaddr;

    bool is_informal_network = false;
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "informal") {
            is_informal_network = true;
        }
    }
    bool isOk = false;
    auto iter = maxhid;
    for (; ; --iter) {

        if (is_informal_network && iter < genesishid) {
            continue;
        }
        else if (iter == genesishid) {
            string payload;
            if (!hyperchainspace->GetLocalBlockPayload(genesisaddr, payload))
                break;
            if (!ResolveBlock(block, payload.c_str(), payload.size())) {
                break;
            }
            latestblockaddr = genesisaddr;
            isOk = true;
            break;
        }
        else if (hyperchainspace->GetLocalBlocksByHID(iter, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    break;
                }
                latestblockaddr = pa->addr;
                isOk = true;
                break;
            }

            if (isOk) {
                break;
            }
        }
    }

    if (!isOk) {
        block = g_cryptoToken.GetGenesisBlock();
        latestblockaddr.set(g_cryptoToken.GetHID(),
            g_cryptoToken.GetChainNum(),
            g_cryptoToken.GetLocalID());
    }

    uint256 hashBlock = block.GetHash();
    if (!_pindexLatestRoot) {
        _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
        SetBestIndex(AddBlockIndex(latestblockaddr, block));
    }
    else if (*_pindexLatestRoot->phashBlock == hashBlock) {
        _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
        AddBlockIndex(latestblockaddr, block);
    }
    if (!_pindexLatestRoot) {
        _pindexLatestRoot = _pindexLatest;
    }

    return _mapBlockIndexLatest.size();
}

CBlockIndexSimplified* LatestLedgerBlock::AddBlockIndex(const T_LOCALBLOCKADDRESS & addrIn, const CBlock & block)
{
    uint256 hashBlock = block.GetHash();
    CBlockIndexSimplified* pIndex = InsertBlockIndex(hashBlock);
    pIndex->Set(addrIn, block);

    if (block.hashPrevBlock == 0) {
        return pIndex;
    }

    CBlockIndexSimplified* pIndexPrev = _mapBlockIndexLatest[block.hashPrevBlock];
    pIndexPrev->pnext = pIndex;
    pIndex->pprev = pIndexPrev;
    return pIndex;
}

CBlockIndexSimplified* LatestLedgerBlock::InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    std::map<uint256, CBlockIndexSimplified*>::iterator mi = _mapBlockIndexLatest.find(hash);
    if (mi != _mapBlockIndexLatest.end())
        return (*mi).second;

    // Create new
    CBlockIndexSimplified* pindexNew = new CBlockIndexSimplified();
    if (!pindexNew)
        throw runtime_error("LatestLedgerBlock : new CBlockIndex failed");

    mi = _mapBlockIndexLatest.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool ChainReadyCondition::IsTooFar(std::string& reason)
{
    uint32_t ncount = 0;

    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        CBlockIndexSimplified* pIndex = LatestLedgerBlock::Get();
        uint256 hash = pIndex->GetBlockHash();

        CBlockIndex* p = pindexBest;
        while (p && !p->addr.isValid() && p->GetBlockHash() != hash) {
            ncount++;
            p = p->pprev;
        }

        if (ncount > 40) {
            _eStatusCode = chainstatuscode::ManyBlocksNonChained;
            return true;
        }

        if (g_seedserver.IsValid()) {

            CBlockIndex* p = pindexBest;
            uint32_t height;
            uint256 hash;
            g_blockChckPnt.Get(height, hash);
            if (height == 0) {

                _eStatusCode = chainstatuscode::ReadyWithWarning1;
                return false;
            }

            if (height > 0) {
                if (p->Height() < height) {

                    _eStatusCode = chainstatuscode::ReadyWithWarning2;
                    return false;
                }

                while (p && p->Height() > height) {
                    p = p->pprev;
                }

                if (p->GetBlockHash() != hash) {

                    _eStatusCode = chainstatuscode::ReadyWithWarning3;
                    return false;
                }
            }
        }
    }
    return false;
}


static uint256 hashStartPulling = 0;
static uint64 tmStartPulling = 0;
static CNode* pullingNode = nullptr;

CNode* ChoosePullingNode()
{
    list<CNode*> listPullingNodes;
    for (auto& node : vNodes) {
        if (node->nHeightCheckPointBlock >= LatestLedgerBlock::GetBackSearchHeight()) {
            listPullingNodes.push_back(node);
        }
    }

    if (listPullingNodes.size() <= 0) {
        return nullptr;
    }

    listPullingNodes.sort([](const CNode *a, const CNode *b) {
                return a->nScore > b->nScore;
        });

    CNode *pulling = *listPullingNodes.begin();
    LogBacktracking("Choose highest score node: %s to pull block, score:%d", pulling->nodeid.c_str(), pulling->nScore);

    return pulling;
}


void LatestLedgerBlock::PullingPrevBlocks()
{
    uint256 currBackHash = LatestLedgerBlock::GetBackSearchHash();

    if (hashStartPulling == currBackHash) {
        if (tmStartPulling + 15 > GetTime()) {
            return;
        }
    }
    else if (tmStartPulling + 10 > GetTime()) {
        return;
    }

    int nRequestingNodes = 0;
    CRITICAL_BLOCK(cs_vNodes)
    {
        pullingNode = ChoosePullingNode();

        if (pullingNode) {
            pullingNode->PushGetBlocksReversely(currBackHash);
        }
    }

    tmStartPulling = GetTime();
    hashStartPulling = currBackHash;
}

CBlockBloomFilter::CBlockBloomFilter() : _filter()
{
}

//////////////////////////////////////////////////////////////////////////
//CBlockCacheLocator

void CBlockCacheLocator::setFilterReadCompleted()
{
    _filterCacheReadReady = true;
}

bool CBlockCacheLocator::contain(const uint256& hashBlock)
{
    if (!_filterReady) {
        if (_filterCacheReadReady) {

            _filterBlock = _filterBlock | blk_bf_future.get();
            _filterReady = true;
            cout << "Ledger: read block cache completely\n";
        }
    }

    if (_filterReady && !_filterBlock.contain(hashBlock))
        return false;

    if (_mapBlock.count(hashBlock)) {
        return true;
    }


    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (blockdb.ReadBlock(hashBlock, blk)) {
        return true;
    }
    return false;
}

bool CBlockCacheLocator::insert(const uint256& hashBlock, const CBlock& blk)
{
    CBlockDB_Wrapper blockdb;
    blockdb.TxnBegin();
    blockdb.WriteBlock(hashBlock, blk);
    if (!blockdb.TxnCommit())
        return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;

    insert(hashBlock);
    return true;
}

void CBlockCacheLocator::clear()
{
    _filterBlock.clear();
    _mapBlock.clear();
    _mapTmJoined.clear();
}


bool CBlockCacheLocator::erase(const uint256& hashBlock)
{
    return true;

    //CBlockDB_Wrapper blockdb;
    //blockdb.TxnBegin();
    //blockdb.EraseBlock(hashBlock);
    //if (!blockdb.TxnCommit())
    //    return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    //_mapBlock.erase(hashBlock);
    //std::remove_if(_mapTmJoined.begin(), _mapTmJoined.end(), [&hashBlock](const auto& x) { return x.second == hashBlock; });

    //return true;
}

const CBlock& CBlockCacheLocator::operator[](const uint256& hashBlock)
{
    if (_mapBlock.count(hashBlock)) {
        return _mapBlock[hashBlock];
    }

    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (!blockdb.ReadBlock(hashBlock, blk)) {
        throw runtime_error(strprintf("Failed to Read block: %s", hashBlock.ToPreViewString().c_str()));
    }

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;
    return _mapBlock[hashBlock];
}




/////////////////////////////////////////////////////////////////////////////////////////
//CBlockDiskLocator

bool CBlockDiskLocator::contain(const uint256& hashBlock)
{
    if (_setRemoved.count(hashBlock)) {
        return false;
    }

    if (!_filterBlock.contain(hashBlock))
        return false;


    CBlockTripleAddressDB btadb;
    BLOCKTRIPLEADDRESS addr;
    if (btadb.ReadBlockTripleAddress(hashBlock, addr)) {
        return true;
    }
    return false;
}

bool CBlockDiskLocator::insert(CBlockTripleAddressDB& btadb, const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr)
{
    if (!contain(hashBlock)) {
        _sizeInserted++;
    }

    btadb.WriteBlockTripleAddress(hashBlock, addr);

    if (_mapBlockTripleAddr.size() > _capacity) {
        _mapBlockTripleAddr.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlockTripleAddr[hashBlock] = addr;

    insertBloomFilter(hashBlock);
    return true;
}

bool CBlockDiskLocator::insert(const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr)
{
    CBlockTripleAddressDB btadb;
    return insert(btadb,hashBlock,addr);
}

bool CBlockDiskLocator::insertBloomFilter(const uint256& hashBlock)
{
    return _filterBlock.insert(hashBlock);
}

void CBlockDiskLocator::clear()
{
    _filterBlock.clear();
    _mapBlockTripleAddr.clear();
    _mapTmJoined.clear();
    _setRemoved.clear();
}


bool CBlockDiskLocator::erase(const uint256& hashBlock)
{
    if (!_filterBlock.contain(hashBlock)) {
        return true;
    }

    _setRemoved.insert(hashBlock);

    CBlockTripleAddressDB btadb;
    btadb.EraseBlockTripleAddress(hashBlock);

    return true;
}

const BLOCKTRIPLEADDRESS& CBlockDiskLocator::operator[](const uint256& hashBlock)
{
    if (_mapBlockTripleAddr.count(hashBlock)) {
        return _mapBlockTripleAddr[hashBlock];
    }

    CBlockTripleAddressDB blockdb;
    BLOCKTRIPLEADDRESS addr;
    if (!blockdb.ReadBlockTripleAddress(hashBlock, addr)) {
        throw runtime_error(strprintf("Failed to Read block's triple address: %s", hashBlock.ToPreViewString().c_str()));
    }

    if (_mapBlockTripleAddr.size() > _capacity) {
        _mapBlockTripleAddr.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlockTripleAddr[hashBlock] = addr;
    return _mapBlockTripleAddr[hashBlock];
}


CSpentTime::CSpentTime()
{
    _StartTimePoint = std::chrono::system_clock::now();
}

uint64 CSpentTime::Elapse()
{
    auto tdiff = std::chrono::system_clock::now() - _StartTimePoint;
    return std::chrono::duration_cast<std::chrono::milliseconds>(tdiff).count();
}

void CSpentTime::Reset()
{
    _StartTimePoint = std::chrono::system_clock::now();
}

