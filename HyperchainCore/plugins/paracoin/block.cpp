/*Copyright 2016-2024 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "block.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

//
//std::string CScriptWitness::ToString() const
//{
//    std::string ret = "CScriptWitness(";
//    for (unsigned int i = 0; i < stack.size(); i++) {
//        if (i) {
//            ret += ", ";
//        }
//        ret += HexStr(stack[i]);
//    }
//    return ret + ")";
//}


CTransaction& MakeTransactionRef(CTransaction& tx, CMutableTransaction&& mtx)
{
    tx.vin = std::forward<std::vector<CTxIn>>(mtx.vin);
    tx.vout = std::forward<std::vector<CTxOut>>(mtx.vout);
    tx.nVersion = mtx.nVersion;
    tx.nLockTime = mtx.nLockTime;
    return tx;
}

CTransaction::CTransaction(const CMutableTransaction& tx) :
    vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ ComputeHash() }, m_witness_hash{ ComputeWitnessHash() }
{}



bool CBlock::AddToMemoryPool(const uint256 &nBlockHash)
{
    return mapBlocks.insert(nBlockHash, *this);
}

bool CBlock::AddToMemoryPool()
{
    uint256 hash = GetHash();
    return AddToMemoryPool(hash);
}

bool CBlock::RemoveFromMemoryPool()
{
    uint256 hash = GetHash();
    return mapBlocks.erase(hash);
}

bool CBlock::ReadFromMemoryPool(uint256 nBlockHash)
{
    SetNull();

    if (mapBlocks.contain(nBlockHash)) {
        *this = mapBlocks[nBlockHash];
        return true;
    }
    return false;
}

std::optional<CDiskTxPos> CBlock::GetDiskTxPos(int nTx)
{
    unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 2 + GetSizeOfCompactSize(vtx.size());

    int i = 0;
    BOOST_FOREACH(CTransaction & tx, vtx) {
        if (nTx == i) {
            return std::make_optional<CDiskTxPos>(nTxPos, nHeight, this->GetHash());
        }
        nTxPos += ::GetSerializeSize(tx, SER_DISK);
    }
    return std::nullopt;
}


CBlockIndexSP CBlockIndex::pprev() const
{
    return mapBlockIndex[hashPrev];
}

CBlockIndexSP CBlockIndex::pnext() const
{
    return mapBlockIndex[hashNext];
}

int64 CBlockIndex::GetMedianTimePast() const
{
    int64 pmedian[nMedianTimeSpan];
    int64* pbegin = &pmedian[nMedianTimeSpan];
    int64* pend = &pmedian[nMedianTimeSpan];

    auto pindex = shared_from_this();
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev())
        *(--pbegin) = pindex->GetBlockTime();

    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin) / 2];
}

int64 CBlockIndex::GetMedianTime() const
{
    auto pindex = shared_from_this();
    for (int i = 0; i < nMedianTimeSpan / 2; i++) {
        auto sp = pindex->pnext();
        if (!sp)
            return GetBlockTime();
        pindex = sp;
    }
    return pindex->GetMedianTimePast();
}

bool CBlockIndex::IsInMainChain() const
{
    //HCE: The following way is too slow
    //if (this == pindexBest.get())
    //    return true;
    //else {
    //    if (maintrunkchain.IsInMain(this))
    //        return true;
    //}
    //return false;


    //return (pnext() || this == pindexBest.get());

    //HCE: if not in main chain, hashNext == 0 is true
    return (hashNext > 0 || this == pindexBest.get());
}

//////////////////////////////////////////////////////////////////////////
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
            //HCE: merge the block filter
            _filterBlock = _filterBlock | blk_bf_future.get();
            _filterReady = true;
            cout << "Paracoin: read block cache completely\n";
        }
    }

    if (_filterReady && !_filterBlock.contain(hashBlock))
        return false;

    {
        std::lock_guard<std::mutex> lck(_mutexblk);
        if (_mapBlock.count(hashBlock)) {
            return true;
        }
    }

    //HCE: Is it in storage?
    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (blockdb.ReadBlock(hashBlock, blk)) {
        putintocache(hashBlock, blk);
        return true;
    }
    return false;
}

bool CBlockCacheLocator::insert(const uint256& hashBlock, const CBlock& blk)
{
    CBlockDB_Wrapper blockdb;
    if (!blockdb.TxnBegin())
        return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);
    blockdb.WriteBlock(hashBlock, blk);
    if (!blockdb.TxnCommit())
        return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    putintocache(hashBlock, blk);
    return true;
}

void CBlockCacheLocator::putintocache(const uint256& hashBlock, const CBlock& blk)
{
    std::lock_guard<std::mutex> lck(_mutexblk);

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;

    insert(hashBlock);
}

void CBlockCacheLocator::clear()
{
    std::lock_guard<std::mutex> lck(_mutexblk);
    _filterBlock.clear();
    _mapBlock.clear();
    _mapTmJoined.clear();
}

//HCE: how to clean the bit flag?
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

CBlock CBlockCacheLocator::operator[](const uint256& hashBlock)
{
    {
        std::lock_guard<std::mutex> lck(_mutexblk);
        if (_mapBlock.count(hashBlock)) {
            return _mapBlock[hashBlock];
        }
    }

    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (!blockdb.ReadBlock(hashBlock, blk)) {
        throw runtime_error(strprintf("Failed to Read block: %s", hashBlock.ToPreViewString().c_str()));
    }

    putintocache(hashBlock, blk);
    return blk;
}

const int CBlockLocatorEx::nHeightSpan = 2500;
const int CBlockLocatorEx::nHeightSpanTail = 100;

void CBlockLocatorEx::Add(int height, const uint256& hash)
{
    if (height % nHeightSpan != 0) {
        return;
    }

    int idx = height / nHeightSpan;

    if (idx + 1 > vHave.size()) {
        vHave.resize(idx + 1);
    }
    vHave[idx] = hash;
}

bool CBlockLocatorEx::Have(const CBlockIndexSP& pindex) const
{
    uint256 hash;
    if (IsIn(pindex->nHeight, hash)) {
        if (hash == pindex->hashBlock) {
            return true;
        }
    }
    return false;
}

bool CBlockLocatorEx::IsInMain(const CBlockIndex* pindex) const
{
    int nBlkHeight = pindex->nHeight;
    uint256 hashBlk = pindex->hashBlock;
    return IsInMain(nBlkHeight, hashBlk);
}


bool CBlockLocatorEx::IsInMain(int nBlkHeight, const uint256 &hashBlk) const
{
    uint256 hashbegin;
    uint256 hashEnd;

    if (GetRange(nBlkHeight, hashbegin, hashEnd)) {
        CBlockIndexSP pindexBegin = mapBlockIndex[hashbegin];
        CBlockIndexSP pindexEnd = mapBlockIndex[hashEnd];

        while (pindexEnd && (pindexEnd->nHeight >= nBlkHeight)) {
            if (pindexBegin->nHeight > pindexEnd->nHeight) {
                break;
            }
            if (pindexEnd->GetBlockHash() == hashBlk) {
                return true;
            }
            pindexEnd = pindexEnd->pprev();
        }
    }
    return false;
}

bool CBlockLocatorEx::GetRange(int nBlkHeight, uint256& hashbegin, uint256& hashEnd) const
{
    int nH = nBlkHeight;
    if (nH > nBestHeight) {
        return false;
    }

    int idx = nH / nHeightSpan;
    if (idx + 1 < vHave.size()) {
        hashbegin = vHave[idx];

        int nLeft = nH % nHeightSpan;
        if (nLeft == 0)
            hashEnd = hashbegin;
        else
            hashEnd = vHave[idx + 1];
        return true;
    }
    else if ((idx + 1) == vHave.size()) {

        int idxTail = (nH - idx * nHeightSpan) / nHeightSpanTail;

        if (vHaveTail.size() > 0) {
            if (idxTail == 0) {
                hashbegin = vHave[idx];
                hashEnd = vHaveTail[0];
                return true;
            } else if (idxTail < vHaveTail.size()) {
                hashbegin = vHaveTail[idxTail - 1];
                hashEnd = vHaveTail[idxTail];
                return true;
            } else if (idxTail == vHaveTail.size()) {
                hashbegin = vHaveTail[idxTail - 1];
                hashEnd = hashBestChain; //pindexBest->GetBlockHash();
                return true;
            }
        } else {
            hashbegin = vHave[idx];
            hashEnd = hashBestChain;   //pindexBest->GetBlockHash();
            return true;
        }
    }
    return false;
}

CBlockIndexSP CBlockLocatorEx::GetBlockIndexInMainChain() const
{
    // Find the first block the caller has in the main chain
    auto mi = mapBlockIndex[hashEnd];
    if (mi) {
        CBlockIndexSP pindex = mi;
        if (pindex->IsInMainChain())
            return pindex;
    }

    size_t nSize = vHaveTail.size();
    for (size_t i = nSize; i > 0; i--) {
        auto mi = mapBlockIndex[vHaveTail[i - 1]];
        if (mi) {
            CBlockIndexSP pindex = mi;
            if (pindex->IsInMainChain())
                return pindex;
        }
    }


    nSize = vHave.size();
    for (size_t i = nSize; i > 0; i--) {
        auto mi = mapBlockIndex[vHave[i - 1]];
        if (mi) {
            CBlockIndexSP pindex = mi;
            if (pindex->IsInMainChain())
                return pindex;
        }
    }

    return pindexGenesisBlock;
}

bool CBlockLocatorEx::Save()
{
    CMainTrunkDB mtdb;

    if (vHave.size() == 0) {
        mtdb.WriteMaxHeight(0);
        return true;
    }

    int nMaxHeight = (vHave.size() - 1) * nHeightSpan;

    if (mtdb.WriteMaxHeight(nMaxHeight)) {

        int h = GetLInnerHeight();
        mtdb.WriteData(h, hashvHaveLInner);

        for (int idx = vHave.size() - 1; idx >= 0; --idx) {
            int nH = idx * nHeightSpan;
            uint256 hash;
            if (mtdb.ReadData(nH, hash)) {
                if (hash == vHave[idx])
                    return true;
            }
            mtdb.WriteData(nH, vHave[idx]);
        }

        return true;
    }

    return false;

}

std::string CBlockLocatorEx::ToString(int idx)
{
    int nH;
    uint256 hash1;
    if (idx < 0) {
        int offset = vHaveTail.size() + idx;
        if (offset >= 0) {
            nH = vHave.size() > 0 ? (vHave.size() - 1) * nHeightSpan : 0;
            nH = nH + (offset + 1) * nHeightSpanTail;
            hash1 = vHaveTail[offset];
        } else {
            nH = vHave.size() > 0 ? (vHave.size() - 1) * nHeightSpan : 0;
            hash1 = vHave.size() > 0 ? vHave.back() : 0;
        }
    } else if (idx + 1 > vHave.size()) {
        nH = vHave.size() > 0 ? (vHave.size() - 1) * nHeightSpan : 0;
        hash1 = vHave.size() > 0 ? vHave.back() : 0;
    } else {
        nH = idx * nHeightSpan;
        hash1 = vHave[idx];
    }
    return strprintf("%d(%s)", nH, hash1.ToPreViewString().c_str());
}

int CBlockLocatorEx::GetChkPoint(uint256 &hashchkp)
{
    int nTail = vHaveTail.size();
    if (nTail > 1) {
        //HC: 取倒数第2个
        //HCE: Take the 2nd from the bottom
        hashchkp = vHaveTail[nTail - 2];
        return (vHave.size() - 1) * nHeightSpan + (nTail - 1) * nHeightSpanTail;
    }

    if (nTail == 1) {
        hashchkp = vHave.back();
        return (vHave.size() - 1) * nHeightSpan;
    }

    if (vHave.size() == 0) {
        hashchkp = 0;
        return 0;
    } else if (vHave.size() == 1) {
        hashchkp = vHave[0];
        return 0;
    }
    hashchkp = hashvHaveLInner;
    return GetLInnerHeight();
}


int CBlockLocatorEx::GetChain(vector<uint256>& chains)
{
    int nTail = vHaveTail.size();
    for (int i = nTail - 1; i >= 0; i--) {
        chains.push_back(vHaveTail[i]);
    }

    int n = vHave.size();
    int nCount = 0;
    for (int i = n - 1; i >= 0; i--) {
        chains.push_back(vHave[i]);
        nCount++;
        if (nCount >= 4) {
            break;
        }
    }

    return 0;
}

bool CBlockLocatorEx::IsIn(int nHeight, const uint256& hash) const
{
    int nMax = GetMaxHeight();
    if (nHeight > nMax) {
        return false;
    }

    //HC: 余数必须为0
    //HCE: The remainder must be 0
    if (nHeight % nHeightSpanTail != 0) {
        return false;
    }

    int idx = nHeight / nHeightSpan;
    if (idx + 1 < vHave.size()) {
        if (GetLInnerHeight() == nHeight) {
            return hashvHaveLInner == hash;
        }
        //HC: 余数必须为0
        //HCE: The remainder must be 0
        if (nHeight % nHeightSpan != 0) {
            return false;
        }
        if (vHave[idx] == hash) {
            return true;
        }
    } else if ((idx + 1) == vHave.size()) {

        if (GetVHaveMaxHeight() == nHeight) {
            return vHave[idx] == hash;
        }

        int idxTail = (nHeight - idx * nHeightSpan) / nHeightSpanTail;
        if (idxTail > 0 && vHaveTail.size() >= idxTail) {
            if (vHaveTail[idxTail - 1] == hash) {
                return true;
            }
        }
    }
    return false;
}

void CBlockLocatorEx::updateLInnerHash(CBlockIndexSP pStartIdx)
{
    if (hashLatestInvHave != vHave.back()) {

        if (vHave.size() == 1) {
            hashvHaveLInner = 0;
            hashLatestInvHave = vHave.back();
            return;
        }

        int vHaveLInnerHeight = GetLInnerHeight();
        CBlockIndexSP pindex = pStartIdx;
        while (pindex) {
            if (pindex->nHeight == vHaveLInnerHeight) {
                hashvHaveLInner = pindex->GetBlockHash();
                hashLatestInvHave = vHave.back();
                break;
            }
            pindex = pindex->pprev();
        }
    }
}

std::string CBlockLocatorEx::ToDetailString(int idx, int idxTail)
{
    uint256 hashchkp;
    int nH = GetChkPoint(hashchkp);

    if (idx < 0) {
        idx = 0;
    }

    if (idx > (vHave.size() - 1)) {
        idx = vHave.size() - 1;
    }

    string hashTail = "no data";
    if (idxTail < 0) {
        idxTail = 0;
    }
    if (idxTail > (vHaveTail.size() - 1)) {
        idxTail = vHaveTail.size() - 1;
    }
    if (vHaveTail.size() > 0) {
        hashTail = vHaveTail[idxTail].ToString();
    }

    return strprintf("hashLInner: (%d)%s \nvHave: %d idx: %d(%d %s)\nvHaveTail: %d idx: %d(%d %s)\nchkp: %d(%s) \nBest: %d(%s)",
        GetLInnerHeight(), hashvHaveLInner.ToString().c_str(),
        vHave.size(), idx, idx * nHeightSpan, vHave[idx].ToString().c_str(),
        vHaveTail.size(), idxTail, GetVHaveMaxHeight() + (idxTail + 1) * nHeightSpanTail, hashTail.c_str(),
        nH, hashchkp.ToPreViewString().c_str(),
        nHeighEnd,
        hashEnd.ToPreViewString().c_str());
}



bool DeleteDBFile(const string &dbfile)
{
    namespace fs = boost::filesystem;

    string datadir = GetDataDir();
    auto rootpath = fs::path(GetDataDir());

    CloseDb(dbfile);

    fs::path datfile(rootpath / dbfile);
    if (fs::exists(datfile)) {
        if (!fs::remove(datfile))
            return false;
    }
    return true;
}


//////////////////////////////////////////////////////////////////////////
//HC: v0.7.2 2021年7月14日前版本更新
//HCE: v0.7.2 Updated before July 14, 2021
CBlockIndex To_CBlockIndex(const CBlockIndexV72& blkindex)
{
    CBlockIndex newBlkIndex;
    newBlkIndex.hashBlock = blkindex.hashBlock;
    newBlkIndex.hashPrev = blkindex.hashPrev;
    newBlkIndex.hashNext = blkindex.hashNext;


    newBlkIndex.nHeight = blkindex.nHeight;
    newBlkIndex.bnChainWork = blkindex.bnChainWork;

    newBlkIndex.triaddr = blkindex.addr;

    newBlkIndex.nVersion = blkindex.nVersion;
    newBlkIndex.hashMerkleRoot = blkindex.hashMerkleRoot;

    newBlkIndex.nTime = blkindex.nTime;
    newBlkIndex.nBits = blkindex.nBits;
    newBlkIndex.nNonce = blkindex.nNonce;
    newBlkIndex.nSolution = blkindex.nSolution;

    newBlkIndex.nPrevHID = blkindex.nPrevHID;
    newBlkIndex.hashPrevHyperBlock = blkindex.hashPrevHyperBlock;
    newBlkIndex.hashExternData = blkindex.hashExternData;

    newBlkIndex.ownerNodeID = blkindex.ownerNodeID;
    return newBlkIndex;
}

bool UpgradeBlockIndexFormatOfV72()
{
    CMgrTxDB txdb("cr+");

    cout << "Load block indexes...\n";

    map<uint256, CBlockIndexV72> mapBlkIndex;
    txdb.LoadBlockIndex(mapBlkIndex);

    uint256 h = g_cryptoCurrency.GetHashGenesisBlock();

    if (!mapBlkIndex.count(h)) {
        cerr << "genesis block hash error, should be " << h.ToString();
        return false;
    }

    cout << "Start to upgrade Para block indexes ";
    cout << "and bulk save result to blkindex.dat...\n";

    //HCE: We have to save into origin file for a lot of transactions saved in the blkindex.dat.

    CommadLineProgress progress;
    progress.Start();

    int nCount = 0;
    auto beginitem = mapBlkIndex.begin();
    for (; beginitem != mapBlkIndex.end(); ++beginitem) {
        CBlockIndex blkidx = To_CBlockIndex(beginitem->second);
        txdb.BulkWriteBlockIndex(beginitem->first, CDiskBlockIndex(&blkidx));
        nCount++;
        if (nCount % 1000 == 0) {
            progress.PrintStatus(1000, strprintf("upgraded: %d", nCount));
        }
    }

    CBlockIndexV72 genesisidxv72 = mapBlkIndex[h];
    CBlockIndex genesisidx = To_CBlockIndex(genesisidxv72);

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    T_LOCALBLOCKADDRESS genesisaddr;
    genesisaddr.set(g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());


    T_HYPERBLOCK hblock;
    if (hyperchainspace->getHyperBlock(g_cryptoCurrency.GetHID(), hblock)) {
        genesisidx.triaddr.hhash = to_uint256(hblock.GetHashSelf());
    } else {
        genesisidx.triaddr.hhash = uint256S("88845ff7acb1f21b6be55815d72b87cb850dccf999c279a0266d14e79a1f597c"); //HCE: for informal network
        cout << StringFormat("Failed to read Hyperblock: %d, use a default value, only for informal network of Para\n", g_cryptoCurrency.GetHID());
    }
    txdb.BulkWriteBlockIndex(h, CDiskBlockIndex(&genesisidx));

    if (!txdb.BulkCommit()) {
        return false;
    }

    DBFlush(false);

    progress.PrintStatus(1, strprintf("upgraded: %d", nCount));
    cout << "\n";
    return true;
}

//HCE: The following function is use to upgrade to V73
bool DeleteOldIndexFilesOfV72()
{
    namespace fs = boost::filesystem;

    string datadir = GetDataDir();
    auto rootpath = fs::path(GetDataDir());

    char* porphanblockaddr = "orphanblocktripleaddr.dat";
    CloseDb(porphanblockaddr);

    fs::path datfile(rootpath / porphanblockaddr);
    if (fs::exists(datfile)) {
        if (!fs::remove(datfile))
            return false;
    }

    datfile = rootpath / "blocktripleaddress.dat";
    if (fs::exists(datfile)) {
        if (!fs::remove(datfile))
            return false;
    }
    return true;
}

bool UpgradeTxIndexFormatofV72()
{
    CommadLineProgress progress;
    progress.Start();

    typedef struct
    {
        int nHeightBlk;
        uint256 hashBlk;
    } BlkInfo;

    size_t notfoundBlock = 0;
    auto p = pindexBest;
    map<uint256, BlkInfo> mapTxes;
    while (p && p->nHeight >= 0) {
        CBlock blk;
        BLOCKTRIPLEADDRESS addrblock;
        char* pWhere = nullptr;
        uint256 hash = p->GetBlockHash();
        if (GetBlockData(hash, blk, addrblock, &pWhere)) {
            for (size_t i = 0; i < blk.vtx.size(); i++) {
                mapTxes[blk.vtx[i].GetHash()] = { p->nHeight, hash };
                if (mapTxes.size() % 1000 == 0) {
                    progress.PrintStatus(1000, StringFormat("Reading tx from block: %d, not found blocks: %d", p->nHeight, notfoundBlock));
                }
            }
        } else {
            notfoundBlock++;
            cerr << StringFormat("\n%s: cannot GetBlockData: (%d)%s\n", __FUNCTION__, p->nHeight, hash.ToString());
        }
        p = p->pprev();
    }

    cout << "\nLoading transaction indexes...\n";
    progress.Start();

    typedef struct
    {
        uint256 hashtx;
        CTxIndexV72 idxtxv72;
    } TxInfo;


    size_t nTxNum = 0;
    std::map<uint32_t, list<TxInfo>> mapTxInfoV72;
    //HC: 所有交易 按高度排序
    //HCE: All transactions are sorted by height
    std::map<CDiskTxPosV72, uint256> mapDiskTxV72;
    CTxDB_Wrapper txdb("r+");
    txdb.Load("tx", [&progress, &mapTxInfoV72, &mapDiskTxV72, &nTxNum](CDataStream& ssKey, CDataStream& ssValue) ->bool {
        uint256 hash;
        ssKey >> hash;

        CTxIndexV72 txidxv72;
        ssValue >> txidxv72;

        if (txidxv72.IsNull()) {
            //Skip
            return true;
        }

        auto& listTx = mapTxInfoV72[txidxv72.pos.nHeight];
        listTx.push_back({ hash, txidxv72 });

        //std::pair<std::map<uint32_t, TxInfo>::iterator, bool> ret = mapTxInfoV72.insert({ txidxv72.pos.nHeight, {hash, txidxv72 } });
        mapDiskTxV72.insert({ txidxv72.pos, hash });

        nTxNum++;
        if (nTxNum % 1000 == 0) {
            progress.PrintStatus(1000, StringFormat("Loaded: %d", nTxNum));
        }

        return true;
        });

    cout << "\nParsing and upgrading transaction indexes...\n";
    size_t nTxErr = 0;
    nTxNum = 0;
    progress.Start();

    if (!txdb.TxnBegin())
        return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);

    //HC: 按Block高度从小到大来遍历每一笔交易,这样可以比较容易判断不合法的交易花费
    //HCE: Traverse each transaction from smallest to largest by block height, which makes it easier to judge the cost of illegitimate transactions
    auto txlistiter = mapTxInfoV72.begin();
    for (; txlistiter != mapTxInfoV72.end(); ++txlistiter) {

        auto txiter = txlistiter->second.begin();
        for (; txiter != txlistiter->second.end(); ) {
            if (mapTxes.count(txiter->hashtx)) {
                //HCE:
                BlkInfo& blkinfo = mapTxes[txiter->hashtx];
                CDiskTxPos disktx(txiter->idxtxv72.pos.nTxPos, blkinfo.nHeightBlk, blkinfo.hashBlk);

                CTxIndex txidx(disktx, txiter->idxtxv72.vSpent.size());

                int nSpent = 0;
                for (auto& vs : txiter->idxtxv72.vSpent) {
                    if (!vs.IsNull() && mapDiskTxV72.count(vs)) {
                        uint256 &hashin = mapDiskTxV72[vs];
                        if (mapTxes.count(hashin)) {
                            BlkInfo blkinfoin = mapTxes[hashin];
                            txidx.vSpent[nSpent] = { vs.nTxPos, blkinfoin.nHeightBlk, blkinfoin.hashBlk };
                        }
                    }
                    nSpent++;
                }

                if (!txdb.UpdateTxIndex(txiter->hashtx, txidx)) {
                    txdb.TxnAbort();
                    cerr << StringFormat("cannot UpdateTxIndex: %s\n", txidx.pos.ToString());
                    goto upgradeerr;
                }

                ++txiter;
            }
            else {
                //HC: 不合法交易
                //HCE: invalid transaction
                if (!txdb.EraseTxIndex(txiter->hashtx)) {
                    txdb.TxnAbort();
                    cerr << StringFormat("cannot EraseTxIndex: %s\n", txiter->hashtx.ToString());
                    goto upgradeerr;
                }
                nTxErr++;
                mapDiskTxV72.erase(txiter->idxtxv72.pos);
                txlistiter->second.erase(txiter++);
            }

            nTxNum++;
            if (nTxNum % 1000 == 0) {
                progress.PrintStatus(1000, StringFormat("Parsed: %d, Invalid Tx: %d", nTxNum, nTxErr));
            }
        }
    }

    progress.PrintStatus(0, StringFormat("Parsed: %d, Invalid Tx: %d", nTxNum, nTxErr));
    cout << endl;

    if (!txdb.TxnCommit()) {
        cerr << StringFormat("%s: cannot TxnCommit\n", __FUNCTION__);
        return false;
    }
    return true;

upgradeerr:

    return false;
}
