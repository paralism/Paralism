/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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

#include "headers.h"
#include "db/dbmgr.h"
#include "../dllmain.h"

#include <boost/filesystem.hpp>

#include <regex>

#undef printf

extern bool ExtractAddress(const CScript& scriptPubKey, std::vector<unsigned char>& vchPubKey);

using PUBKEY = std::vector<unsigned char>;

std::set<T_SHA256> g_setLocalBlockScanned;
map<PUBKEY, int64> g_mapWallet;

int ParseTx(const string& dbpath, uint32_t genesisHID, uint16_t genesisChainNum, uint16_t genesisID)
{
    DBmgr* _db = Singleton<DBmgr>::instance();
    _db->open(dbpath.c_str());
    if (!_db->isOpen()) {
        cout << "cannot open db file: " << dbpath << endl;
        return -1;
    }

    std::set<uint64> _localHID;
    int ret = _db->getAllHyperblockNumInfo(_localHID);

    std::set<uint64_t> setMyHIDInDB;
    for (auto iter = _localHID.lower_bound(genesisHID); iter != _localHID.end(); ++iter) {
        setMyHIDInDB.insert(*iter);
    }

    if (setMyHIDInDB.size() == 0) {
        cout << "not found any block, make sure " << dbpath << " is existed." << endl;
        return -1;
    }

    string mynodeid = "123456789012345678901234567890ab";
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::instance(mynodeid);

    //HCE: load block triple address index
    vector<T_PAYLOADADDR> vecPA;
    T_SHA256 thhash;

    cout << "Paracoin Tool: scanning: " << dbpath << "\n"
         << "\t" << *setMyHIDInDB.rbegin() - genesisHID + 1 << " Hyperblocks on disk: " << endl;

    T_APPTYPE app(APPTYPE::paracoin, genesisHID, genesisChainNum, genesisID);

    uint64_t totalnum = setMyHIDInDB.size();
    uint64_t progress = 0;
    uint64_t cuurprogress = 0;

    auto iter = setMyHIDInDB.begin();
    for (; iter != setMyHIDInDB.end(); ++iter) {

        progress++;
        if (progress * 100 / totalnum > cuurprogress) {
            cuurprogress = progress * 100 / totalnum;
            if (cuurprogress % 2 == 0) {
                cout << ">";
            }
        }

        vecPA.clear();
        if (hyperchainspace->GetLocalBlocksByHID(*iter, app, thhash, vecPA)) {

            //HCE: Check if the local block have already scanned.
            if (g_setLocalBlockScanned.count(thhash)) {
                continue;
            }
            g_setLocalBlockScanned.insert(thhash);

            //HCE: scan the Para transactions in local block
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                CBlock block;
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    continue;
                }

                if (block.vtx.size() > 0) {
                    CTransaction& tx = block.vtx.front();
                    if (tx.IsCoinBase()) {

                        PUBKEY vchPubKey;
                        if (ExtractAddress(tx.vout.front().scriptPubKey, vchPubKey)) {
                            if (g_mapWallet.count(vchPubKey)) {
                                g_mapWallet[vchPubKey] += tx.vout.front().nValue;
                            }
                            else {
                                g_mapWallet.insert(make_pair(vchPubKey, tx.vout.front().nValue));
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}


class CBlockIndexMigr
{
public:
    const uint256* phashBlock;
    CBlockIndexMigr* pprev;
    CBlockIndexMigr* pnext;
    //unsigned int nFile;     
    //unsigned int nBlockPos; //HCE: unused

    // block header
    int nHeight;
    CBigNum bnChainWork;    

    T_LOCALBLOCKADDRESS addr; 

    int nVersion;
    uint256 hashMerkleRoot;

    unsigned int nTime;
    unsigned int nBits;
    uint64 nNonce;

    std::vector<unsigned char> nSolution;

    uint32 nPrevHID;
    uint256 hashPrevHyperBlock;

    uint256 hashExternData = 0;                 //HCE: =hash256(nOwerNode)
    CUInt128 ownerNodeID = CUInt128(true);

    CBlockIndexMigr()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;

        nVersion = 0;
        hashMerkleRoot = 0;
        nHeight = 0;
        nTime = 0;
    }

    CBlockIndexMigr(const T_LOCALBLOCKADDRESS& addrIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        addr = addrIn;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nHeight = block.nHeight;
        nTime = block.nTime;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
    }

    CBlockIndexMigr(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nHeight = block.nHeight;
        nTime = block.nTime;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
    }

    //HC: 该区块的高度，从创世区块0开始算起
    //HCE: The height of the block is calculated from genesis block 0
    inline int64 Height() const
    {
        return nHeight;
    };                             

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight = nHeight;
        block.nTime = nTime;
        block.nPrevHID = nPrevHID;
        block.hashPrevHyperBlock = hashPrevHyperBlock;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    static CBigNum GetBlockWork(unsigned int nBlkBits)
    {
        CBigNum bnTarget;
        bnTarget.SetCompact(nBlkBits);
        if (bnTarget <= 0)
            return 0;
        return (CBigNum(1) << 256) / (bnTarget + 1);
    }

    CBigNum GetBlockWork() const
    {
        return GetBlockWork(nBits);
    }

    bool operator<(const CBlockIndex& st) const
    {
        return (addr < st.addr);
    }
    bool operator>=(const CBlockIndex& st) const
    {
        return (addr >= st.addr);
    }
};

class CDiskBlockIndex2020 : public CBlockIndexMigr
{
public:
    uint256 hashPrev;
    uint256 hashNext;

    explicit CDiskBlockIndex2020()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex2020(CBlockIndexMigr* pindex) : CBlockIndexMigr(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nHeight);

        uint32_t* hid = (uint32_t*)(&addr.hid);
        READWRITE(*hid);

        READWRITE(addr.chainnum);
        READWRITE(addr.id);
        READWRITE(addr.ns);

        // block header
        READWRITE(this->nVersion);
        if (this->nVersion != 1) {
            cout << "Block nVersion is " << this->nVersion << endl;
        }

        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);

        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);
        READWRITE(hashExternData);

        READWRITE(ownerNodeID.Lower64());
        READWRITE(ownerNodeID.High64());
    )


    bool operator<(const CDiskBlockIndex2020& right) const
    {
        if (nHeight == right.nHeight) {
            return GetBlockHash() > right.GetBlockHash();
        }
        return nHeight > right.nHeight;
    }

    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight = nHeight;

        //memcpy(block.nReserved, nReserved, sizeof(block.nReserved));

        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        block.nPrevHID = nPrevHID;
        block.nSolution = nSolution;
        block.hashPrevHyperBlock = hashPrevHyperBlock;
        block.nNonce = nNonce;
        block.hashExternData = hashExternData;
        return block.GetHash();
    }
};

map<uint256, CBlockIndexMigr*> mapBlockIndexMigr;
std::multimap<int, CDiskBlockIndex2020> mapMigrBlockIndex;
CBlockIndexMigr* pindexBestMigr;

static CBlockIndexMigr* InsertBlockIndexMigr(uint256 hash, int nHeight)
{
    if (hash == 0)
        return NULL;

    // Return existing
    auto mi = mapBlockIndexMigr.count(hash);
    if (mi > 0)
        return mapBlockIndexMigr[hash];

    // Create new
    CBlockIndexMigr* pindexNew = new CBlockIndexMigr();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndexMigr failed");
    pindexNew->nHeight = nHeight;
    auto miter = mapBlockIndexMigr.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*miter).first);

    return miter->second;
}


class CMgrTxDB : public CTxDB
{
public:
    using CTxDB::CTxDB;

    bool LoadBlockIndex()
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        CONST int nConstStep = 1000;
        int nCount = 0;
        int nStep = nConstStep;

        // Load mapBlockIndex
        unsigned int fFlags = DB_SET_RANGE;
        loop
        {
            // Read next record
            CDataStream ssKey;
            if (fFlags == DB_SET_RANGE)
                ssKey << make_pair(string("blockindex"), uint256(0));
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
            fFlags = DB_NEXT;
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            ssKey >> strType;
            if (strType == "blockindex") {
                CDiskBlockIndex2020 diskindex;
                ssValue >> diskindex;

                CBlockIndexMigr* pindexNew = ConstructBlockIndexMigr(diskindex);

                nCount++;
                nStep--;
                if (nStep == 0) {
                    cout << ".";
                    nStep = nConstStep;
                }
                //mapMigrBlockIndex.insert(decltype(mapMigrBlockIndex)::value_type(diskindex.nHeight, diskindex));
            }
            else {
                break;
            }
        }
        pcursor->close();
        cout << "\n Sum(blockindex) : " << nCount << endl;


        if (!ReadHashBestChain(hashBestChain)) {
            if (pindexGenesisBlock == NULL) {
                return true;
            }
            hashBestChain = pindexGenesisBlock->GetBlockHash();
        }

        if (!mapBlockIndexMigr.count(hashBestChain)) {
            ERROR_FL("hashBestChain not found in the block index");
            hashBestChain = hashGenesisBlock;
        }

        pindexBestMigr = mapBlockIndexMigr[hashBestChain];

        return true;
    }

    CBlockIndexMigr* ConstructBlockIndexMigr(CDiskBlockIndex2020& diskindex)
    {
        CBlockIndexMigr *pindexNew = InsertBlockIndexMigr(diskindex.GetBlockHash(), diskindex.nHeight);
        pindexNew->pprev = InsertBlockIndexMigr(diskindex.hashPrev, diskindex.nHeight - 1);
        pindexNew->pnext = InsertBlockIndexMigr(diskindex.hashNext, diskindex.nHeight + 1);
        //HCE: add block address
        pindexNew->addr = diskindex.addr;
        pindexNew->nVersion = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime = diskindex.nTime;
        pindexNew->nBits = diskindex.nBits;
        pindexNew->nNonce = diskindex.nNonce;
        pindexNew->nSolution = diskindex.nSolution;
        pindexNew->ownerNodeID = diskindex.ownerNodeID;
        pindexNew->nPrevHID = diskindex.nPrevHID;
        pindexNew->hashExternData = diskindex.hashExternData;
        pindexNew->hashPrevHyperBlock = diskindex.hashPrevHyperBlock;
        pindexNew->bnChainWork = diskindex.bnChainWork;
        return pindexNew;
    }

};

void ToBlkIdx(CBlockIndexMigr* migr, CBlockIndex &blkidx)
{
    blkidx.hashPrev = migr->pprev->GetBlockHash();
    blkidx.hashNext = migr->pnext->GetBlockHash();
    //HCE: add block address
    CBlockIndexMigr& diskindex = *migr;
    blkidx.addr = diskindex.addr;
    blkidx.nVersion = diskindex.nVersion;
    blkidx.hashMerkleRoot = diskindex.hashMerkleRoot;
    blkidx.nTime = diskindex.nTime;
    blkidx.nBits = diskindex.nBits;
    blkidx.nNonce = diskindex.nNonce;
    blkidx.nSolution = diskindex.nSolution;
    blkidx.ownerNodeID = diskindex.ownerNodeID;
    blkidx.nPrevHID = diskindex.nPrevHID;
    blkidx.hashExternData = diskindex.hashExternData;
    blkidx.hashPrevHyperBlock = diskindex.hashPrevHyperBlock;
    blkidx.bnChainWork = diskindex.bnChainWork;
}

int main(int argc, char* argv[])
{
    namespace fs = boost::filesystem;

    AppParseParameters(argc, argv);

    string strDataDir = GetDataDir();

    cout << strprintf("Doing format conversion for: %s/blkindex.dat ", strDataDir.c_str())<< endl;

    CMgrTxDB txdb("cr+");

    cout << "LoadBlockIndex...\n";

    txdb.LoadBlockIndex();
    //new version, CBlockIndex::bnChainWork is saved into blkindex.dat

    //auto beginitem = mapMigrBlockIndex.begin();
    //if (beginitem->second.nHeight != 0) {
    //    cerr << "error occur,why does not have 0 block?";
    //    return -1;
    //}

    //beginitem->second.bnChainWork = beginitem->second.GetBlockWork();

    cout << "Start to update chain work for every block index ";
    cout << "and save result to blkindex-result.dat...\n";

    CBlockIndexMigr *pindex = pindexBestMigr;
    while (pindex->nHeight > 0) {
        pindex = pindex->pprev;
    }

    CMgrTxDB txdbResult("cr+","blkindex-result.dat");

    pindex->bnChainWork = pindex->GetBlockWork();
    pindex = pindex->pnext;
    while (pindex != nullptr) {
        pindex->bnChainWork = pindex->pprev->bnChainWork + pindex->GetBlockWork();
        pindex = pindex->pprev;
        CBlockIndex blkidx;
        ToBlkIdx(pindex, blkidx);
        txdbResult.WriteBlockIndex(CDiskBlockIndex(&blkidx));
    }


    //uint256 h = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba5");
    //beginitem->second.hashBlock = h;
    //auto previtem = beginitem;
    //beginitem++;
    //for (; beginitem != mapMigrBlockIndex.end(); ++beginitem) {

    //    int nH = beginitem->second.nHeight;
    //    auto pp = beginitem;
    //    --pp;
    //    while (pp != mapMigrBlockIndex.end()) {
    //        if (pp->second.nHeight < nH - 1 || pp->second.nHeight > nH) {
    //            //error
    //            cerr << "map sort error" << endl;
    //            break;
    //        }
    //        if (pp->second.hashBlock == beginitem->second.hashPrev) {
    //            //OK
    //            beginitem->second.bnChainWork = pp->second.bnChainWork + beginitem->second.GetBlockWork();
    //            CBlockIndex* p = &(beginitem->second);
    //            txdbResult.WriteBlockIndex(CDiskBlockIndex(p));
    //            break;
    //        }
    //        --pp;
    //    }
    //}


    //CMgrTxDB txdbResult("cr+","blkindex-result.dat");

    //beginitem = mapMigrBlockIndex.begin();
    //for (; beginitem != mapMigrBlockIndex.end(); ++beginitem) {
    //    CBlockIndex* p = &(beginitem->second);
    //    txdbResult.WriteBlockIndex(CDiskBlockIndex(p));
    //}

    cout << "File Format conversion is finished" << endl;

   /* CBlockIndex* pindex = vSortedByHeight[0].second.GetBlockIndex();
    pindex->bnChainWork = pindex->GetBlockWork();

    auto beginitem = setMigrBlockIndex.begin();
    beginitem++;

    for (;beginitem != vSortedByHeight.end(); ++beginitem) {

        CBlockIndex* pindex = beginitem->second.GetBlockIndex();
        auto prev = pindex->pprev();
        if (!prev || prev->bnChainWork == 0) {
            cout << "error occur";
        }
        pindex->bnChainWork = prev->bnChainWork + pindex->GetBlockWork();
    }

    beginitem = vSortedByHeight.begin();
    for (;beginitem != vSortedByHeight.end(); ++beginitem) {
        txdb.WriteBlockIndex(beginitem->second);
    }

    if (argc !=4) {
        cout << "At first, put all hyper chain db files in current directory, file name must start with 'hyperchain', and end with '.db'." << endl;
        cout << "\tFor example: hyperchain125.db, hyerchainuuxeee.db" << endl;
        cout << "Usage: stat hid chainnum id" << endl;
        cout << "Result is in paralism.tx" << endl;
        return -1;
    }*/

    return 0;
}
