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

#include "headers.h"
#include "db.h"
#include "net.h"
#include "util.h"
#include "key_io.h"

#include <boost/make_shared.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <algorithm>
using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;
uint64 nAccountingEntryNumber = 0;



//
// CDB
//

static boost::shared_ptr<CCriticalSection> cs_db = boost::make_shared<CCriticalSection>();
static bool fDbEnvInit = false;

boost::shared_ptr<DbEnv> dbenv(new DbEnv(0));

static map<string, int> mapFileUseCount;
static map<string, Db*> mapDb;

thread_local boost::shared_ptr<CTxDB> tls_txdb_instance;
thread_local boost::shared_ptr<CWalletDB> tls_walletdb_instance;
thread_local boost::shared_ptr<CBlockDB> tls_blkdb_instance;
thread_local boost::shared_ptr<COrphanBlockDB> tls_orphanblkdb_instance;

extern CBlockCacheLocator mapBlocks;


extern bool SwitchChainTo(CBlockIndexSP pindexBlock);

CCriticalSection::~CCriticalSection()
{
    //HC: debug cs_db
    //int a = 0;
    //if (this == cs_db.get()) {
    //    a = 1;
    //}
}
class CDBInit
{
public:
    CDBInit()
    {
    }
    ~CDBInit()
    {
        if (fDbEnvInit)
        {
            //HC: dbenv will automatically call close
            //dbenv->close(0);
            fDbEnvInit = false;
        }
    }
}
instance_of_cdbinit;

std::string getdbenv()
{
    string ret;
    CRITICAL_BLOCK(*cs_db)
    {
        cout << "\n\nstat: ****************";
        dbenv->stat_print(0);

        cout << "\n\nlock: ****************";
        dbenv->lock_stat_print(0);

        cout << "\n\nmemp: ****************";
        dbenv->memp_stat_print(0);

        cout << "\n\nlog: ****************";
        dbenv->log_stat_print(0);

        cout << "\n\ntxn: ****************";
        dbenv->txn_stat_print(0);

        cout << "\n\nmutex: ****************";
        dbenv->mutex_stat_print(0);
    }
    return "";
}

CDB::CDB(const char* pszFile, const char* pszMode) : m_dbenv(dbenv), pdb(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    CRITICAL_BLOCK(*cs_db)
    {
        if (!fDbEnvInit)
        {
            if (fShutdown)
                return;
            string strDataDir = GetDataDir();
            string strLogDir = strDataDir + "/database";
            boost::filesystem::create_directory(strLogDir.c_str());
            string strErrorFile = strDataDir + "/db.log";
            TRACE_FL("dbenv.open strLogDir=%s strErrorFile=%s\n", strLogDir.c_str(), strErrorFile.c_str());

            m_dbenv->set_lg_dir(strLogDir.c_str());
            m_dbenv->set_lg_max(10000000);
            m_dbenv->set_lk_max_locks(500000);  //HC:
            m_dbenv->set_lk_max_objects(500000); //HC:
            m_dbenv->set_errfile(fopen(strErrorFile.c_str(), "a")); /// debug
            m_dbenv->set_flags(DB_AUTO_COMMIT, 1);
            ret = m_dbenv->open(strDataDir.c_str(),
                             DB_CREATE     |
                             DB_INIT_LOCK  |
                             DB_INIT_LOG   |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN   |
                             DB_THREAD     |
                             DB_RECOVER,
                             S_IRUSR | S_IWUSR);
            if (ret > 0)
                throw runtime_error(strprintf("CDB() : error %d opening database environment", ret));
            fDbEnvInit = true;
        }

        strFile = pszFile;
        ++mapFileUseCount[strFile];
        internal_cs_db = cs_db;
        pdb = mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(m_dbenv.get(), 0);

            ret = pdb->open(NULL,      // Txn pointer
                            pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret > 0)
            {
                delete pdb;
                pdb = NULL;
                CRITICAL_BLOCK(*cs_db)
                    --mapFileUseCount[strFile];
                internal_cs_db.reset();
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(VERSION);
                fReadOnly = fTmp;
            }

            mapDb[strFile] = pdb;
        }
    }
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (!vTxn.empty())
        vTxn.front()->abort();
    vTxn.clear();
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;
    if (strFile == "addr.dat")
        nMinutes = 2;
    if (strFile == "blkindex.dat" && IsInitialBlockDownload() && nBestHeight % 500 != 0)
        nMinutes = 1;
    m_dbenv->txn_checkpoint(0, nMinutes, 0);

    CRITICAL_BLOCK(*cs_db)
        --mapFileUseCount[strFile];
}

void CloseDb(const string& strFile)
{
    CRITICAL_BLOCK(*cs_db)
    {
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

void DBFlush(bool fRemove)
{
    // Flush log data to the actual data file
    //  on all files that are not in use
    TRACE_FL("DBFlush(%s)%s\n", fRemove ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    CRITICAL_BLOCK(*cs_db)
    {
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            TRACE_FL("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                dbenv->txn_checkpoint(0, 0, 0);
                TRACE_FL("%s flush\n", strFile.c_str());
                dbenv->lsn_reset(strFile.c_str(), 0);
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        if (fRemove)
        {
            char** listp;
            if (mapFileUseCount.empty())
                dbenv->log_archive(&listp, DB_ARCH_REMOVE);
            fDbEnvInit = false;
        }
    }
}






//
// CTxDB
//
bool CTxDB::ReadTxIndex(const uint256& hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(const uint256& hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(const uint256& hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadOwnerTxes(const uint160& hash160, int nMinHeight, vector<CTransaction>& vtx)
{
    assert(!fClient);
    vtx.clear();

    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << string("owner") << hash160 << CDiskTxPos();
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            return false;
        }

        // Unserialize
        string strType;
        uint160 hashItem;
        CDiskTxPos pos;
        ssKey >> strType >> hashItem >> pos;
        int nItemHeight;
        ssValue >> nItemHeight;

        // Read transaction
        if (strType != "owner" || hashItem != hash160)
            break;
        if (nItemHeight >= nMinHeight)
        {
            vtx.resize(vtx.size()+1);
            if (!vtx.back().ReadFromDisk(pos))
            {
                pcursor->close();
                return false;
            }
        }
    }

    pcursor->close();
    return true;
}

bool CTxDB::ReadDiskTx(const uint256& hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(const uint256& hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint& outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex)
{
    return Read(make_pair(string("blockindex"), hash), blockindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::EraseBlockIndex(uint256 hash)
{
    return Erase(make_pair(string("blockindex"), hash));
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
    return Read(string("bnBestInvalidWork"), bnBestInvalidWork);
}

bool CTxDB::WriteBestInvalidWork(CBigNum bnBestInvalidWork)
{
    return Write(string("bnBestInvalidWork"), bnBestInvalidWork);
}

static CBlockIndexSP InsertBlockIndex(const uint256 &hash, int nHeight)
{
    if (hash == 0)
        return NULL;

    // Return existing
    auto mi = mapBlockIndex.fromcache(hash);
    if (mi)
        return mi;

    // Create new
    CBlockIndexSP pindexNew = make_shared_proxy<CBlockIndex>();
    if (!pindexNew)
        throw runtime_error("InsertBlockIndex() : new CBlockIndex failed");
    pindexNew->nHeight = nHeight;
    pindexNew->hashBlock = hash;

    return pindexNew;
}

bool CTxDB::CheckBestBlockIndex()
{
    if (!pindexBest) {
        pindexBest = pindexGenesisBlock;
    }
    hashBestChain = pindexBest->GetBlockHash();
    nBestHeight = pindexBest->nHeight;
    bnBestChainWork = pindexBest->bnChainWork;

    TRACE_FL("CheckBestBlockIndex(): hashBestChain=%s  height=%d\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight);
    return true;
}

CBlockIndexSP CTxDB::ConstructBlockIndex(const uint256 &hash, CDiskBlockIndex& diskindex)
{
    const CBlockIndex *pidx = diskindex.GetBlockIndex();
    CBlockIndexSP pindexNew = InsertBlockIndex(hash, pidx->nHeight);
    //pindexNew->pprev = InsertBlockIndex(diskindex.hashPrev, diskindex.nHeight - 1);
    //pindexNew->pnext = InsertBlockIndex(diskindex.hashNext, diskindex.nHeight + 1);
    pindexNew->hashPrev = pidx->hashPrev;
    pindexNew->hashNext = pidx->hashNext;
    //HC: add block address
    pindexNew->triaddr = pidx->triaddr;
    pindexNew->nVersion = pidx->nVersion;
    pindexNew->hashMerkleRoot = pidx->hashMerkleRoot;
    pindexNew->nTime = pidx->nTime;
    pindexNew->nBits = pidx->nBits;
    pindexNew->nNonce = pidx->nNonce;
    pindexNew->nSolution = pidx->nSolution;
    pindexNew->ownerNodeID = pidx->ownerNodeID;
    pindexNew->nPrevHID = pidx->nPrevHID;
    pindexNew->hashExternData = pidx->hashExternData;
    pindexNew->hashPrevHyperBlock = pidx->hashPrevHyperBlock;
    pindexNew->bnChainWork = pidx->bnChainWork;

    //HC: Notice: firstly must set block index value before putting into block index pool, else cause chain work(bnChainWork) error
    mapBlockIndex.insert(make_pair(hash, pindexNew),false);
    return pindexNew;
}

//HC: erase the block index not in main chain
bool CTxDB::CleanaBlockIndex()
{
    vector<uint256> vecClean;
    int nCurrBestHeight = pindexBest->nHeight;

    set<uint256> setBlkIndexInMain;
    auto pIndex = pindexBest;
    while (pIndex) 	{
        setBlkIndexInMain.insert(pIndex->hashBlock);
        pIndex = pIndex->pprev();
    }

    std::function<bool(CDataStream&, CDataStream&, uint256&)> fn = [this, nCurrBestHeight, &vecClean, &setBlkIndexInMain](CDataStream& ssKeySecond,
        CDataStream& ssValue, uint256& nextT) ->bool {

        CBlockIndex blkindex;
        CDiskBlockIndex diskindex(&blkindex);

        ssKeySecond >> nextT;
        ssValue >> diskindex;
        if (blkindex.nHeight < nCurrBestHeight - 1000  && !setBlkIndexInMain.count(nextT)) {
            vecClean.push_back(nextT);
        }
        return true;
    };

    std::function<CDataStream(const uint256&, string&)> fnNext = [&vecClean](const uint256& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("blockindex"), nextT);
        msgstatus = strprintf("blockindex: %s cleaning: %d", nextT.ToPreViewString().c_str(), vecClean.size());  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("blockindex"), uint256(0));

    if (!BulkLoad("blockindex", ssKey, fn, fnNext)) {
        return false;
    }

    cout << strprintf("%d block indexes will be erased\n", vecClean.size());

    CommadLineProgress progress;
    progress.Start();

    int nCount = 0;
    for (auto &hash : vecClean) {
        EraseBlockIndex(hash);
        if (nCount++ % 1000 == 0) {
            progress.PrintStatus(100, StringFormat("Deleted: %d", nCount));
        }
    }
    return true;
}

bool CTxDB::LoadBlockIndex()
{
    int nFileVersion;

    /////////////////////////////////////////////////////////////////////////////////////
    //HC: upgrade to v0.7.3
    bool is_upgrade_to_v73 = false;
    if (ReadVersion(nFileVersion) && nFileVersion <= VERSION_V72) {
        cout << "Para: need to delete a part of index files of v0.7.2... ";
        if (!DeleteOldIndexFilesOfV72()) {
            cerr << "Failed to remove old index files of v0.7.2\n";
            return false;
        }
        cout << "deleted\n";

        //HC: create
        {
            COrphanBlockTripleAddressDB db("cr+");
        }

        //HC: should upgrade block index
        cout << "Para: need to upgrading block index... ";
        if (UpgradeBlockIndexFormatOfV72()) {
            WriteVersion(VERSION); //HC: 2021-7-16 v0.7.3
        } else {
            cerr << "Failed to upgrade block index format of v0.7.2\n";
            return false;
        }
        is_upgrade_to_v73 = true;
    }
    /////////////////////////////////////////////////////////////////////////////////////

    bool bscanbestindex = false;
    std::map<uint256, CBlockIndexSP> mBlockIndextmp;
    //HC: This is a important functionality
    if (GetBoolArg("-scanbestindex")) {
        bscanbestindex = true;
    }

    size_t nNumRead = 0;
    size_t nMaxCapBlkIdx = mapBlockIndex.capacity() / 10;

    uint64 totoltm = 0;
    std::function<bool(CDataStream&, CDataStream&, uint256&)> fn = [this, &totoltm, bscanbestindex, &mBlockIndextmp, &nNumRead, nMaxCapBlkIdx](CDataStream& ssKeySecond,
        CDataStream& ssValue, uint256& nextT) ->bool {

        CSpentTime st1;

        CBlockIndex blkindex;
        CDiskBlockIndex diskindex(&blkindex);

        ssKeySecond >> nextT;
        ssValue >> diskindex;

        CBlockIndexSP pindexNew = ConstructBlockIndex(nextT, diskindex);


        if (bscanbestindex && pindexNew->hashNext != 0) {
            mBlockIndextmp.insert({ pindexNew->GetBlockHash(), pindexNew });
        }

        if (!pindexNew->CheckIndex()) {
            return ERROR_FL("CheckIndex failed at %d", pindexNew->nHeight);
        }

        totoltm += st1.Elapse();

        // Watch for genesis block
        if (pindexGenesisBlock == NULL && pindexNew->hashBlock == hashGenesisBlock)
            pindexGenesisBlock = pindexNew;

        nNumRead++;
        if (nNumRead > nMaxCapBlkIdx && !bscanbestindex) {
            //HC: end load
            return false;
        }

        return true;
    } ;

    std::function<CDataStream(const uint256&, string&)> fnNext = [&nNumRead, bscanbestindex, nMaxCapBlkIdx](const uint256& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;

        if (nNumRead > nMaxCapBlkIdx && !bscanbestindex) {
            //HC: end load
            ssNxtKey << make_pair(string("blockindex"), uint256(string(64, 'f')));
        } else {
            ssNxtKey << make_pair(string("blockindex"), nextT);
        }

        msgstatus = strprintf("blockindex : %s", nextT.ToPreViewString().c_str());  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("blockindex"), uint256(0));

    if (!BulkLoad("blockindex", ssKey, fn, fnNext)) {
        return false;
    }
    cout << strprintf("ConstructBlockIndex spent: %u(ms)\n", totoltm);

    //HC: get genesis block
    if (pindexGenesisBlock == NULL) {
        if (mapBlockIndex.count(hashGenesisBlock)) {
            pindexGenesisBlock = mapBlockIndex[hashGenesisBlock];
        }
    }


    //HC: unnecessary
    // Calculate bnChainWork
    //vector<pair<int, CBlockIndexSP> > vSortedByHeight;
    //vSortedByHeight.reserve(mapBlockIndex.size());
    //BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndexSP)& item, mapBlockIndex)
    //{
    //    CBlockIndexSP pindex = item.second;
    //    vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    //}
    //sort(vSortedByHeight.begin(), vSortedByHeight.end());
    //BOOST_FOREACH(const PAIRTYPE(int, CBlockIndexSP)& item, vSortedByHeight)
    //{
    //    CBlockIndexSP pindex = item.second;
    //    auto spprev = pindex->pprev();
    //    pindex->bnChainWork = (spprev ? spprev->bnChainWork : 0) + pindex->GetBlockWork();
    //}


    //HC: Read best chain from database
    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL) {
            return true;
        }
        hashBestChain = pindexGenesisBlock->GetBlockHash();
    }
    if (!mapBlockIndex.count(hashBestChain)) {
        ERROR_FL("hashBestChain not found in the block index");
        hashBestChain = hashGenesisBlock;
    }

    pindexBest = mapBlockIndex[hashBestChain];

    //HC:
    //auto maxindex = std::max_element(mapBlockIndex.begin(), mapBlockIndex.end());
    CheckBestBlockIndex();

    // Load bnBestInvalidWork, OK if it doesn't exist
    //HC:
    ReadBestInvalidWork(bnBestInvalidWork);


    if (GetBoolArg("-scanbestindex")) {
        cout << "Paracoin: scan the block indexes in best chain...\n";

        //HC: set hashNext = 0;
        cout << StringFormat("Firstly set %d blocks indexes: hashNext = 0, wait for a while...\n", mBlockIndextmp.size());
        for (auto& elm : mapBlockIndex) {
            if (elm.second->hashNext != 0) {
                elm.second->hashNext = 0;
            }
        }

        CommadLineProgress progress;
        int nTotalScanned = 0;
        TxnBegin();

        progress.Start();
        for (auto& elm : mBlockIndextmp) {
            nTotalScanned++;
            elm.second->hashNext = 0;
            if (!WriteBlockIndex(CDiskBlockIndex(elm.second.get()))) {
                TxnAbort();
                cerr << ("WriteBlockIndex failed when scanning the block indexes\n");
                return false;
            }

            if (nTotalScanned % 1000 == 0) {
                progress.PrintStatus(1000, strprintf("set hashNext: %d", nTotalScanned));
            }

            if (nTotalScanned % 10000 == 0) {
                //HC: avoid EXCEPTION: Db::get: Not enough space which is caused by not enough lock to use
                if (!TxnCommit()) {
                    cerr << ("TxnCommit failed when scanning the block indexes\n");
                    return false;
                }
                TxnBegin();
            }
        }
        if (!TxnCommit()) {
            cerr << ("TxnCommit failed when scanning the block indexes\n");
            return false;
        }
        cout << StringFormat("\nset %d blocks indexes: hashNext = 0\n", mBlockIndextmp.size());

        cout << "Secondly scan all blocks indexes in best chain, and set their hashNext..." << endl;

        TxnBegin();

        progress.Start();

        nTotalScanned = 0;
        int nFixed = 0;
        auto pprevindex = pindexBest->pprev();
        auto pindex = pindexBest;

        while (pindex && pprevindex) {
            nTotalScanned++;
            if (nTotalScanned % 1000 == 0) {
                progress.PrintStatus(1000, strprintf("scanned: %d, fixed: %d", nTotalScanned, nFixed));
            }

            if (nTotalScanned % 10000 == 0) {
                //HC: avoid EXCEPTION: Db::get: Not enough space which is caused by not enough lock to use
                TxnCommit();
                TxnBegin();
            }

            if (pprevindex->hashNext == pindex->GetBlockHash()) {
                if (pprevindex->nHeight + 1 != pindex->nHeight) {
                    cerr << strprintf("Critical error: block index data, %d(%s) %d(%s), please rescan block data with '-rescan'\n",
                        pprevindex->nHeight, pprevindex->GetBlockHash().ToPreViewString().c_str(),
                        pindex->nHeight, pindex->GetBlockHash().ToPreViewString().c_str());
                    return false;
                }
            }
            else {
                pprevindex->hashNext = pindex->GetBlockHash();
                if (!WriteBlockIndex(CDiskBlockIndex(pprevindex.get()))) {
                    TxnAbort();
                    cerr << ("WriteBlockIndex failed when scanning the block indexes\n");
                    return false;
                }
                nFixed++;
            }
            pindex = pprevindex;
            pprevindex = pindex->pprev();
        }

        if (!TxnCommit()) {
            cerr << ("TxnCommit failed when scanning the block indexes\n");
            return false;
        }
        progress.PrintStatus(1, strprintf("scanned: %d, fixed: %d", nTotalScanned, nFixed));
        cout << "\n";
    }

    /////////////////////////////////////////////////////////////////////////////////////
    //HC: upgrade to v0.7.3.802
    int nTxVersion = 0;
    if (is_upgrade_to_v73 || !ReadTxVersion(nTxVersion) || nTxVersion < TXIDX_VERSION) {
        cout << "Para: need to upgrade transaction indexes format of v0.7.2...\n";
        if (UpgradeTxIndexFormatofV72()) {
            WriteTxVersion(TXIDX_VERSION);
        } else {
            cerr << ("Failed to upgrade transaction indexes format of v0.7.2\n");
            return false;
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////

    cout << "Paracoin: verifying blocks in the best chain...\n";

    //HC: Check about 50 blocks
    int nCurrHeight = nBestHeight - 1;
    CBlockIndexSP pindexFork = nullptr;
    CBlockIndexSP pindex = pindexBest->pprev();
    CBlockIndexSP pprevindex;
    if(pindex)
        pprevindex = pindex->pprev();
    for (; pindex && pprevindex; pindex = pprevindex, pprevindex = pindex->pprev(), nCurrHeight--) {

        if (pindex->nTime == 0 || pindex->nSolution.size() == 0) {
            WARNING_FL("LoadBlockIndex() : *** error block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
            continue;
        }

        if (pindex->nHeight < nBestHeight - 50 && !mapArgs.count("-checkblocks"))
            break;

        if (!pindex->triaddr.isValid() && !mapBlocks.contain(pindex->GetBlockHash())) {
            continue;
        }

        CBlock block;
        if (!block.ReadFromDisk(pindex)) {
            WARNING_FL("LoadBlockIndex() : *** cannot read block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
            continue;
        }

        if (!block.CheckBlock()) {
            WARNING_FL("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
        }
    }

    if (pindex && !pindex->pprev() && nCurrHeight > 0) {
        cerr << ("LoadBlockIndex(): block index is bad, To rebuild, please remove blkindex.dat and restart the program\n");
        return false;

        //pindexBest = pindexGenesisBlock;
        //while (pindexBest && pindexBest->pnext) {
        //    pindexBest = pindexBest->pnext;
        //}
        //CheckBestBlockIndex(pindexBest);
    }

    if (pindexFork) {
        // Reorg back to the fork
        cout << StringFormat("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        if (!SwitchChainTo(pindexFork)) {
            cerr << ("LoadBlockIndex() : SwitchChainTo failed\n");
            return false;
        }
    }

    return true;
}

//
//CBlockDB
//

//HC: Load the blocks which waiting to do global buddy consensus
bool CBlockDB::LoadBlockUnChained(CBlockBloomFilter &filterBlk)
{
    bool ret = Load("block", [&](CDataStream& ssKey, CDataStream& ssValue) -> bool {

        //CBlock block;
        //ssValue >> block;

        uint256 hash;
        ssKey >> hash;

        //assert(hash == block.GetHash());
        filterBlk.insert(hash);

        return true;
    });
    return ret;
}


//HC: Load the blocks which waiting to do global buddy consensus
bool CBlockDB::LoadBlockUnChained(const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f)
{
    return Load("block",hash, f);
}

bool CBlockDB::ReadBlock(const uint256& hash, CBlock& block)
{
    return Read(make_pair(string("block"), hash), block);
}

bool CBlockDB::WriteBlock(const CBlock& block)
{
    return Write(make_pair(string("block"), block.GetHash()), block);
}

bool CBlockDB::WriteBlock(const uint256& hash, const CBlock& block)
{
    return Write(make_pair(string("block"), hash), block);
}

bool CBlockDB::EraseBlock(uint256 hash)
{
    return Erase(make_pair(string("block"), hash));
}

//
//CTxDB
//
bool CTxDB::ReadSP(const uint256& hash, CDiskBlockIndex & diskindex)
{
    if (!ReadBlockIndex(hash, diskindex)) {
        return false;
    }

    return true;
}

bool CTxDB::WriteSP(const CBlockIndex* blockindex)
{
    CBlockIndex *idx = const_cast<CBlockIndex*>(blockindex);
    CDiskBlockIndex diskindex(idx);
    return WriteBlockIndex(diskindex);
}

//
//CBlockTripleAddressDB
//
bool CBlockTripleAddressDB::LoadBlockTripleAddress()
{
    return Load("triaddr", [](CDataStream& ssKey, CDataStream& ssValue) -> bool {

        BLOCKTRIPLEADDRESS blocktripleaddr;
        ssValue >> blocktripleaddr;
        uint256 hash;
        ssKey >> hash;
        LatestParaBlock::AddBlockTripleAddress(hash, blocktripleaddr);
        return true;
    });
}


bool CBlockTripleAddressDB::ReadMaxHID(uint32 &maxhid)
{
    return Read(string("maxhid"), maxhid);
}

bool CBlockTripleAddressDB::WriteMaxHID(uint32 hid)
{
    return Write(string("maxhid"), hid);
}


bool CBlockTripleAddressDB::ReadBlockTripleAddress(const uint256& hash, BLOCKTRIPLEADDRESS& addr)
{
    return Read(make_pair(string("triaddr"), hash), addr);
}

bool CBlockTripleAddressDB::WriteBlockTripleAddress(const uint256& hash, const BLOCKTRIPLEADDRESS& addr)
{
    return Write(make_pair(string("triaddr"), hash), addr);
}

bool CBlockTripleAddressDB::EraseBlockTripleAddress(const uint256& hash)
{
    return Erase(make_pair(string("triaddr"), hash));
}


//
// CAddrDB
//

bool CAddrDB::WriteAddress(const CAddress& addr)
{
    return Write(make_pair(string("addr"), addr.GetKey()), addr);
}

bool CAddrDB::EraseAddress(const CAddress& addr)
{
    return Erase(make_pair(string("addr"), addr.GetKey()));
}

bool CAddrDB::LoadAddresses()
{
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        // Load user provided addresses
        CAutoFile filein = fopen((GetDataDir() + "/addr.txt").c_str(), "rt");
        if (filein)
        {
            try
            {
                char psz[1000];
                while (fgets(psz, sizeof(psz), filein))
                {
                    CAddress addr(psz, false, NODE_NETWORK);
                    addr.nTime = 0; // so it won't relay unless successfully connected
                    if (addr.IsValid())
                        AddAddress(addr);
                }
            }
            catch (...) { }
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            ssKey >> strType;
            if (strType == "addr")
            {
                CAddress addr;
                ssValue >> addr;
                mapAddresses.insert(make_pair(addr.GetKey(), addr));
            }
        }
        pcursor->close();

        TRACE_FL("Loaded %d addresses\n", mapAddresses.size());
    }

    return true;
}

bool LoadAddresses()
{
    return CAddrDB("cr+").LoadAddresses();
}




//
// CWalletDB
//

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdated++;
    return Erase(make_pair(string("name"), strAddress));
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const CAccountingEntry& acentry)
{
    return Write(boost::make_tuple(string("acentry"), acentry.strAccount, ++nAccountingEntryNumber), acentry);
}

int64 CWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    int64 nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << boost::make_tuple(string("acentry"), (fAllAccounts? string("") : strAccount), uint64(0));
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        entries.push_back(acentry);
    }

    pcursor->close();
}


int CWalletDB::BulkLoadWalletUser(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, string&)> fn = [this,pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, string& strAddress) ->bool {

        ssKeySecond >> strAddress;
        CTxDestination address = DecodeDestination(strAddress);
        if (!IsValidDestination(address))
            cerr << "Error: Invalid address calling BulkLoadWalletUser: " << strAddress << endl;
        else
            ssValue >> pwallet->mapAddressBook[address];
        return true;
    };

    std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("name"), nextT);
        msgstatus = strprintf("name : %s", nextT.c_str());  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("name"), string(""));

    if (!BulkLoad("name", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletTx(CWallet* pwallet, vector<uint256>& vWalletUpgrade)
{
    std::function<bool(CDataStream&, CDataStream&, uint256&)> fn = [pwallet, &vWalletUpgrade](CDataStream& ssKeySecond,
        CDataStream& ssValue, uint256& hash) ->bool {

        ssKeySecond >> hash;
        CWalletTx& wtx = pwallet->mapWallet[hash];
        ssValue >> wtx;
        wtx.pwallet = pwallet;

        if (wtx.GetHash() != hash)
            ERROR_FL("Error in wallet.dat, hash mismatch\n");

        // Undo serialize changes in 31600
        if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703) {
            if (!ssValue.empty()) {
                char fTmp;
                char fUnused;
                ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                TRACE_FL("LoadWallet() upgrading tx ver=%d %d '%s' %s\n", wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount.c_str(), hash.ToString().c_str());
                wtx.fTimeReceivedIsTxTime = fTmp;
            }
            else {
                TRACE_FL("LoadWallet() repairing tx ver=%d %s\n", wtx.fTimeReceivedIsTxTime, hash.ToString().c_str());
                wtx.fTimeReceivedIsTxTime = 0;
            }
            vWalletUpgrade.push_back(hash);
        }

        //// debug print
        //DEBUG_FL("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
        //DEBUG_FL(" %12I64d  %s  %s  %s\n",
        //    wtx.vout[0].nValue,
        //    DateTimeStrFormat("%x %H:%M:%S", wtx.GetBlockTime()).c_str(),
        //    wtx.hashBlock.ToString().substr(0,20).c_str(),
        //    wtx.mapValue["message"].c_str());        return true;
        return true;
    };

    std::function<CDataStream(const uint256&, string&)> fnNext = [](const uint256& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("tx"), nextT);
        msgstatus = strprintf("tx : %s", nextT.ToPreViewString().c_str());  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("tx"), uint256(0));

    if (!BulkLoad("tx", ssKey, fn, fnNext)) {

        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletAcentry(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, string&)> fn = [](CDataStream& ssKeySecond,
        CDataStream& ssValue, string& strAccount) ->bool {

        ssKeySecond >> strAccount;
        uint64 nNumber;
        ssKeySecond >> nNumber;
        if (nNumber > nAccountingEntryNumber)
            nAccountingEntryNumber = nNumber;
        return true;
    };

    std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("acentry"), nextT);
        msgstatus = strprintf("acentry : %s", nextT.c_str());  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("acentry"), string(""));

    if (!BulkLoad("acentry", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletCScript(CWallet* pwallet)
{
    LegacyScriptPubKeyMan* pman = pwallet->GetOrCreateLegacyScriptPubKeyMan();
    if (!pman) {
        cerr << "Error reading wallet database: CWallet::GetOrCreateLegacyScriptPubKeyMan failed\n";
        return false;
    }

    std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn = [pman](CDataStream& ssKeySecond,
        CDataStream& ssValue, std::vector<unsigned char>& vchPubKey) ->bool {

            CScript redeemScript;
            ssValue >> redeemScript;
            pman->LoadCScript(redeemScript);
            return true;
    };

    std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
        string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("cscript"), nextT);
            msgstatus = "cscript : ******";  //HC: status message
            return ssNxtKey;
    };

    CDataStream ssKey;
    std::vector<unsigned char> veckey;
    ssKey << make_pair(string("cscript"), veckey);

    if (!BulkLoad("cscript", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}


int CWalletDB::BulkLoadWalletKey(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, std::vector<unsigned char>& vchPubKey) ->bool {

        //HC: read all used key pairs
        ssKeySecond >> vchPubKey;
        CKey key;
        CPrivKey pkey;
        ssValue >> pkey;
        key.SetPrivKey(pkey);

        if (!pwallet->LoadKey(vchPubKey, key))
            return false; //DB_CORRUPT;
        return true;
    };

    std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("key"), nextT);
        msgstatus = "key : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    std::vector<unsigned char> veckey;
    ssKey << make_pair(string("key"), veckey);

    if (!BulkLoad("key", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletWKey(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, std::vector<unsigned char>& vchPubKey) ->bool {

        //HC: read all used key pairs
        ssKeySecond >> vchPubKey;
        CKey key;
        CWalletKey wkey;
        ssValue >> wkey;
        key.SetPrivKey(wkey.vchPrivKey);
        if (!pwallet->LoadKey(vchPubKey, key))
            return false; //DB_CORRUPT;
        return true;
    };

    std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("wkey"), nextT);
        msgstatus = "wallet key : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    std::vector<unsigned char> veckey;
    ssKey << make_pair(string("wkey"), veckey);

    if (!BulkLoad("wkey", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletMKey(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, unsigned int&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, unsigned int &nID) ->bool {

        ssKeySecond >> nID;
        CMasterKey kMasterKey;
        ssValue >> kMasterKey;
        if (pwallet->mapMasterKeys.count(nID) != 0)
            return false; //DB_CORRUPT;
        pwallet->mapMasterKeys[nID] = kMasterKey;
        if (pwallet->nMasterKeyMaxID < nID)
            pwallet->nMasterKeyMaxID = nID;
        return true;
    };

    std::function<CDataStream(const unsigned int&, string&)> fnNext = [](const unsigned int &nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("mkey"), nextT);
        msgstatus = "mkey : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("mkey"), 0);
    if (!BulkLoad("mkey", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletCKey(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, std::vector<unsigned char>& vchPubKey) ->bool {

        ssKeySecond >> vchPubKey;
        vector<unsigned char> vchPrivKey;
        ssValue >> vchPrivKey;
        if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            return false;//DB_CORRUPT;
        return true;
    };

    std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("ckey"), nextT);
        msgstatus = "ckey : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    std::vector<unsigned char> veckey;
    ssKey << make_pair(string("ckey"), veckey);

    if (!BulkLoad("ckey", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletPool(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, int64&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, int64& nIndex) ->bool {

        //HC: read all unused key pairs
        ssKeySecond >> nIndex;
        pwallet->setKeyPool.insert(nIndex);
        return true;
    };

    std::function<CDataStream(const int64&, string&)> fnNext = [](const int64 &nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("pool"), nextT);
        msgstatus = "pool : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("pool"), 0);
    if (!BulkLoad("pool", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWalletSettings(CWallet* pwallet)
{
    std::function<bool(CDataStream&, CDataStream&, string&)> fn = [pwallet](CDataStream& ssKeySecond,
        CDataStream& ssValue, string& strKey) ->bool {

        //HC: read all unused key pairs
        ssKeySecond >> strKey;

        // Options
#ifndef GUI
        if (strKey == "fGenerateBitcoins")  ssValue >> fGenerateBitcoins;
#endif
        if (strKey == "nTransactionFee")    ssValue >> nTransactionFee;
        if (strKey == "fLimitProcessors")   ssValue >> fLimitProcessors;
        if (strKey == "nLimitProcessors")   ssValue >> nLimitProcessors;
        if (strKey == "fMinimizeToTray")    ssValue >> fMinimizeToTray;
        if (strKey == "fMinimizeOnClose")   ssValue >> fMinimizeOnClose;
        if (strKey == "fUseProxy")          ssValue >> fUseProxy;
        if (strKey == "addrProxy")          ssValue >> addrProxy;
        if (fHaveUPnP && strKey == "fUseUPnP")           ssValue >> fUseUPnP;
        return true;
    };

    std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
        string& msgstatus) ->CDataStream {

        CDataStream ssNxtKey;
        ssNxtKey << make_pair(string("setting"), nextT);
        msgstatus = "setting : ******";  //HC: status message
        return ssNxtKey;
    };

    CDataStream ssKey;
    ssKey << make_pair(string("setting"), string(""));
    if (!BulkLoad("setting", ssKey, fn, fnNext)) {
        return false;
    }
    return true;
}

int CWalletDB::BulkLoadWallet(CWallet* pwallet, vector<uint256> &vWalletUpgrade, int &nFileVersion)
{
    BulkLoadWalletUser(pwallet);

    bool isLoadTxAndKey = !GetBoolArg("-noloadwallet");
    if (isLoadTxAndKey) {
        //HC: load tx and keys
        BulkLoadWalletTx(pwallet, vWalletUpgrade);
        BulkLoadWalletAcentry(pwallet);

        if (!BulkLoadWalletCScript(pwallet))
            return DB_CORRUPT;

        if (!BulkLoadWalletKey(pwallet))
            return DB_CORRUPT;

        if (!BulkLoadWalletWKey(pwallet))
            return DB_CORRUPT;

        if (!BulkLoadWalletMKey(pwallet))
            return DB_CORRUPT;

        if (!BulkLoadWalletCKey(pwallet))
            return DB_CORRUPT;
    } else {
        cout << "Skip Txes and Keys in the wallets\n";
    }

    ReadDefaultKey(pwallet->vchDefaultKey);
    bool ret = ReadDefaultKeyType(pwallet->defaultType);
    if (!ret) {
        //HC: version < v0.7.5 will return false
        pwallet->defaultType = OutputType::LEGACY;
    }

    BulkLoadWalletPool(pwallet);

    if (!isLoadTxAndKey) {
        //HC: load a part of keys
        if (!pwallet->vchDefaultKey.empty()) {
            CDataStream ssKey;
            ssKey << make_pair(string("key"), pwallet->vchDefaultKey);
            //HC: Load default key
            CPrivKey pkey;
            if (Read(ssKey, pkey)) {
                CKey key;
                key.SetPrivKey(pkey);
                pwallet->LoadKey(pwallet->vchDefaultKey, key);
            }
        }

        //HC: Load keys in KeyPool
        for (auto nIndex : pwallet->setKeyPool) {
            CKeyPool keypool;
            if (!ReadPool(nIndex, keypool))
                continue;

            CDataStream ssKey;
            ssKey << make_pair(string("key"), keypool.vchPubKey);
            CPrivKey pkey;
            if (Read(ssKey, pkey)) {
                CKey key;
                key.SetPrivKey(pkey);
                pwallet->LoadKey(keypool.vchPubKey, key);
            }
        }
    }

    BulkLoadWalletSettings(pwallet);

    ReadVersion(nFileVersion);
    if (nFileVersion == 10300)
        nFileVersion = 300;

    int nMinVersion = 0;
    Read(std::string("minversion"), nMinVersion);
    if (nMinVersion > VERSION)
        return DB_TOO_NEW;

    return 0;
}

int CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey.clear();
    pwallet->setKeyPool.clear();
    int nFileVersion = 0;
    vector<uint256> vWalletUpgrade;

    // Modify defaults
#ifndef __WXMSW__
    // Tray icon sometimes disappears on 9.10 karmic koala 64-bit, leaving no way to access the program
    fMinimizeToTray = false;
    fMinimizeOnClose = false;
#endif

    //// todo: shouldn't we catch exceptions and try to recover and continue?
    CRITICAL_BLOCK(pwallet->cs_wallet)
    {
        //HC: bulk load
        int ret = BulkLoadWallet(pwallet, vWalletUpgrade, nFileVersion);
        if (ret != 0) {
            return ret;
        }
    }

    BOOST_FOREACH(uint256 hash, vWalletUpgrade)
        WriteTx(hash, pwallet->mapWallet[hash]);

    TRACE_FL("nFileVersion = %d\n", nFileVersion);
    TRACE_FL("fGenerateBitcoins = %d\n", fGenerateBitcoins);
    TRACE_FL("nTransactionFee = %" PRI64d "\n", nTransactionFee);
    TRACE_FL("fMinimizeToTray = %d\n", fMinimizeToTray);
    TRACE_FL("fMinimizeOnClose = %d\n", fMinimizeOnClose);
    TRACE_FL("fUseProxy = %d\n", fUseProxy);
    TRACE_FL("addrProxy = %s\n", addrProxy.ToString().c_str());
    if (fHaveUPnP)
        TRACE_FL("fUseUPnP = %d\n", fUseUPnP);


    // Upgrade
    if (nFileVersion < VERSION)
    {
        // Get rid of old debug.log file in current directory
        if (nFileVersion <= 105 && !pszSetDataDir[0])
            unlink("debug.log");

        WriteVersion(VERSION);
    }


    return DB_LOAD_OK;
}

void ThreadFlushWalletDB(void* parg)
{
    const string& strFile = ((const string*)parg)[0];
    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
    if (mapArgs.count("-noflushwallet"))
        return;

    unsigned int nLastSeen = nWalletDBUpdated;
    unsigned int nLastFlushed = nWalletDBUpdated;
    int64 nLastWalletUpdate = GetTime();
    while (!fShutdown)
    {
        Sleep(500);

        if (nLastSeen != nWalletDBUpdated)
        {
            nLastSeen = nWalletDBUpdated;
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2)
        {
            TRY_CRITICAL_BLOCK(*cs_db)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = mapFileUseCount.begin();
                while (mi != mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0 && !fShutdown)
                {
                    map<string, int>::iterator mi = mapFileUseCount.find(strFile);
                    if (mi != mapFileUseCount.end())
                    {
                        TRACE_FL("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
                        TRACE_FL("Flushing wallet.dat\n");
                        nLastFlushed = nWalletDBUpdated;
                        int64 nStart = GetTimeMillis();

                        // Flush wallet.dat so it's self contained
                        CloseDb(strFile);
                        dbenv->txn_checkpoint(0, 0, 0);
                        dbenv->lsn_reset(strFile.c_str(), 0);

                        mapFileUseCount.erase(mi++);
                        TRACE_FL("Flushed wallet.dat %" PRI64d "ms\n", GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const CWallet& wallet, const string& strDest, string &errmsg)
{
    if (!wallet.fFileBacked) {
        errmsg = "wallet object error";
        return false;
    }

    int nCount = 0;
    while (!fShutdown)
    {
        if (nCount > 10) {
            errmsg = "wallet file is opened, now cannot backup";
            break;
        }
        CRITICAL_BLOCK(*cs_db)
        {
            if (!mapFileUseCount.count(wallet.strWalletFile) || mapFileUseCount[wallet.strWalletFile] == 0)
            {
                // Flush log data to the dat file
                CloseDb(wallet.strWalletFile);
                dbenv->txn_checkpoint(0, 0, 0);
                dbenv->lsn_reset(wallet.strWalletFile.c_str(), 0);
                mapFileUseCount.erase(wallet.strWalletFile);

                // Copy wallet.dat
                boost::filesystem::path pathSrc(GetDataDir() + "/" + wallet.strWalletFile);
                boost::filesystem::path pathDest(strDest);
                if (boost::filesystem::is_directory(pathDest))
                    pathDest = pathDest / wallet.strWalletFile;
#if BOOST_VERSION >= 104000
                boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists);
#else
                filesystem::copy_file(pathSrc, pathDest);
#endif
                TRACE_FL("copied wallet.dat to %s\n", pathDest.string().c_str());

                return true;
            }
        }
        Sleep(100);
        nCount++;
    }
    return false;
}

//////////////////////////////////////////////////////////////////////////
extern ParaMQCenter paramqcenter;
bool CMainTrunkDB::LoadData()
{
    int nMaxHeight = 0;
    Read(string("maxheight"), nMaxHeight);

    CBlockLocatorEx &mtc = paramqcenter.GetMTC();
    uint256 hash;
    for (int i = 0; i <= nMaxHeight; i+= mtc.nHeightSpan) {
        if (ReadData(i, hash)) {
            mtc.Add(i, hash);
        }
    }

    int h = mtc.GetLInnerHeight();
    if (ReadData(h, hash)) {
        mtc.hashvHaveLInner = hash;
    }

    return true;
}


bool CMainTrunkDB::ReadData(int nHeight, uint256 &hash)
{
    return Read(make_pair(string("mtrunk"), nHeight), hash);
}

bool CMainTrunkDB::WriteData(int nHeight, const uint256 &hash)
{
    return Write(make_pair(string("mtrunk"), nHeight), hash);
}


bool CMainTrunkDB::WriteMaxHeight(int nMaxHeight)
{
    return Write(string("maxheight"), nMaxHeight);
}

bool CMainTrunkDB::EraseData(int nHeight)
{
    return Erase(make_pair(string("mtrunk"), nHeight));
}


