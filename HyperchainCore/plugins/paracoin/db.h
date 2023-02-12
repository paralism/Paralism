/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include "headers/inter_public.h"
#include "key.h"
#include "block.h"
#include "utilc.h"
#include "outputtype.h"

#include <map>
#include <string>
#include <vector>

#include <db_cxx.h>

class CTxIndex;
class CDiskBlockIndex;
class CDiskTxPos;
class COutPoint;
class CAddress;
class CWalletTx;
class CWallet;
class CAccount;
class CAccountingEntry;
class CBlockLocator;
class CBlock;
class CBlockIndex;
class BLOCKTRIPLEADDRESS;
template<class T>
class shared_ptr_proxy;

class CBlockBloomFilter;
class CommadLineProgress;


extern unsigned int nWalletDBUpdated;

extern boost::shared_ptr<DbEnv> dbenv;



void CloseDb(const string& strFile);
void DBFlush(bool fShutdown);

void ThreadFlushWalletDB(void* parg);
bool BackupWallet(const CWallet& wallet, const std::string& strDest, string& errmsg);
std::string getdbenv();

#if !defined CBlockIndexSP
using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;
#endif


class CDB
{
protected:
    boost::shared_ptr<DbEnv> m_dbenv;
    boost::shared_ptr<CCriticalSection> internal_cs_db;  //HCE: avoid to release cs_db before CDB object was released
    Db* pdb;
    std::string strFile;
    std::vector<DbTxn*> vTxn;
    bool fReadOnly;

    explicit CDB(const char* pszFile, const char* pszMode="r+");
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:

    template<typename K, typename NT, typename... Args>
    bool BulkLoad(const std::string& keytype, const K& keyload,
        std::function<bool(CDataStream&, CDataStream&, NT &nextT, Args&...)> fn,
        std::function<K(const NT &nextT, std::string &msgstatus)> fnNext, Args&... args)
    {
        Dbc* dbcp = nullptr;
        Dbt data, dp, key, kp;
        std::shared_ptr<DbMultipleKeyDataIterator> sptrkd;
        u_int32_t flags;
        int nCount = 0, ret = 0;

        int dlen = 8 * 1024 * 1024;
        char* data_buf = (char*)malloc(dlen);

        std::shared_ptr<char> sp(data_buf, [](auto databuf) {
            free(databuf);
        });

        data.set_flags(DB_DBT_USERMEM);
        data.set_data(data_buf);
        data.set_ulen(dlen);
        data.set_size(dlen);

        flags = DB_SET_RANGE | DB_MULTIPLE_KEY; // no duplicate key in db

        CommadLineProgress progress;
        progress.Start();
        try {
            CDataStream ssKey, ssValue;
            ssKey << keyload;

            if (!TxnBegin())
                ThrowException(-1, "DB_ENV->txn_begin");

            dbcp = GetCursor();
            if (!dbcp)
                ThrowException(-1, "DB->cursor");

            std::shared_ptr<Dbc> sp(dbcp, [this](Dbc* pCursor) {
                    if (pCursor != NULL) (void)pCursor->close();
                    TxnCommit();
                });

            bool isLoadCompleted = false;
            for (; !isLoadCompleted;) {

                key.set_data(&ssKey[0]);
                key.set_size(ssKey.size());
                memset(data_buf, 0, dlen);

                int nAdd = 0;
                //HCE: Notice, duplicate key data will be read which is last one for last time
                if ((ret = dbcp->get(&key, &data, flags)) != 0)
                    ThrowException(ret, "DBC->get");

                NT nextK;
                sptrkd = std::make_shared<DbMultipleKeyDataIterator>(data);
                while (sptrkd->next(kp, dp) == true) {
                    ssKey.SetType(SER_DISK);
                    ssKey.clear();
                    ssKey.write((char*)kp.get_data(), kp.get_size());
                    ssValue.SetType(SER_DISK);
                    ssValue.clear();
                    ssValue.write((char*)dp.get_data(), dp.get_size());

                    // Unserialize
                    string strType;
                    ssKey >> strType;
                    if (strType == keytype) {
                        try {
                            if (!fn(ssKey, ssValue, nextK, args...))
                                break;
                        }
                        catch (...) {
                            ThrowException(-1, strprintf("Failed to load: %s\n", ssKey.str()).c_str());
                        }
                        nAdd++;
                    }
                    else {
                        isLoadCompleted = true;
                        break;
                    }
                }
                nCount += nAdd;
                ssKey.clear();

                string sstatus;
                ssKey << fnNext(nextK, sstatus);
                progress.PrintStatus(nAdd, sstatus.c_str());
            }
            cout << strprintf(" Loaded(%s) : %d\n", keytype.c_str(), nCount);
        }
        catch (DbException& dbe) {
            if (dbe.get_errno() == DB_NOTFOUND) {
                cout << " bulkLoad : " << dbe.what() << endl;
                return true;
            }
            cerr << " bulkLoad error: " << dbe.what() << endl;
            return false;
        }
        return true;
    }

    bool Load(const std::string& key, const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f)
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        // Load mapBlockIndex
        unsigned int fFlags = DB_SET_RANGE;
        for (; !fShutdown;) {
            // Read next record
            CDataStream ssKey;
            if (fFlags == DB_SET_RANGE)
                ssKey << make_pair(key, hash);
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
            fFlags = DB_NEXT;
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            uint256 hash;
            ssKey >> strType;

            if (strType == key) {
                if (!f(ssKey, ssValue)) break;
            }
            else {
                break;
            }
        }
        pcursor->close();

        return true;
    }

    bool Load(const std::string& key, std::function<bool(CDataStream&, CDataStream&)> f)
    {
        return Load(key, uint256(0), f);
    }

    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(GetTxn(), &datKey, &datValue, 0);
        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data() == NULL)
            return false;

        // Unserialize value
        CDataStream ssValue((char*)datValue.get_data(), (char*)datValue.get_data() + datValue.get_size(), SER_DISK);
        ssValue >> value;

        // Clear and free memory
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Value
        CDataStream ssValue(SER_DISK);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], ssValue.size());

        // Write
        int ret = pdb->put(GetTxn(), &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Erase
        int ret = pdb->del(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }

    //HCE: can use txnid or not
    Dbc* GetCursor(DbTxn* txnid = NULL)
    {
        if (!pdb)
            return NULL;
        Dbc* pcursor = NULL;
        int ret = pdb->cursor(txnid, &pcursor, 0);
        if (ret != 0)
            return NULL;
        return pcursor;
    }

    int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT)
    {
        // Read at cursor
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datKey.set_data(&ssKey[0]);
            datKey.set_size(ssKey.size());
        }
        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datValue.set_data(&ssValue[0]);
            datValue.set_size(ssValue.size());
        }
        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datKey.get_data());
        free(datValue.get_data());
        return 0;
    }

    //HCE: cursor must close firstly if txn bind with a cursor
    void ThrowException(Dbc** pcursor, int ret, const char* msg)
    {
        if (*pcursor) {
            (*pcursor)->close();
            *pcursor = nullptr;
        }
        ThrowException(ret, msg);
    }

    void ThrowException(int ret, const char* msg)
    {
        DbTxn* txn = GetTxn();
        if (txn != NULL) {
            TxnAbort();
        }

        throw DbException(msg, ret);
    }

public:
    DbTxn* GetTxn()
    {
        if (!vTxn.empty())
            return vTxn.back();
        else
            return NULL;
    }

    //HCE: flags: for isolation level, for example, DB_READ_COMMITTED
    bool TxnBegin(u_int32_t flags = DB_TXN_NOSYNC)
    {
        if (!pdb)
            return false;
        DbTxn* ptxn = NULL;
        //HCE: If the first argument is non-NULL, the new transaction will be a nested transaction
        int ret = m_dbenv->txn_begin(GetTxn(), &ptxn, flags);
        if (!ptxn || ret != 0)
            return false;
        vTxn.push_back(ptxn);
        return true;
    }

    bool TxnCommit()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->commit(0);
        vTxn.pop_back();
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->abort();
        vTxn.pop_back();
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    string GetDBFile() { return strFile; }
};






class CTxDB_Wrapper;
class CTxDB : public CDB
{
public:
    friend class CTxDB_Wrapper;

    CTxDB(const char* pszMode = "r+", const char* pszFile= "blkindex.dat") : CDB(pszFile, pszMode) {
        bool fCreate = strchr(pszMode, 'c');
        if (fCreate && !Exists(string("txversion"))) {
            WriteTxVersion(TXIDX_VERSION);
        }
    }
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);

 public:
    bool ReadTxIndex(const uint256& hash, CTxIndex& txindex);
    bool UpdateTxIndex(const uint256& hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(const uint256& hash);
    bool ReadOwnerTxes(const uint160& hash160, int nHeight, std::vector<CTransaction>& vtx);
    bool ReadDiskTx(const uint256& hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(const uint256& hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx);

    bool ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(uint256 hash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    //HC
    bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork);
    bool WriteBestInvalidWork(CBigNum bnBestInvalidWork);
    bool LoadBlockIndex();
    bool CleanaBlockIndex();

    bool ReadSP(const uint256& hash, CDiskBlockIndex& diskindex);
    bool WriteSP(const CBlockIndex *blockindex);

    bool ReadTxVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("txversion"), nVersion);
    }

    bool WriteTxVersion(int nVersion)
    {
        return Write(std::string("txversion"), nVersion);
    }


    CBlockIndexSP ConstructBlockIndex(const uint256 &hash, CDiskBlockIndex& diskindex);

private:
    bool CheckBestBlockIndex();
};

extern thread_local boost::shared_ptr<CTxDB> tls_txdb_instance;

class CTxDB_Wrapper
{
public:
    CTxDB_Wrapper(const char* pszMode = "r+")
    {
        if (tls_txdb_instance.get()) {
            _dbptr = tls_txdb_instance;
        }
        else {
            tls_txdb_instance.reset(new CTxDB(pszMode));
            _dbptr = tls_txdb_instance;
        }
    }

    ~CTxDB_Wrapper()
    {}

    inline bool TxnBegin(u_int32_t flags = DB_TXN_NOSYNC) { return _dbptr->TxnBegin(flags); }
    inline bool TxnCommit() { return _dbptr->TxnCommit(); }
    inline bool TxnAbort() { return _dbptr->TxnAbort(); }
    inline bool ReadVersion(int& nVersion) { return _dbptr->ReadVersion(nVersion); }
    inline bool WriteVersion(int nVersion) { return _dbptr->WriteVersion(nVersion); }
    inline void Close() { _dbptr->Close(); }

    inline bool ReadTxIndex(const uint256& hash, CTxIndex& txindex) { return _dbptr->ReadTxIndex(hash, txindex); }
    inline bool UpdateTxIndex(const uint256& hash, const CTxIndex& txindex) { return _dbptr->UpdateTxIndex(hash, txindex); }
    inline bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight) { return _dbptr->AddTxIndex(tx, pos, nHeight); }
    inline bool EraseTxIndex(const CTransaction& tx) { return _dbptr->EraseTxIndex(tx); }
    inline bool EraseTxIndex(const uint256& hashtx) { return _dbptr->Erase(make_pair(string("tx"), hashtx)); }
    inline bool ContainsTx(const uint256& hash) { return _dbptr->ContainsTx(hash); }
    inline bool ReadOwnerTxes(uint160& hash160, int nHeight, std::vector<CTransaction>& vtx) { return _dbptr->ReadOwnerTxes(hash160, nHeight, vtx); }
    inline bool ReadDiskTx(uint256& hash, CTransaction& tx, CTxIndex& txindex) { return _dbptr->ReadDiskTx(hash, tx, txindex); }
    inline bool ReadDiskTx(uint256& hash, CTransaction& tx) { return _dbptr->ReadDiskTx(hash, tx); }
    inline bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex) {
        return  _dbptr->ReadDiskTx(outpoint, tx, txindex);
    }
    inline bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx) { return _dbptr->ReadDiskTx(outpoint, tx); }

    inline bool ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex) { return _dbptr->ReadBlockIndex(hash, blockindex); }
    inline bool WriteBlockIndex(const CDiskBlockIndex& blockindex) { return _dbptr->WriteBlockIndex(blockindex); }
    inline bool EraseBlockIndex(uint256& hash) { return _dbptr->EraseBlockIndex(hash); }
    inline bool ReadHashBestChain(uint256& hashBestChain) { return _dbptr->ReadHashBestChain(hashBestChain); }
    inline bool WriteHashBestChain(uint256& hashBestChain) { return _dbptr->WriteHashBestChain(hashBestChain); }
    //HC
    inline bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork) { return _dbptr->ReadBestInvalidWork(bnBestInvalidWork); }
    inline bool WriteBestInvalidWork(CBigNum bnBestInvalidWork) { return _dbptr->WriteBestInvalidWork(bnBestInvalidWork); }
    inline bool LoadBlockIndex() { return _dbptr->LoadBlockIndex(); }
    inline bool CleanaBlockIndex() { return _dbptr->CleanaBlockIndex(); }
    inline bool Load(const std::string& key, std::function<bool(CDataStream&, CDataStream&)> f) { return _dbptr->Load(key, f); }


    inline bool ReadSP(const uint256& hash, CDiskBlockIndex & diskindex) { return _dbptr->ReadSP(hash, diskindex); }
    inline bool WriteSP(const CBlockIndex *blockindex) { return _dbptr->WriteSP(blockindex); }

    boost::shared_ptr<CTxDB> GetPtr() { return _dbptr; }


    //HCE: v0.7.3.802 introduce
    bool ReadTxVersion(int& nVersion) { return _dbptr->ReadTxVersion(nVersion); }
    bool WriteTxVersion(int nVersion) { return _dbptr->WriteTxVersion(nVersion); }


private:
    class _internal
    {
    public:
        _internal() {}
        ~_internal()
        {
            //HCE: close the db, make DBFlush work to delete archive log,
            //HCE: and at the same time recursively open is supported
            //HCE: unique() more faster than (use_count() == 1)
            if (tls_txdb_instance.unique()) {
               tls_txdb_instance.reset();
            }
        }
    };
    //HCE: Don't change the order of the following two members
    _internal _i;
    boost::shared_ptr<CTxDB> _dbptr;
};


class CBlockDB : public CDB
{
public:
    CBlockDB(const char* pszMode = "r+", const char* filename = "block.dat") : CDB(filename, pszMode) { }
private:
    CBlockDB(const CBlockDB&);
    void operator=(const CBlockDB&);
public:
    bool LoadBlockUnChained(CBlockBloomFilter& filterBlk);
    bool LoadBlockUnChained(const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f);
    bool ReadBlock(const uint256& hash, CBlock& block);
    bool WriteBlock(const CBlock& block);
    bool WriteBlock(const uint256& hash, const CBlock& block);
    bool EraseBlock(uint256 hash);
};


extern thread_local boost::shared_ptr<CBlockDB> tls_blkdb_instance;

class CBlockDB_Wrapper
{
public:
    CBlockDB_Wrapper(const char* pszMode = "r+", const char* filename = "block.dat")
    {
        if (tls_blkdb_instance.get()) {
            _dbptr = tls_blkdb_instance;
        }
        else {
            tls_blkdb_instance.reset(new CBlockDB(pszMode, filename));
            _dbptr = tls_blkdb_instance;
        }
    }

    ~CBlockDB_Wrapper()
    {
    }

    inline bool TxnBegin() { return _dbptr->TxnBegin(); }
    inline bool TxnCommit() { return _dbptr->TxnCommit(); }
    inline bool TxnAbort() { return _dbptr->TxnAbort(); }
    inline bool ReadVersion(int& nVersion) { return _dbptr->ReadVersion(nVersion); }
    inline bool WriteVersion(int nVersion) { return _dbptr->WriteVersion(nVersion); }
    inline void Close() { _dbptr->Close(); }

    inline bool LoadBlockUnChained(CBlockBloomFilter& filterBlk) {
        return _dbptr->LoadBlockUnChained(filterBlk);
    }

    inline bool LoadBlockUnChained(const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f) {
        return _dbptr->LoadBlockUnChained(hash, f);
    }

    inline bool ReadBlock(const uint256& hash, CBlock& block) {
        return _dbptr->ReadBlock(hash, block);
    }

    inline bool WriteBlock(const CBlock& block) {
        return _dbptr->WriteBlock(block);
    }

    inline bool WriteBlock(const uint256& hash, const CBlock& block) {
        return _dbptr->WriteBlock(hash, block);
    }

    inline bool EraseBlock(uint256 hash) {
        return _dbptr->EraseBlock(hash);
    }

private:
    class _internal
    {
    public:
        _internal() {}
        ~_internal()
        {
            //HCE: close the db, make DBFlush work to delete archive log,
            //HCE: and at the same time recursively open is supported
            //HCE: unique() more faster than (use_count() == 1)
            if (tls_blkdb_instance.unique()) {
                tls_blkdb_instance.reset();
            }
        }
    };
    //HCE: Don't change the order of the following two members
    _internal _i;
    boost::shared_ptr<CBlockDB> _dbptr;
};

class COrphanBlockDB : public CBlockDB
{
public:
    COrphanBlockDB(const char* pszMode = "cr+") : CBlockDB(pszMode, "orphanblock.dat") { }
private:
    COrphanBlockDB(const COrphanBlockDB&);
    void operator=(const COrphanBlockDB&);
};


extern thread_local boost::shared_ptr<COrphanBlockDB> tls_orphanblkdb_instance;

class COrphanBlockDB_Wrapper
{
public:
    COrphanBlockDB_Wrapper(const char* pszMode = "cr+")
    {
        if (tls_orphanblkdb_instance.get()) {
            _dbptr = tls_orphanblkdb_instance;
        }
        else {
            tls_orphanblkdb_instance.reset(new COrphanBlockDB(pszMode));
            _dbptr = tls_orphanblkdb_instance;
        }
    }

    ~COrphanBlockDB_Wrapper()
    {
    }

    inline bool ReadBlock(const uint256& hash, CBlock& block) {
        return _dbptr->ReadBlock(hash, block);
    }

    inline bool WriteBlock(const CBlock& block) {
        return _dbptr->WriteBlock(block);
    }

    inline bool EraseBlock(uint256 hash)
    {
        return _dbptr->EraseBlock(hash);
    }


private:
    boost::shared_ptr<COrphanBlockDB> _dbptr;
};

class CBlockTripleAddressDB : public CDB
{
public:
    CBlockTripleAddressDB(const char* pszMode = "r+", const char* pszFile = "blocktripleaddress.dat") : CDB(pszFile, pszMode) {}

private:
    CBlockTripleAddressDB(const CBlockTripleAddressDB&);
    void operator=(const CBlockTripleAddressDB&);
public:
    bool LoadBlockTripleAddress();

    bool ReadMaxHID(uint32& maxhid);
    bool WriteMaxHID(uint32 hid);

    bool ReadBlockTripleAddress(const uint256& hash, BLOCKTRIPLEADDRESS& addr);
    bool WriteBlockTripleAddress(const uint256& hash, const BLOCKTRIPLEADDRESS& addr);
    bool EraseBlockTripleAddress(const uint256& hash);
};

class COrphanBlockTripleAddressDB : public CBlockTripleAddressDB
{
public:
    COrphanBlockTripleAddressDB(const char* pszMode = "r+") : CBlockTripleAddressDB(pszMode, "orphanblocktripleaddr.dat") {}

};


class CAddrDB : public CDB
{
public:
    CAddrDB(const char* pszMode="r+") : CDB("addr.dat", pszMode) { }
private:
    CAddrDB(const CAddrDB&);
    void operator=(const CAddrDB&);
public:
    bool WriteAddress(const CAddress& addr);
    bool EraseAddress(const CAddress& addr);
    bool LoadAddresses();
};

bool LoadAddresses();



class CKeyPool
{
public:
    int64 nTime;
    std::vector<unsigned char> vchPubKey;

    CKeyPool()
    {
        nTime = GetTime();
    }

    CKeyPool(const std::vector<unsigned char>& vchPubKeyIn)
    {
        nTime = GetTime();
        vchPubKey = vchPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    )
};




enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
};

class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string &strFilename, const char* pszMode="r+") : CDB(strFilename.c_str(), pszMode)
    {
    }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    bool ReadName(const std::string& strAddress, std::string& strName)
    {
        strName = "";
        return Read(std::make_pair(std::string("name"), strAddress), strName);
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);

    bool EraseName(const std::string& strAddress);

    bool ReadTx(uint256 hash, CWalletTx& wtx)
    {
        return Read(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("tx"), hash));
    }

    bool ReadKey(const std::vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey)
    {
        vchPrivKey.clear();
        return Read(std::make_pair(std::string("key"), vchPubKey), vchPrivKey);
    }

    bool WriteKey(const std::vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("key"), vchPubKey), vchPrivKey, false);
    }

    bool WriteCryptedKey(const std::vector<unsigned char>& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool fEraseUnencryptedKey = true)
    {
        nWalletDBUpdated++;
        if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
            return false;
        if (fEraseUnencryptedKey)
        {
            Erase(std::make_pair(std::string("key"), vchPubKey));
            Erase(std::make_pair(std::string("wkey"), vchPubKey));
        }
        return true;
    }

    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
    }

    bool WriteBestBlock(const CBlockLocator& locator)
    {
        nWalletDBUpdated++;
        return Write(std::string("bestblock"), locator);
    }

    bool ReadBestBlock(CBlockLocator& locator)
    {
        return Read(std::string("bestblock"), locator);
    }

    bool ReadDefaultKey(std::vector<unsigned char>& vchPubKey)
    {
        vchPubKey.clear();
        return Read(std::string("defaultkey"), vchPubKey);
    }

    bool WriteDefaultKey(const std::vector<unsigned char>& vchPubKey)
    {
        nWalletDBUpdated++;
        return Write(std::string("defaultkey"), vchPubKey);
    }

//////////////////////////////////////////////////////////////////////////
    //HCE: SegWit
    //HCE: value of utype: OutputType::LEGACY, OutputType::P2SH_SEGWIT, OutputType::BECH32
    //HCE: see outputtype.cpp
    bool ReadDefaultKeyType(OutputType &utype)
    {
        unsigned char t;
        if (Read(std::string("defaultkeytype"), t)) {
            utype = static_cast<OutputType>(t);
            return true;
        }
        return false;
    }

    bool WriteDefaultKeyType(OutputType utype)
    {
        nWalletDBUpdated++;
        return Write(std::string("defaultkeytype"), static_cast<unsigned char>(utype));
    }

    bool WriteCScript(const uint160& hash, const CScript& redeemScript)
    {
        return Write(std::make_pair(std::string("cscript"), hash), redeemScript);
    }

    bool ReadCScript(const uint160& hash, CScript& redeemScript)
    {
        return Read(std::make_pair(std::string("cscript"), hash), redeemScript);
    }

//////////////////////////////////////////////////////////////////////////

    bool ReadPool(int64 nPool, CKeyPool& keypool)
    {
        return Read(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool WritePool(int64 nPool, const CKeyPool& keypool)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool ErasePool(int64 nPool)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("pool"), nPool));
    }

    template<typename T>
    bool ReadSetting(const std::string& strKey, T& value)
    {
        return Read(std::make_pair(std::string("setting"), strKey), value);
    }

    template<typename T>
    bool WriteSetting(const std::string& strKey, const T& value)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("setting"), strKey), value);
    }

    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);
    bool WriteAccountingEntry(const CAccountingEntry& acentry);
    int64 GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    int LoadWallet(CWallet* pwallet);

private:
    int BulkLoadWallet(CWallet* pwallet, vector<uint256>& vWalletUpgrade, int& nFileVersion);
    int BulkLoadWalletUser(CWallet* pwallet);
    int BulkLoadWalletTx(CWallet* pwallet, vector<uint256>& vWalletUpgrade);
    int BulkLoadWalletAcentry(CWallet* pwallet);
    int BulkLoadWalletCScript(CWallet* pwallet); //HCE: SegWit
    int BulkLoadWalletKey(CWallet* pwallet);
    int BulkLoadWalletWKey(CWallet* pwallet);
    int BulkLoadWalletMKey(CWallet* pwallet);
    int BulkLoadWalletCKey(CWallet* pwallet);
    int BulkLoadWalletPool(CWallet* pwallet);
    int BulkLoadWalletSettings(CWallet* pwallet);
};


extern thread_local boost::shared_ptr<CWalletDB> tls_walletdb_instance;

class CWalletDB_Wrapper
{
public:
    CWalletDB_Wrapper(const std::string &strFilename, const char* pszMode = "r+")
    {
        if (tls_walletdb_instance.get()) {
            _dbptr = tls_walletdb_instance;
        }
        else {
            tls_walletdb_instance.reset(new CWalletDB(strFilename, pszMode));
            _dbptr = tls_walletdb_instance;
        }
    }

    ~CWalletDB_Wrapper()
    {}

public:

    inline bool TxnBegin() { return _dbptr->TxnBegin(); }
    inline bool TxnCommit() { return _dbptr->TxnCommit(); }
    inline bool TxnAbort() { return _dbptr->TxnAbort(); }
    inline bool ReadVersion(int& nVersion) { return _dbptr->ReadVersion(nVersion); }
    inline bool WriteVersion(int nVersion) { return _dbptr->WriteVersion(nVersion); }
    inline void Close() { _dbptr->Close(); }

    inline bool ReadName(const std::string& strAddress, std::string& strName) {
        return tls_walletdb_instance->ReadName(strAddress, strName);
    }

    inline bool WriteName(const std::string& strAddress, const std::string& strName) {
        return tls_walletdb_instance->WriteName(strAddress, strName);
    }

    inline bool EraseName(const std::string& strAddress) {
        return tls_walletdb_instance->EraseName(strAddress);
    }

    inline bool ReadTx(uint256 hash, CWalletTx& wtx) {
        return tls_walletdb_instance->ReadTx(hash, wtx);
    }

    inline bool WriteTx(uint256 hash, const CWalletTx& wtx) {
        return tls_walletdb_instance->WriteTx(hash, wtx);
    }

    inline bool EraseTx(uint256 hash) {
        return tls_walletdb_instance->EraseTx(hash);
    }

    inline bool ReadKey(const std::vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey) {
        return tls_walletdb_instance->ReadKey(vchPubKey, vchPrivKey);
    }

    inline bool WriteKey(const std::vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey) {
        return tls_walletdb_instance->WriteKey(vchPubKey, vchPrivKey);
    }

    inline bool WriteCryptedKey(const std::vector<unsigned char>& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool fEraseUnencryptedKey = true) {
        return tls_walletdb_instance->WriteCryptedKey(vchPubKey, vchCryptedSecret, fEraseUnencryptedKey);
    }

    inline bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey) {
        return tls_walletdb_instance->WriteMasterKey(nID, kMasterKey);
    }

    inline bool WriteBestBlock(const CBlockLocator& locator) {
        return tls_walletdb_instance->WriteBestBlock(locator);
    }

    inline bool ReadBestBlock(CBlockLocator& locator) {
        return tls_walletdb_instance->ReadBestBlock(locator);
    }

    inline bool ReadDefaultKey(std::vector<unsigned char>& vchPubKey) {
        return tls_walletdb_instance->ReadDefaultKey(vchPubKey);
    }

    inline bool WriteDefaultKey(const std::vector<unsigned char>& vchPubKey) {
        return tls_walletdb_instance->WriteDefaultKey(vchPubKey);
    }

    //////////////////////////////////////////////////////////////////////////
    //HCE: SegWit
    inline bool ReadDefaultKeyType(OutputType &utype)
    {
        return tls_walletdb_instance->ReadDefaultKeyType(utype);
    }

    inline bool WriteDefaultKeyType(OutputType utype)
    {
        return tls_walletdb_instance->WriteDefaultKeyType(utype);
    }

    inline bool WriteCScript(const uint160& hash, const CScript& redeemScript)
    {
        return tls_walletdb_instance->WriteCScript(hash, redeemScript);
    }

    inline bool ReadCScript(const uint160& hash, CScript& redeemScript)
    {
        return tls_walletdb_instance->ReadCScript(hash, redeemScript);
    }

    //////////////////////////////////////////////////////////////////////////

    inline bool ReadPool(int64 nPool, CKeyPool& keypool) {
        return tls_walletdb_instance->ReadPool(nPool, keypool);
    }

    inline bool WritePool(int64 nPool, const CKeyPool& keypool) {
        return tls_walletdb_instance->WritePool(nPool, keypool);
    }

    inline bool ErasePool(int64 nPool) {
        return tls_walletdb_instance->ErasePool(nPool);
    }

    template<typename T>
    inline bool ReadSetting(const std::string& strKey, T& value)
    {
        return tls_walletdb_instance->ReadSetting(strKey, value);
    }

    template<typename T>
    inline bool WriteSetting(const std::string& strKey, const T& value)
    {
        return tls_walletdb_instance->WriteSetting(strKey, value);
    }

    inline bool ReadAccount(const std::string& strAccount, CAccount& account) {
        return tls_walletdb_instance->ReadAccount(strAccount, account);
    }

    inline bool WriteAccount(const std::string& strAccount, const CAccount& account) {
        return tls_walletdb_instance->WriteAccount(strAccount, account);
    }

    inline bool WriteAccountingEntry(const CAccountingEntry& acentry) {
        return tls_walletdb_instance->WriteAccountingEntry(acentry);
    }

    inline int64 GetAccountCreditDebit(const std::string& strAccount) {
        return tls_walletdb_instance->GetAccountCreditDebit(strAccount);
    }

    inline void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries) {
        tls_walletdb_instance->ListAccountCreditDebit(strAccount, acentries);
    }

    inline int LoadWallet(CWallet* pwallet) {
        return tls_walletdb_instance->LoadWallet(pwallet);
    }

private:
    class _internal
    {
    public:
        _internal() {}
        ~_internal()
        {
            //HCE: close the db, make RPC interface(backupwallet) work,
            //HCE: and at the same time recursively open is supported
            //HCE: unique() more faster than (use_count() == 1)
            if (tls_walletdb_instance.unique()) {
                tls_walletdb_instance.reset();
            }
        }
    };
    //HCE: Don't change the order of the following two members
    _internal _i;
    boost::shared_ptr<CWalletDB> _dbptr;

};



class CMainTrunkDB : public CDB
{
public:
    CMainTrunkDB(const char* pszMode = "r+", const char* pszFile = "maintrunk.dat") : CDB(pszFile, pszMode) {}

private:
    CMainTrunkDB(const CMainTrunkDB&);

public:
    bool LoadData();

    bool ReadData(int nHeight, uint256& hash);
    bool WriteData(int nHeight, const uint256& hash);
    bool WriteMaxHeight(int nMaxHeight);
    bool EraseData(int nHeight);
};


#endif
