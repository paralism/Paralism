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
#include "globalconfig.h"
#include "headers.h"
#include "db/dbmgr.h"
#include "../dllmain.h"
#include "../../node/defer.h"

//HCE: two ways for display the progress: percent and already handled
class CommadLineProgressX
{
public:
    void Update(double newProgress)
    {
        currentProgress += newProgress;
        amountOfFiller = (int)((currentProgress / neededProgress) * (double)pBarLength);
    }

    void PrintPercent()
    {
        currUpdateVal %= pBarUpdater.length();
        cout << "\r" //Bring cursor to start of line
            << firstPartOfpBar;
        for (int a = 0; a < amountOfFiller; a++) { //Print out current progress
            cout << pBarFiller;
        }
        cout << pBarUpdater[currUpdateVal];
        for (int b = 0; b < pBarLength - amountOfFiller; b++) { //Print out spaces
            cout << " ";
        }
        cout << lastPartOfpBar //Print out last part of progress bar
            << " (" << (int)(100 * (currentProgress / neededProgress)) << "%)" //This just prints out the percent
            << flush;
        currUpdateVal += 1;
    }

    void Start()
    {
        _spentt.Reset();
        _ncount = 0;
        PrintStatus(0, "starting...");
    }

    //
    void PrintStatus(int nAddCount, const string& msg = "")
    {
        //[ 145668   176(s)   18776(n/s) ] (msg)
        cout << "\r"             //Bring cursor to start of line
            << firstPartOfpBar;
        _ncount += nAddCount;

        int ms = _spentt.Elapse();
        if (ms == 0) {
            ms = 1; //1ms
        }
        cout << strprintf(" %d   %d(s)   %d(n/s)", _ncount, ms / 1000, _ncount * 1000 / ms);

        cout << strprintf(" %s   ( %s )", lastPartOfpBar.c_str(), msg.c_str())
            << flush;
    }


    std::string firstPartOfpBar = "[", //Change these at will (that is why I made them public)
        lastPartOfpBar = "]",
        pBarFiller = "|",
        pBarUpdater = "/-\\|";
private:
    int amountOfFiller,
        pBarLength = 50,        //I would recommend NOT changing this
        currUpdateVal = 0;      //Do not change
    double currentProgress = 0, //Do not change
        neededProgress = 100;   //I would recommend NOT changing this

    CSpentTime _spentt;
    int _ncount;
};

//HCE: the following class is a implement of old version for CDiskBlockIndex
class CDiskBlockIndex2020 : public CBlockIndex
{
public:

    explicit CDiskBlockIndex2020()
    {
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nHeight);

        uint32_t* hid = (uint32_t*)(&triaddr.hid);
        READWRITE(*hid);

        READWRITE(triaddr.chainnum);
        READWRITE(triaddr.id);
        string ns;
        READWRITE(ns);

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

    //bool operator<(const CDiskBlockIndex2020& right) const
    //{
    //    if (nHeight == right.nHeight) {
    //        return GetBlockHash() > right.GetBlockHash();
    //    }
    //    return nHeight > right.nHeight;
    //}

};

//HC: v0.7.2 2021-7-14 前版本
//HCE: v0.7.2 version before 2021-7-14
class BLOCKTRIPLEADDRESSV72
{
public:
    uint32 hid = 0;            //HCE: hyper block id
    uint16 chainnum = 0;
    uint16 id = 0;

public:
    BLOCKTRIPLEADDRESSV72() {}

    BLOCKTRIPLEADDRESSV72(const T_LOCALBLOCKADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(hid);
        READWRITE(chainnum);
        READWRITE(id);
    )
};



std::multimap<int, CDiskBlockIndex2020> mapMigrBlockIndex;

class CMgrTxDB_Tool : public CTxDB
{
public:
    using CTxDB::CTxDB;

    bool ReadBlockIndex(const uint256& hash, CDiskBlockIndex2020& blockindex)
    {
        return Read(make_pair(string("blockindex"), hash), blockindex);
    }

    bool BulkLoadBlockIndex()
    {
        Dbc* dbcp = nullptr;
        Dbt data, dp, key, kp;
        DbMultipleKeyDataIterator* ptrkd;
        u_int32_t flags;
        int nCount = 0, i, j, ret = 0;

        int dlen = 16 * 1024 * 1024;
        char* data_buf = (char*)malloc(dlen);
        defer{
            free(data_buf);
        };

        data.set_flags(DB_DBT_USERMEM);
        data.set_data(data_buf);
        data.set_ulen(dlen);
        data.set_size(dlen);

        flags = DB_SET_RANGE | DB_MULTIPLE_KEY; // no duplicate key in db

        CommadLineProgress progress;
        progress.Start();
        try {
            CDataStream ssKey, ssValue;
            ssKey << make_pair(string("blockindex"), uint256(0));

            if (!TxnBegin())
                ThrowException(-1, "DB_ENV->txn_begin");

            dbcp = GetCursor();
            if (!dbcp)
                ThrowException(-1, "DB->cursor");

            bool isLoadCompleted = false;
            for (; !isLoadCompleted;) {

                key.set_data(&ssKey[0]);
                key.set_size(ssKey.size());
                memset(data_buf, 0, dlen);

                int nAdd = 0;
                //HCE: Notice, duplicate block index will be read which is last one for last time
                if ((ret = dbcp->get(&key, &data, flags)) != 0)
                    ThrowException(ret, "DBC->get");

                CBlockIndex blkindex;
                CDiskBlockIndex diskindex(&blkindex);
                ptrkd = new DbMultipleKeyDataIterator(data);
                while (ptrkd->next(kp, dp) == true) {
                    ssKey.SetType(SER_DISK);
                    ssKey.clear();
                    ssKey.write((char*)kp.get_data(), kp.get_size());
                    ssValue.SetType(SER_DISK);
                    ssValue.clear();
                    ssValue.write((char*)dp.get_data(), dp.get_size());

                    // Unserialize
                    string strType;
                    ssKey >> strType;
                    if (strType == "blockindex") {
                        try {
                            ssValue >> diskindex;
                        }
                        catch (...) {
                            uint256 h;
                            ssKey >> h;
                            cerr << "Failed to check block index, hash:" << h.ToString() << endl;
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
                uint256 currhash = diskindex.GetBlockHash();
                ssKey << make_pair(string("blockindex"), currhash);
                progress.PrintStatus(nAdd, strprintf("blockindex : %s", currhash.ToPreViewString().c_str()));
            }
            cout << "\n Check(blockindex) : " << nCount << endl;

            ret = dbcp->close();
            dbcp = NULL;
            if (ret != 0)
                ThrowException(ret, "DBC->close");
            TxnCommit();
        }
        catch (DbException& dbe) {
            cerr << "bulkRead " << dbe.what() << endl;
            if (dbcp != NULL)
                (void)dbcp->close();
        }
        return true;
    }

    bool LoadBlockIndex()
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        const int nConstStep = 1000;
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

                nCount++;
                nStep--;
                if (nStep == 0) {
                    cout << ".";
                    nStep = nConstStep;
                }
                mapMigrBlockIndex.insert(decltype(mapMigrBlockIndex)::value_type(diskindex.nHeight, diskindex));
            }
            else {
                break;
            }
        }
        pcursor->close();
        cout << "\n Sum(blockindex) : " << nCount << endl;
        return true;
    }


    bool LoadBlockIndex_nohhash(map<uint256, CBlockIndexV72>& mapBlkIndex)
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        const int nConstStep = 1000;
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
                //HCE: 50000 is a key, which it is not read hhash
                uint256 blkhash;
                ssKey >> blkhash;

                CBlockIndexV72 blkindex;
                CDiskBlockIndexV72 diskindex(&blkindex);
                ssValue >> diskindex;

                nCount++;
                nStep--;
                if (nStep == 0) {
                    cout << ".";
                    nStep = nConstStep;
                }
                mapBlkIndex.insert({ blkhash, *diskindex.GetBlockIndex() });
            }
            else {
                break;
            }
        }
        pcursor->close();
        cout << "\n Sum(blockindex) : " << nCount << endl;
        return true;
    }


    //HCE: after format conversion, check every block index if data format is right
    bool CheckBlockIndex()
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        const int nConstStep = 5000;
        int nCount = 0;
        int nStep = nConstStep;

        // Load mapBlockIndex
        CommadLineProgress progress;
        progress.Start();

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
                CBlockIndex blkindex;
                CDiskBlockIndex diskindex(&blkindex);

                try {
                    ssValue >> diskindex;
                }
                catch (...) {
                    uint256 h;
                    ssKey >> h;
                    cerr << "Failed to check block index, hash:" << h.ToString() << endl;
                }

                nCount++;
                nStep--;
                if (nStep == 0) {
                    nStep = nConstStep;

                    uint256 currhash = diskindex.GetBlockHash();
                    progress.PrintStatus(nConstStep, strprintf("blockindex : %s", currhash.ToPreViewString().c_str()));
                }
            }
            else {
                break;
            }
        }
        pcursor->close();
        cout << "\n Check(blockindex) : " << nCount << endl;
        return true;
    }

    //HCE: c++ style version
    bool bulkUpdate_cpp()
    {
        Dbt key, data;
        u_int32_t flag;
        int i, ret;
        DbMultipleDataBuilder* ptrd, * ptrk;

        flag = ret = 0;

        char* key_buf, * data_buf;

        //HCE: why size need to + 8 and +4, see DB_MULTIPLE_WRITE_NEXT
        const int suffix = 8;
        int KEY_T_SIZE = 0;
        for (auto& ssKey : m_keybuf) {
            KEY_T_SIZE += ssKey.size() + suffix;
        }
        KEY_T_SIZE += 4;

        key_buf = (char*)malloc(KEY_T_SIZE);
        memset(key_buf, 0, KEY_T_SIZE);

        key.set_ulen(KEY_T_SIZE);
        key.set_flags(DB_DBT_USERMEM | DB_DBT_BULK);
        key.set_data(key_buf);

        int DATA_T_SIZE = 0;
        for (auto& ssValue : m_databuf) {
            DATA_T_SIZE += ssValue.size() + suffix;
        }
        DATA_T_SIZE += 4;

        data_buf = (char*)malloc(DATA_T_SIZE);
        memset(data_buf, 0, DATA_T_SIZE);

        data.set_ulen(DATA_T_SIZE);
        data.set_flags(DB_DBT_USERMEM | DB_DBT_BULK);
        data.set_data(data_buf);

        /*
         * Bulk insert with either DB_MULTIPLE in two buffers or
         * DB_MULTIPLE_KEY in a single buffer. With DB_MULTIPLE, all keys are
         * constructed in the key Dbt, and all data is constructed in the data
         * Dbt. With DB_MULTIPLE_KEY, all key/data pairs are constructed in the
         * key Dbt. We use DB_MULTIPLE mode when there are duplicate records.
         */
         //HCE: Here use DB_MULTIPLE mode to handle any case
        flag = DB_MULTIPLE;
        ptrk = new DbMultipleDataBuilder(key);
        ptrd = new DbMultipleDataBuilder(data);

        defer{
            delete ptrk;
            delete ptrd;
        };

        try {
            if (!TxnBegin()) {
                ThrowException(EXIT_FAILURE, "[insert] DB_ENV->txn_begin");
            }

            for (i = 0; i < m_keybuf.size(); i++) {
                auto& keyelm = m_keybuf[i];
                void* pdata = &keyelm[0];
                if (ptrk->append(&keyelm[0], keyelm.size()) == false)
                    ThrowException(EXIT_FAILURE, "DbMultipleDataBuilder->append");

                auto& dataelm = m_databuf[i];
                if (ptrd->append(&dataelm[0], dataelm.size()) == false)
                    ThrowException(EXIT_FAILURE, "DbMultipleDataBuilder->append");
            }

            if ((ret = pdb->put(GetTxn(), &key, &data, flag)) != 0)
                ThrowException(ret, "Bulk DB->put");

            if (!TxnCommit())
                ThrowException(ret, "DB_TXN->commit");
        }
        catch (DbException& dbe) {
            cerr << "bulkUpdate " << dbe.what() << endl;
            return false;
        }
        return true;
    }

    //HCE: c style version
    bool bulkUpdate_c()
    {
        if (!pdb)
            return false;

        DBT key, data;
        int i, ret, op_flag;

        char* key_buf, * data_buf;

        /* Initialize structs and arrays */
        memset(&key, 0, sizeof(DBT));
        memset(&data, 0, sizeof(DBT));

        //HCE: why size need to + 8 and +4, see DB_MULTIPLE_WRITE_NEXT
        const int suffix = 8;
        int KEY_SIZE = m_keybuf[0].size();
        int KEY_T_SIZE = (KEY_SIZE + suffix) * m_keybuf.size() + 4;
        key_buf = (char*)malloc(KEY_T_SIZE);

        int DATA_T_SIZE = 0;
        for (auto& ssValue : m_databuf) {
            DATA_T_SIZE += ssValue.size() + suffix;
        }
        DATA_T_SIZE += 4;

        data_buf = (char*)malloc(DATA_T_SIZE);
        memset(data_buf, 0, DATA_T_SIZE);

        /*
        * 初始化Bulk buffer.使用批量操作(bulk operations) 也就是 * 批量插入/删除/更新/读取的时候，必须使用用户提供的内存。
        * 所以需要设置DBT对象的flags为DB_DBT_USERMEM，并且设置ulen成员而不是size成员。
        */
        key.data = key_buf;
        key.ulen = KEY_T_SIZE;
        key.flags = DB_DBT_USERMEM;
        data.data = data_buf;
        data.ulen = DATA_T_SIZE;
        data.flags = DB_DBT_USERMEM;

        op_flag = DB_MULTIPLE; /* 这个flag给put/get/del 表示执行批量插入/更新/读取/删除。 */

        /*
        * 填充bulk buffer DBT 对象. 先调用DB_MULTIPLE_WRITE_INIT初始化该 * DBT。必须传入一个工作指针p和data buffer DBT 对象。
        * p: 是这个宏内部使用的工作变量，由DB_MULTIPLE_WRITE_INIT初始化，并且必须在此处一直使用。
        */
        void* p;
        DB_MULTIPLE_WRITE_INIT(p, &data);
        for (i = 0; i < m_databuf.size(); i++) {
            /*
            * 各参数说明： data: 是data buffer DBT对象。
            * 循环结束后填充完成，这个data buffer当中有bulk_size个data，
            */
            auto& dataelm = m_databuf[i];
            DB_MULTIPLE_WRITE_NEXT(p, &data, &dataelm[0], dataelm.size());
        }

        DB_MULTIPLE_WRITE_INIT(p, &key);
        for (i = 0; i < m_keybuf.size(); i++) {
            auto& keyelm = m_keybuf[i];
            DB_MULTIPLE_WRITE_NEXT(p, &key, &keyelm[0], KEY_SIZE);
        }

        bool result = false;
        DB* dbp = pdb->get_DB();

        //批量插入key/data pairs.
        /* 启动事务准备批量插入。 */
        if (!TxnBegin()) {
            m_dbenv->err(-1, "[insert] DB_ENV->txn_begin");
            goto inserterr;
        }

        switch (ret = dbp->put(dbp, GetTxn()->get_DB_TXN(), &key, &data, op_flag)) {
        case 0: /* 批量插入操作成功，提交事务。*/
            if (!TxnCommit()) {
                m_dbenv->err(ret, "[insert] DB_TXN->commit");
            }
            result = true;
            break;
        case DB_LOCK_DEADLOCK:
            /* 如果数据库操作发生死锁，那么必须abort事务。然后，可以选择重新执行该操作。*/
            if (!TxnAbort()) {
                m_dbenv->err(ret, "[insert] DB_TXN->abort");
            }
        default:
            m_dbenv->err(ret, "[insert] DB->put()");
        }

    inserterr:
        (void)free(key_buf);
        (void)free(data_buf);

        return result;
    }


    bool BulkWriteBlockIndex(const uint256& blockhash, const CDiskBlockIndex& blockindex)
    {
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << make_pair(string("blockindex"), blockhash);

        m_keybuf.push_back(ssKey);

        CDataStream ssValue(SER_DISK);
        ssValue.reserve(4000);
        ssValue << blockindex;

        m_databuf.emplace_back(ssValue);

        if (m_keybuf.size() == 100) {

            for (size_t i = 0; i < 3; i++) {
                if (bulkUpdate_cpp()) {
                    m_keybuf.clear();
                    m_databuf.clear();
                    break;
                }
            }
        }
        return true;
    }


    bool BulkWriteBlockIndex(const CDiskBlockIndex& blockindex)
    {
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << make_pair(string("blockindex"), blockindex.GetBlockHash());

        m_keybuf.push_back(ssKey);

        CDataStream ssValue(SER_DISK);
        ssValue.reserve(4000);
        ssValue << blockindex;

        m_databuf.emplace_back(ssValue);

        if (m_keybuf.size() == 100) {

            for (size_t i = 0; i < 3; i++) {
                if (bulkUpdate_cpp()) {
                    m_keybuf.clear();
                    m_databuf.clear();
                    break;
                }
            }
        }
        return true;
    }

    bool BulkCommit()
    {
        for (size_t i = 0; i < 3; i++) {
            if (bulkUpdate_cpp()) {
                m_keybuf.clear();
                m_databuf.clear();
                return true;
            }
        }
        return false;
    }

private:
    using KEY_TYPE = std::pair<string, uint256>;
    using VALUE_TYPE = CDiskBlockIndex;

    vector<CDataStream> m_keybuf;
    vector<CDataStream> m_databuf;
};

class CBlockTripleAddressDBV72 : public CBlockTripleAddressDB
{
public:
    using CBlockTripleAddressDB::CBlockTripleAddressDB;

public:
    bool LoadBlockTripleAddress(map<uint256, BLOCKTRIPLEADDRESSV72>& mapTriAddr)
    {
        return Load("triaddr", [&](CDataStream& ssKey, CDataStream& ssValue) -> bool {

            BLOCKTRIPLEADDRESSV72 blocktripleaddr;
            ssValue >> blocktripleaddr;
            uint256 hash;
            ssKey >> hash;
            mapTriAddr.insert({ hash, blocktripleaddr });
            return true;
            });
    }
};

class COrphanBlockTripleAddressDBV72 : public COrphanBlockTripleAddressDB
{
public:
    using COrphanBlockTripleAddressDB::COrphanBlockTripleAddressDB;

public:
    bool LoadBlockTripleAddress(map<uint256, BLOCKTRIPLEADDRESSV72>& mapTriAddr)
    {
        return Load("triaddr", [&](CDataStream& ssKey, CDataStream& ssValue) -> bool {

            BLOCKTRIPLEADDRESSV72 blocktripleaddr;
            ssValue >> blocktripleaddr;
            uint256 hash;
            ssKey >> hash;
            mapTriAddr.insert({ hash, blocktripleaddr });
            return true;
            });
    }
};


void testbulkwrite(const char* filename)
{
    CMgrTxDB_Tool txdb("cr+", filename);
    CBlockIndexV72 idx;
    idx.addr.hid = 2111;
    idx.addr.id = 100;
    idx.addr.chainnum = 89;
    idx.addr.ns = "Hello";
    idx.bnChainWork = 89999;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba6");
    idx.nHeight = 10000;
    idx.nSolution = { 'a','a','n' };

    //txdb.WriteBlockIndex(CDiskBlockIndex(&idx));
    //txdb.BulkWriteBlockIndex(CDiskBlockIndexV72(&idx));

    idx.addr.hid = 1999;
    idx.addr.id = 101;
    idx.addr.chainnum = 8;
    idx.addr.ns = "world...";
    idx.bnChainWork = 89999;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba7");
    idx.nHeight = 1001;
    idx.nSolution = { 'a' };

    //txdb.BulkWriteBlockIndex(CDiskBlockIndexV72(&idx));

    idx.addr.hid = 1999;
    idx.addr.id = 102;
    idx.addr.chainnum = 8900;
    idx.addr.ns = "Hellollllllllllllllllllllllllllllllll";
    idx.bnChainWork = 12000;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba8");
    idx.nHeight = 1003;
    idx.nSolution = { 'a','x','n','y','z','a','x','n','y','z' ,'a','x','n','y','z' };

    //txdb.BulkWriteBlockIndex(CDiskBlockIndexV72(&idx));

    txdb.BulkCommit();
    txdb.Close();
    DBFlush(false);
}

void check()
{
    CTxDB txdb("cr+");

    //uint256 hh = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba5");

    //CBlockIndex blkidx1;
    //CDiskBlockIndex diskindex1(&blkidx1);
    //txdb.ReadBlockIndex(hh, diskindex1);
    //blkidx1.bnChainWork = blkidx1.GetBlockWork();
    //txdb.WriteBlockIndex(diskindex1);

    ///*  CDiskBlockIndex2020 diskindex;
    //  txdb.ReadBlockIndex(hh, diskindex);

    //  if (!txdb.ReadHashBestChain(hashBestChain)) {
    //      cerr << "error ReadHashBestChain";
    //      return;
    //  }

    //  CBlockIndex *blkidx = &diskindex;
    //  CDiskBlockIndex idx(blkidx);
    //  blkidx->bnChainWork = blkidx->GetBlockWork();

    //  txdb.WriteBlockIndex(idx);*/
    //return;

    cout << "LoadBlockIndex...\n";
    txdb.LoadBlockIndex();
}

void convertFormat()
{
    CMgrTxDB_Tool txdb("cr+");

    if (!txdb.ReadHashBestChain(hashBestChain)) {
        cerr << "error ReadHashBestChain";
        return;
    }
    cout << "LoadBlockIndex...\n";
    txdb.LoadBlockIndex();

    auto beginitem = mapMigrBlockIndex.begin();
    if (beginitem->second.nHeight != 0) {
        cerr << "error occur,why does not have 0 block?";
        return;
    }

    beginitem->second.bnChainWork = beginitem->second.GetBlockWork();
    uint256 h = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba5");
    if (h != beginitem->second.GetBlockHash()) {
        cerr << "genesis block error";
        return;
    }

    beginitem->second.hashBlock = h;

    cout << "Start to update chain work for every block index ";
    cout << "and bulk save result to blkindex.dat...\n";

    //HCE: We have to save into origin file for a lot of transactions saved in the blkindex.dat.
    //CMgrTxDB_Tool txdbResult("cr+","blkindex-result.dat");

    const int nConstStep = 1000;
    int nCount = 0;
    int nStep = nConstStep;

    bool IsBestIdxerr = false;
    int nBestHeight = 0;

    auto previtem = beginitem;

    //genesis block
    txdb.BulkWriteBlockIndex(CDiskBlockIndex(&(beginitem->second)));

    beginitem++;
    for (; beginitem != mapMigrBlockIndex.end(); ++beginitem) {

        beginitem->second.hashBlock = beginitem->second.GetBlockHash();
        int nH = beginitem->second.nHeight;
        auto pp = beginitem;
        --pp;
        while (pp != mapMigrBlockIndex.end()) {
            if (pp->second.nHeight < nH - 1 || pp->second.nHeight > nH) {
                //error
                cerr << strprintf("cannot find the previous block index for %d, erase...\n", beginitem->second.nHeight);
                if (hashBestChain == beginitem->second.hashBlock) {
                    cerr << "critical: best index error\n";
                    IsBestIdxerr = true;
                    nBestHeight = nH;
                }
                txdb.EraseBlockIndex(beginitem->second.hashBlock);
                break;
            }
            if (pp->second.hashBlock == beginitem->second.hashPrev) {
                //OK
                beginitem->second.bnChainWork = pp->second.bnChainWork + beginitem->second.GetBlockWork();
                CBlockIndex* p = &(beginitem->second);
                txdb.BulkWriteBlockIndex(CDiskBlockIndex(p));
                break;
            }
            --pp;
        }

        nCount++;
        nStep--;
        if (nStep == 0) {
            cout << "*";
            nStep = nConstStep;
        }
    }

    txdb.BulkCommit();

    if (IsBestIdxerr) {
        //HCE: reset a best index
        cout << "Current best index hash: " << hashBestChain.ToString()
            << " Height: " << nBestHeight << endl;

        bool isOK = false;
        do {
            nBestHeight--;
            if (mapMigrBlockIndex.count(nBestHeight) > 0) {
                auto range = mapMigrBlockIndex.equal_range(nBestHeight);
                for (auto i = range.first; i != range.second; ++i) {
                    if (i->second.bnChainWork > i->second.GetBlockWork()) {
                        txdb.WriteHashBestChain(i->second.hashBlock);
                        isOK = true;
                        cout << "\nNew best index hash: " << i->second.hashBlock.ToString()
                            << " Height: " << nBestHeight << endl;
                        break;
                    }
                }
            }
        } while (nBestHeight > 0 && !isOK);

        if (!isOK) {
            cerr << "warning: cannot reset a best index!!!\n";
        }
    }

    DBFlush(false);
    cout << "\nFile Format conversion is finished" << endl;
}

void convertBlockIndexFormat()
{
    CMgrTxDB_Tool txdb("cr+");

    if (!txdb.ReadHashBestChain(hashBestChain)) {
        cerr << "error ReadHashBestChain";
        return;
    }
    cout << "LoadBlockIndex...\n";

    map<uint256, CBlockIndexV72> mapBlkIndex;
    txdb.LoadBlockIndex_nohhash(mapBlkIndex);

    uint256 h = uint256S("a33a70884e516eee7fb41d8ffa38d5ddee3cd2ac121cd46a853cd29bb13c4e53");
    if (!mapBlkIndex.count(h)) {
        cerr << "genesis block hash error, should be " << h.ToString();
        return;
    }

    cout << "Start to update Para block indexes ";
    cout << "and bulk save result to blkindex.dat...\n";

    //HCE: We have to save into origin file for a lot of transactions saved in the blkindex.dat.
    const int nConstStep = 1000;
    int nCount = 0;
    int nStep = nConstStep;

    bool IsBestIdxerr = false;
    int nBestHeight = 0;

    auto beginitem = mapBlkIndex.begin();
    for (; beginitem != mapBlkIndex.end(); ++beginitem) {
        CBlockIndex blkidx = To_CBlockIndex(beginitem->second);
        txdb.BulkWriteBlockIndex(beginitem->first, CDiskBlockIndex(&blkidx));
        nCount++;
        nStep--;
        if (nStep == 0) {
            cout << "*";
            nStep = nConstStep;
        }
    }

    CBlockIndexV72 genesisidxv72 = mapBlkIndex[h];
    CBlockIndex genesisidx = To_CBlockIndex(genesisidxv72);
    genesisidx.triaddr.hhash = uint256S("88845ff7acb1f21b6be55815d72b87cb850dccf999c279a0266d14e79a1f597c");

    txdb.BulkWriteBlockIndex(h, CDiskBlockIndex(&genesisidx));

    txdb.BulkCommit();

    DBFlush(false);
    cout << "\nFile Format conversion is finished" << endl;
}

BLOCKTRIPLEADDRESS To_BlockTriAddr(const BLOCKTRIPLEADDRESSV72 triaddr)
{
    BLOCKTRIPLEADDRESS newAddr;
    newAddr.hid = triaddr.hid;
    newAddr.chainnum = triaddr.chainnum;
    newAddr.id = triaddr.id;
    return newAddr;
}

template<typename T>
void convertBlockTriAddrFormat(T& tridb)
{
    cout << "Load triple address...\n";

    map<uint256, BLOCKTRIPLEADDRESSV72> mapBlkAddr;
    tridb.LoadBlockTripleAddress(mapBlkAddr);

    cout << "Start to update Para block address ";
    cout << "and bulk save result...\n";

    //HCE: We have to save into origin file for a lot of transactions saved in the blkindex.dat.
    const int nConstStep = 1000;
    int nCount = 0;
    int nStep = nConstStep;

    bool IsBestIdxerr = false;
    int nBestHeight = 0;

    tridb.TxnBegin();
    auto beginitem = mapBlkAddr.begin();
    for (; beginitem != mapBlkAddr.end(); ++beginitem) {

        if (!tridb.WriteBlockTripleAddress(beginitem->first, To_BlockTriAddr(beginitem->second))) {
            tridb.TxnAbort();
            cout << "File Format conversion is failed" << endl;
            return;
        }
        nCount++;
        nStep--;
        if (nStep == 0) {
            cout << "*";
            nStep = nConstStep;
        }
    }

    tridb.TxnCommit();

    DBFlush(false);
    cout << "\nFile Format conversion is finished" << endl;
}




//2021-1-28 15:00:26
//To new version Paracoin, CBlockIndex::bnChainWork is saved into blkindex.dat, more see CDiskBlockIndex class
//so we need to convert the old version blkindex.dat
//
//Usage:
//E:\workspace\git\buildwin64\bin\Debug>migr -datadir=C:\hc-69.61\migr\125 -model=informal
//This program do format conversion for Paracoin: C:\hc-69.61\migr\125\informal/blkindex.dat

void ShowUsage()
{
    cout << "\nSelect command:\n";
    cout << "Press '?' or 'help' for help" << endl;
    cout << "Press 1 : convert block index format into v0.7.3" << endl;
    cout << "Press 2 : format check" << endl;
    cout << "Press 3 : set max HID in blocktripleaddress.dat" << endl;
    cout << "Press 4 : read max HID in blocktripleaddress.dat" << endl;
    cout << "Press 5 : test bulk write and read, migrtest.dat will be generated" << endl;
    cout << "Press 'q' for exit" << endl;
}

int main(int argc, char* argv[])
{
    SoftwareInfo();
    AppParseParameters(argc, argv);

    string strDataDir = GetDataDir();

    cout << strprintf("This program do file format conversion for Paracoin: %s/blkindex.dat ", strDataDir.c_str()) << endl;
    cout << "Warning: The following operator will modify blkindex.dat and please save it firstly !!!" << endl;

    ShowUsage();

    while (true) {

        cout << "Migr $ ";
        string sInput;
        getline(std::istream(cin.rdbuf()), sInput);

        if (sInput == "?" || sInput == "help") {
            ShowUsage();
            continue;
        }

        if (sInput == "q") {
            break;
        }

        if (sInput == "1") {
            convertBlockIndexFormat();

            //cout << "converting blocktripleaddress.dat\n";
            //CBlockTripleAddressDBV72 tridb("r+");
            //convertBlockTriAddrFormat(tridb);

            //cout << "converting orphanblocktripleaddr.dat\n";
            //COrphanBlockTripleAddressDBV72 orphantridb("r+");
            //convertBlockTriAddrFormat(orphantridb);

            continue;
        }

        if (sInput == "2") {
            cout << "Start to check block index..." << endl;

            CSpentTime spentt;
            defer{
                cout << strprintf("Spent million seconds : %ld\n", spentt.Elapse());
            };

            CMgrTxDB_Tool txdb("r");

            //txdb.CheckBlockIndex();
            //improve the performance to 2.5 multiple than CheckBlockIndex
            txdb.BulkLoadBlockIndex();

            txdb.Close();
            cout << "Check is finished" << endl;
            continue;
        }


        if (sInput == "3") {
            CBlockTripleAddressDB btadb("cr+");

            cout << "Please input MaxHID: ";
            getline(std::istream(cin.rdbuf()), sInput);

            uint32 maxhidInDB = std::atoi(sInput.c_str());
            bool ret = btadb.WriteMaxHID(maxhidInDB);
            cout << "Write Max HID: " << ret << endl;
            continue;
        }

        if (sInput == "4") {
            CBlockTripleAddressDB btadb("cr+");

            uint32 maxhidInDB = 0;
            btadb.ReadMaxHID(maxhidInDB);
            cout << "Max HID is: " << maxhidInDB << endl;
            continue;
        }

        if (sInput == "5") {
            char* filename = "testmigr.dat";
            testbulkwrite(filename);
            CMgrTxDB_Tool txdb("r", filename);

            txdb.BulkLoadBlockIndex();
        }

    }

    DBFlush(true); //HCE: remove archive log
    return 0;
}
