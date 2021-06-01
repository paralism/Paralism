/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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
    void PrintStatus(int nAddCount, const string &msg = "")
    {
        //[ 145668   176(s)   18776(n/s) ] (msg)
        cout << "\r"             //Bring cursor to start of line
            << firstPartOfpBar;
        _ncount += nAddCount;

        int ms = _spentt.Elapse();
        if (ms == 0) {
            ms = 1; //1ms
        }
        cout << strprintf(" %d   %d(s)   %d(n/s)", _ncount, ms/1000, _ncount * 1000/ms);

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


std::multimap<int, CDiskBlockIndex2020> mapMigrBlockIndex;

class CMgrTxDB : public CTxDB
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
        char *data_buf = (char*)malloc(dlen);
        defer {
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
            for (;!isLoadCompleted;) {

                key.set_data(&ssKey[0]);
                key.set_size(ssKey.size());
                memset(data_buf, 0, dlen);

                int nAdd = 0;

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
                progress.PrintStatus(nAdd, strprintf("blockindex : %s" , currhash.ToPreViewString().c_str()));
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


    bool bulkUpdate_cpp()
    {
        Dbt key, data;
        u_int32_t flag;
        int i, ret;
        DbMultipleDataBuilder* ptrd, * ptrk;

        flag = ret = 0;

        char* key_buf, * data_buf;


        const int suffix = 8;
        int KEY_T_SIZE = 0;
        for (auto& ssKey: m_keybuf) {
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


    bool bulkUpdate_c()
    {
        if (!pdb)
            return false;

        DBT key, data;
        int i, ret, op_flag;

        char* key_buf, *data_buf;

        /* Initialize structs and arrays */
        memset(&key, 0, sizeof(DBT));
        memset(&data, 0, sizeof(DBT));


        const int suffix = 8;
        int KEY_SIZE = m_keybuf[0].size();
        int KEY_T_SIZE = (KEY_SIZE + suffix) * m_keybuf.size() + 4;
        key_buf = (char*)malloc(KEY_T_SIZE);

        int DATA_T_SIZE = 0;
        for (auto & ssValue : m_databuf) {
            DATA_T_SIZE += ssValue.size() + suffix;
        }
        DATA_T_SIZE += 4;

        data_buf = (char*)malloc(DATA_T_SIZE);
        memset(data_buf, 0, DATA_T_SIZE);

        /*
        * ��ʼ��Bulk buffer.ʹ����������(bulk operations) Ҳ���� * ��������/ɾ��/����/��ȡ��ʱ�򣬱���ʹ���û��ṩ���ڴ档
        * ������Ҫ����DBT�����flagsΪDB_DBT_USERMEM����������ulen��Ա������size��Ա��
        */
        key.data = key_buf;
        key.ulen = KEY_T_SIZE;
        key.flags = DB_DBT_USERMEM;
        data.data = data_buf;
        data.ulen = DATA_T_SIZE;
        data.flags = DB_DBT_USERMEM;

        op_flag = DB_MULTIPLE; /* ���flag��put/get/del ��ʾִ����������/����/��ȡ/ɾ���� */

        /*
        * ���bulk buffer DBT ����. �ȵ���DB_MULTIPLE_WRITE_INIT��ʼ���� * DBT�����봫��һ������ָ��p��data buffer DBT ����
        * p: ��������ڲ�ʹ�õĹ�����������DB_MULTIPLE_WRITE_INIT��ʼ�������ұ����ڴ˴�һֱʹ�á�
        */
        void* p;
        DB_MULTIPLE_WRITE_INIT(p, &data);
        for (i = 0; i < m_databuf.size(); i++) {
            /*
            * ������˵���� data: ��data buffer DBT����
            * ѭ�������������ɣ����data buffer������bulk_size��data��
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

        //��������key/data pairs.
        /* ��������׼���������롣 */
        if (!TxnBegin()) {
            m_dbenv->err(-1, "[insert] DB_ENV->txn_begin");
            goto inserterr;
        }

        switch (ret = dbp->put(dbp, GetTxn()->get_DB_TXN(), &key, &data, op_flag)) {
        case 0: /* ������������ɹ����ύ����*/
            if (!TxnCommit()) {
                m_dbenv->err(ret, "[insert] DB_TXN->commit");
            }
            result = true;
            break;
        case DB_LOCK_DEADLOCK:
            /* ������ݿ����������������ô����abort����Ȼ�󣬿���ѡ������ִ�иò�����*/
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

void testbulkwrite(const char *filename)
{
    CMgrTxDB txdb("cr+", filename);
    CBlockIndex idx;
    idx.addr.hid = 2111;
    idx.addr.id = 100;
    idx.addr.chainnum = 89;
    idx.addr.ns = "Hello";
    idx.bnChainWork = 89999;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba6");
    idx.nHeight = 10000;
    idx.nSolution = { 'a','a','n' };

    //txdb.WriteBlockIndex(CDiskBlockIndex(&idx));
    txdb.BulkWriteBlockIndex(CDiskBlockIndex(&idx));

    idx.addr.hid = 1999;
    idx.addr.id = 101;
    idx.addr.chainnum = 8;
    idx.addr.ns = "world...";
    idx.bnChainWork = 89999;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba7");
    idx.nHeight = 1001;
    idx.nSolution = { 'a' };

    txdb.BulkWriteBlockIndex(CDiskBlockIndex(&idx));

    idx.addr.hid = 1999;
    idx.addr.id = 102;
    idx.addr.chainnum = 8900;
    idx.addr.ns = "Hellollllllllllllllllllllllllllllllll";
    idx.bnChainWork = 12000;
    idx.hashBlock = uint256S("0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba8");
    idx.nHeight = 1003;
    idx.nSolution = { 'a','x','n','y','z','a','x','n','y','z' ,'a','x','n','y','z' };

    txdb.BulkWriteBlockIndex(CDiskBlockIndex(&idx));

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
    CMgrTxDB txdb("cr+");

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


    //CMgrTxDB txdbResult("cr+","blkindex-result.dat");

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
    cout << "Press 1 for format conversion" << endl;
    cout << "Press 2 for format check" << endl;
    cout << "Press 3 for set max HID in blocktripleaddress.dat" << endl;
    cout << "Press 4 for read max HID in blocktripleaddress.dat" << endl;
    cout << "Press 5 for test bulk write and read,  migrtest.dat will be generated" << endl;
    cout << "Press 'q' for exit" << endl;
}

int main(int argc, char* argv[])
{
    SoftwareInfo();
    AppParseParameters(argc, argv);

    string strDataDir = GetDataDir();

    cout << strprintf("This program do file format conversion for Paracoin: %s/blkindex.dat ", strDataDir.c_str())<< endl;
    cout << "Warning: The following operator will modify blkindex.dat and please save it firstly !!!"<< endl;

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
            convertFormat();
            continue;
        }

        if (sInput == "2") {
            cout << "Start to check block index..." << endl;

            CSpentTime spentt;
            defer{
                cout << strprintf("Spent million seconds : %ld\n", spentt.Elapse());
            };

            CMgrTxDB txdb("r");

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
            char *filename = "testmigr.dat";
            testbulkwrite(filename);
            CMgrTxDB txdb("r", filename);

            txdb.BulkLoadBlockIndex();
        }

    }

    DBFlush(true);
    return 0;
}