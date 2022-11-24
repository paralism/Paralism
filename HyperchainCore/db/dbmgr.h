/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#pragma once

#include "headers/inter_public.h"
#include "headers/commonstruct.h"

#include <thread>
#include <mutex>

#include <set>
#include <map>
#include <functional>

#include "util/cppsqlite3.h"

class CppSQLite3DB;

class DBmgr
{
public:
    DBmgr();
    virtual ~DBmgr();

    int open(const char * dbpath);
    bool isOpen();
    int close();
    bool bRecord;

public:
    class Transaction {
    public:
        Transaction(CppSQLite3DB *db) : _is_succ(false), _db(db) {
            if (_db) {
                _db->execDML("begin transaction");
            }
        }
        ~Transaction() {
            if (_db) {
                try {
                    _is_succ ? _db->execDML("commit transaction") :
                        _db->execDML("rollback transaction");
                }
                catch (CppSQLite3Exception& e) {
                    std::fprintf(stderr, "error code: %d %s", e.errorCode(), e.errorMessage());
                }
            }
        }
        void set_trans_succ() {
            _is_succ = true;
        }
    private:
        bool _is_succ;
        CppSQLite3DB *_db;
    };

    Transaction beginTran() {
        return Transaction(_db);
    }

    int insertEvidence(const TEVIDENCEINFO& evidence);
    int getEvidences(std::list<TEVIDENCEINFO>& evidences, int page, int size = 20);
    int updateEvidence(const TEVIDENCEINFO& evidence, int type = 1);
    int getNoConfiringList(std::list<TEVIDENCEINFO>& evidences);
    int delEvidence(std::string hash);
    int delEvidence(const TEVIDENCEINFO &evidence);
    int deleteHyperblockAndLocalblock(uint64 hid);
    int rollbackHyperblockAndLocalblock(uint64 hid);
    int deleteHyperblockAndLocalblock(uint64 hid, const T_SHA256& headerhash);
    int SaveHyperblock(const T_HYPERBLOCK& hyperblock);
    int SaveLocalblock(const T_LOCALBLOCK& localblock, uint64 hid, uint16 chainnum, const T_SHA256& hhash);
    int insertHyperblock(const T_HYPERBLOCK& hyperblock);
    int insertLocalblock(const T_LOCALBLOCK& localblock, uint64 hid, uint16 chainnum);
    int updateHyperblock(const T_HYPERBLOCK& hyperblock);
    int getLocalblock(T_LOCALBLOCK& info, uint64 hid, uint16 id, uint16 chain_num);
    int getLocalblock(T_LOCALBLOCK& localblock, const T_SHA256& hhash, const T_LOCALBLOCKADDRESS& addr);
    int getLocalchain(uint64 hid, int chain_num, int &blocks, int &chain_difficulty);
    int getLocalBlocks(std::list<T_LOCALBLOCK> &queue, uint64 nHyperID);
    int getLocalBlocks(std::list<T_LOCALBLOCK> &queue, const T_SHA256& hhash);
    int getLocalBlocks(std::list<T_LOCALBLOCK>& queue, const T_LOCALBLOCKADDRESS& addr);

    int getHyperBlockbyHeaderHash(T_HYPERBLOCK &h, uint64 hid, const T_SHA256 &headerhash);
    int getHyperblockshead(T_HYPERBLOCKHEADER& header, uint64 nStartHyperID);
    int getLocalblocksPayloadTotalSize(uint64 nStartHyperID,size_t& size);
    int getAllHyperblockNumInfo(std::set<uint64> &queue);
    int getHeaderByHash(T_HYPERBLOCKHEADER &header, uint64 hid, const T_SHA256& headerhash);
    int getHeaderIndexByHash(T_HEADERINDEX &headerindex, const T_SHA256& headerhash);
    int getAllSingleHeaderInfo(multimap<uint64, T_SINGLEHEADER> &singleheadermap);
    int getHeaderIndex(MAP_T_HEADERINDEX& headerindexmap, int page, int size = 10000);
    int getAllHeaderIndex(MAP_T_HEADERINDEX &headerindexmap);
    int updateHeaderIndex(const T_HEADERINDEX& headerindex);
    int getAllHeaderHashInfo(std::map<uint64, T_SHA256> &headerhashmap);
    int getHeadersByID(std::map<T_SHA256, T_HYPERBLOCKHEADER> &headermap, uint64 nStartHyperID, uint64 nEndHyperID);
    int getHeadersByID(std::list<T_HYPERBLOCKHEADER> &headerlist, uint64 nStartHyperID, uint64 nEndHyperID);
    int getFurcatedHeaderHash(uint64 hid, const T_SHA256& headerhash, vector<T_SHA256> &headerhashvec);
    int getAllBlockHashInfo(std::map<uint64, T_SHA256> &hashmap);
    int getAllHeaderHashInfo(std::set<pair<uint64, T_SHA256>> &headerhashset);
    int getHyperBlocks(std::list<T_HYPERBLOCK> &queue, uint64 nStartHyperID, uint64 nEndHyperID);
    int getHyperBlock(T_HYPERBLOCK &h, const T_SHA256 &hhash);
    int getUpqueue(std::list<TUPQUEUE> &queue, int page, int size);
    int delUpqueue(std::string hash);
    int64 addUpqueue(string sHash);

    int getLatestHyperBlockNo();
    int getLatestHyperBlock(T_HYPERBLOCK& hyperblock);
    bool getOnChainStateFromRequestID(const string &requestid, T_LOCALBLOCKADDRESS &addr);
    bool getRequestID(const string &batchid, string &requestid);
    int getRequestIDs(vector<string> &requestIDvec);
    int updateSucceedRequestIDs(const string &requestid);
    int getBatchOnChainData(const string &requestid, string &data);

    int getHeaderIndexRecordNumber();
    bool isHeaderIndexExisted(uint64 hid);
    //bool isHeaderExistedbyHash(T_SHA256 hash);
    bool isBlockExisted(uint64 hid);
    bool isBlockExistedbyHash(const T_SHA256& hash);
    bool isBlockExistedbyHeaderHash(uint64 hid, const T_SHA256& headerhash);
    bool isBlockExistedOnBestChain(uint64 hid);

    int rollbackHashInfo(uint64 hid);
    int rollbackHeaderHashInfo(uint64 hid);
    int rollbackSingleHeaderInfo(uint64 hid);
    int deleteHeader(uint64 hid, const T_SHA256& headerhash);
    int deleteHeaderIndex(uint64 hid, const T_SHA256& headerhash);
    int deleteSingleHeaderInfo(uint64 hid, const T_SHA256& headerhash);
    int updateHeaderHashInfo(const uint64 hid, const T_SHA256& headerhash);
    int updateHashInfo(const uint64 hid, const T_SHA256& headerhash, const T_SHA256& hash);
    int updateHeaderInfo(const uint64 hid, const T_SHA256& headerhash, const T_HYPERBLOCKHEADER& header);
    int updateSingleHeaderInfo(const T_SINGLEHEADER& singleheader);
    int InsertOnChainState(const string& requestid, const T_LOCALBLOCKADDRESS& address);
    int updateOnChainState(const string &requestid, const T_LOCALBLOCKADDRESS& address);
    int updateBatchOnChainState(const string &batchid, const string &requestid, const string& batchdata);
    int updateBatchOnChainState(const string &requestid, const string &newrequestid);
    void initOnChainState(uint64 hid);
    void rehandleOnChainState(uint64 hid);

    int RecordRequestTime(const string& requestid, const string& accesspointint, int& queuenum);
    void RecordOnchain1Time(const string& requestid);
    void RecordOnchain2Time(const string& requestid);
    void RecordOnchainTime(const string& requestid);
    void RecordMatureTime(const string& requestid);
    void ResetOnchainTime(uint64 hid);

    void RecordMsgInfo(uint64 msgsize, string function, string toPeer);

    void bindParam(CppSQLite3Statement &stmt, int i)
    {}

    template<typename... Args>
    void bindParam(CppSQLite3Statement &stmt, int i, string &first, Args&&... args)
    {
        stmt.bind(i, first.c_str(), first.size());
        bindParam(stmt, ++i, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void bindParam(CppSQLite3Statement &stmt, int i, uint64 first, Args&&... args)
    {
        stmt.bind(i, (sqlite_int64)first);
        bindParam(stmt, ++i, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void bindParam(CppSQLite3Statement &stmt, int i, int64 first, Args&&... args)
    {
        stmt.bind(i, (sqlite_int64)first);
        bindParam(stmt, ++i, std::forward<Args>(args)...);
    }

    template<typename T, typename... Args>
    void bindParam(CppSQLite3Statement &stmt, int i, T && first, Args&&... args)
    {
        stmt.bind(i, first);
        bindParam(stmt, ++i, std::forward<Args>(args)...);
    }
    template<typename... Args>
    bool query(const string & sql, std::function<void(CppSQLite3Query&)> f, Args&&... args)
    {
        try {
            CppSQLite3Statement stmt;
            stmt = _db->compileStatement(sql.c_str());
            bindParam(stmt, 1, args...);

            CppSQLite3Query query = stmt.execQuery();
            while (!query.eof()) {
                f(query);
                query.nextRow();
            }
        }
        catch (CppSQLite3Exception& ex) {
            dbError(sql.c_str(), __LINE__, ex);
            return false;
        }
        return true;
    }

    //HC: return count of rows changed
    template<typename... Args>
    int exec(const string & sql, Args&&... args)
    {
        try {
            CppSQLite3Statement stmt;
            stmt = _db->compileStatement(sql.c_str());
            bindParam(stmt, 1, args...);
            return stmt.execDML();
        }
        catch (CppSQLite3Exception& ex) {
            dbError(sql.c_str(), __LINE__, ex);
        }
        return 0;
    }

private:

    int createTbls();
    int updateDB();

    bool ifColExist(const char* tbl, const char* col);
    //type 1:tbl 2:index
    bool ifTblOrIndexExist(const char* name, int type = 1);

    int dbError(const char * funcname, int line, CppSQLite3Exception& ex);

private:
    CppSQLite3DB *_db = nullptr;
    std::mutex _mutex;
};
