/*Copyright 2016-2023 hyperchain.net (Hyperchain)

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
#include "../newLog.h"
#include <random>
#include "db/dbmgr.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#define DBERROR(ex) dbError(__FUNCTION__, __LINE__, ex)

namespace DBSQL {

    //HCE: 存证记录
    const std::string EVIDENCES_TBL =
        "CREATE TABLE IF NOT EXISTS evidence_tbl "
        "("
        "    [hash]                                 TEXT NOT NULL,"
        "    [blocknum]                             INTEGER DEFAULT 0,"
        "    [filename]                             TEXT NOT NULL,"
        "    [custominfo]                           TEXT DEFAULT '',"
        "    [owner]                                TEXT DEFAULT '',"
        "    [filestate]                            INTEGER DEFAULT 0,"
        "    [regtime]                              INTEGER DEFAULT 0,"
        "    [filesize]                             INTEGER DEFAULT '',"
        "    [extra]                                TEXT DEFAULT '',"
        "    PRIMARY KEY(hash, regtime)"
        ");";

    const std::string HYPERBLOCK_TBL =
        "CREATE TABLE IF NOT EXISTS hyperblock ("
        "  [id] INTEGER DEFAULT 0,"
        "  [hash_prev] char(64) NOT NULL DEFAULT '',"
        "  [header] blob DEFAULT '' NOT NULL,"
        "  [body] blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (id, hash_prev)"
        ");";


    const std::string LOCALBLOCK_TBL =
        "CREATE TABLE IF NOT EXISTS localblock ("
        "  [id] INTEGER DEFAULT 0,"
        "  [hid] INTEGER DEFAULT 0,"
        "  [chain_num] INTEGER DEFAULT 0,"
        //"  [hash_prev] char(64) NOT NULL DEFAULT '',"
        //"  [hhash_prev] char(64) NOT NULL DEFAULT '',"
        "  [header] blob DEFAULT '' NOT NULL,"
        "  [body] blob DEFAULT '' NOT NULL,"
        "  [payloadMTree] blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (hid,chain_num,id)"
        ");";

    const std::string ONCHAINED_TBL =
        "CREATE TABLE IF NOT EXISTS localblockonchained ("
        "  [requestid]	varchar(32) DEFAULT ''," //HCE: uuid, which is tLocalBlock.getUUID
        "  [hid]		INTEGER DEFAULT 0,"
        "  [chain_num]	INTEGER DEFAULT 0,"
        "  [id]	INTEGER DEFAULT 0,"			//HCE: local block id
        "  PRIMARY KEY (requestid)"
        ");";

    const std::string BATCHONCHAINED_TBL =
        "CREATE TABLE IF NOT EXISTS batchonchained ("
        "  [batchid]	varchar(32) DEFAULT '',"
        "  [requestid]	varchar(32) DEFAULT ''," //HCE: uuid, which is tLocalBlock.getUUID
        "  [data]       blob DEFAULT '' NOT NULL,"
        "  [retry]      INTEGER DEFAULT 0,"
        "  [ctime]	    INTEGER DEFAULT 0,"
        "  [succeed]	INTEGER DEFAULT 0,"
        "  PRIMARY KEY (batchid,requestid,ctime)"
        ");";


    //HCE: best chain info
    const std::string HASHINFO_TBL =
        "CREATE TABLE IF NOT EXISTS hyperblockhashinfo ("
        "  [id]		    INTEGER DEFAULT 0,"
        "  [headerhash]	char(64) NOT NULL DEFAULT '',"
        "  [hash]	    char(64) NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id)"
        ");";

    //HCE: best header chain info
    const std::string HEADERHASHINFO_TBL =
        "CREATE TABLE IF NOT EXISTS headerhashinfo ("
        "  [id]		    INTEGER DEFAULT 0,"
        "  [headerhash]	char(64) NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id)"
        ");";

    const std::string SINGLEHEADERS_TBL =
        "CREATE TABLE IF NOT EXISTS singleheaders ("
        "  [id]             INTEGER DEFAULT 0,"
        "  [headerhash]	    char(64) NOT NULL DEFAULT '',"
        "  [preheaderhash]	char(64) NOT NULL DEFAULT '',"
        "  [from_id]	   TEXT NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id,headerhash)"
        ");";

    const std::string HEADER_TBL =
        "CREATE TABLE IF NOT EXISTS header ("
        "  [id]     	INTEGER DEFAULT 0,"
        "  [headerhash]	char(64) NOT NULL DEFAULT '',"
        "  [header]	    blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (id,headerhash)"
        ");";

    const std::string HEADERINDEX_TBL =
        "CREATE TABLE IF NOT EXISTS headerindex ("
        "  [id]     	   INTEGER DEFAULT 0,"
        "  [headerhash]	   char(64) NOT NULL DEFAULT '',"
        "  [preheaderhash] char(64) NOT NULL DEFAULT '',"
        "  [prehash]       char(64) NOT NULL DEFAULT '',"
        "  [ctime]	       INTEGER DEFAULT 0,"
        "  [weight]	       INTEGER DEFAULT 0,"
        "  [total_weight]  INTEGER DEFAULT 0,"
        "  [from_id]	   TEXT NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id,headerhash)"
        ");";

    const std::string HBLOCKS_TBL =
        "CREATE TABLE IF NOT EXISTS hblocks ("
        "  [id]         INTEGER DEFAULT 0,"
        "  [headerhash]	char(64) NOT NULL DEFAULT '',"
        "  [hash]       char(64) NOT NULL DEFAULT '',"
        "  [header]     blob DEFAULT '' NOT NULL,"
        "  [body]       blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (id,headerhash,hash)"
        ");";

    const std::string LBLOCKS_TBL =
        "CREATE TABLE IF NOT EXISTS lblocks ("
        "  [id] INTEGER DEFAULT 0,"
        "  [hid] INTEGER DEFAULT 0,"
        "  [chain_num] INTEGER DEFAULT 0,"
        "  [hhash] char(64) NOT NULL DEFAULT '',"
        "  [header] blob DEFAULT '' NOT NULL,"
        "  [body] blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (id,hid,chain_num,hhash)"
        ");";


    const std::string UPQUEUE_TBL =
        "CREATE TABLE IF NOT EXISTS upqueue ("
        "  [id] integer PRIMARY KEY autoincrement,"
        "  [hash]	TEXT NOT NULL DEFAULT '',"
        "  [ctime]	INTEGER DEFAULT 0"
        ");";

    const std::string MYSELF_TBL =
        "CREATE TABLE IF NOT EXISTS myself ("
        "  [id] char(16) PRIMARY KEY,"
        "  [regtime] INTEGER DEFAULT 0,"
        "  [accesspoint] TEXT NOT NULL DEFAULT ''"
        ");";

    const std::string NEIGHBORNODE_TBL =
        "CREATE TABLE IF NOT EXISTS neighbornodes ("
        "  [id] char(16) PRIMARY KEY,"
        "  [accesspoint] TEXT NOT NULL DEFAULT '',"
        "  [lasttime] INTEGER DEFAULT 0"
        ");";

    const std::string ONCHAINDATA_TBL =
        "CREATE TABLE IF NOT EXISTS onchaindata ("
        "  [requestid]	varchar(32) DEFAULT ''," //HCE: uuid, which is tLocalBlock.getUUID
        "  [requesttime] INTEGER DEFAULT 0,"
        "  [onchain1time] INTEGER DEFAULT 0,"
        "  [onchain2time] INTEGER DEFAULT 0,"
        "  [onchaintime] INTEGER DEFAULT 0,"
        "  [maturetime] INTEGER DEFAULT 0,"
        "  [queuenum] INTEGER DEFAULT 0,"
        "  [accesspoint] TEXT NOT NULL DEFAULT '',"
        "  PRIMARY KEY (requestid)"
        ");";

    const std::string SENDMSGINFO_TBL =
        "CREATE TABLE IF NOT EXISTS sendmsginfo ("
        "  [msgid] integer PRIMARY KEY autoincrement,"
        "  [msgsize] INTEGER DEFAULT 0,"
        "  [sendtime] INTEGER DEFAULT 0,"
        "  [timecircle] INTEGER DEFAULT 0,"
        "  [function] TEXT NOT NULL DEFAULT '',"
        "  [to_id]	   TEXT NOT NULL DEFAULT 'ALL'"
        ");";

}




////////////////////////////////////////////////////
static const std::string scEvidenceInsert = "INSERT OR REPLACE INTO evidence_tbl(hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra) "
"VALUES(?,?,?,?,?,?,?,?,?);";
////////////////////////////////////////////////////
static const std::string scUpqueueInsert = "INSERT OR REPLACE INTO upqueue(hash,ctime) "
"VALUES(?,?);";
////////////////////////////////////////////////////

static const std::string scGetNeighbors = "SELECT * FROM neighbornodes";
////////////////////////////////////////////////////

DBmgr::DBmgr() {
    bRecord = false;

}

DBmgr::~DBmgr()
{
    if (_db) {
        if (_db->isOpen()) {
            _db->close();
        }
        delete _db;
        _db = nullptr;
    }
}

int DBmgr::open(const char *dbpath)
{
    int ecode = 0;
    try {
        if (_db) {
            if (_db->isOpen()) {
                _db->close();
            }
        }

        if (!_db) {
            _db = new CppSQLite3DB();
        }

        _db->open(dbpath);

#ifndef _DEBUG
        //int result = sqlite3_key(_db->getDB(), "123456!@#$%^", 12);
#endif
        createTbls();

        updateDB();
    }
    catch (CppSQLite3Exception& sqliteException) {
        return DBERROR(sqliteException);
    }
    catch (...) {
        ecode = -1;
    }

    return ecode;
}

bool DBmgr::isOpen()
{
    if (_db && _db->isOpen())
    {
        return true;
    }

    return false;
}

int DBmgr::close()
{
    int ecode = 0;

    try {
        _db->close();
    }
    catch (CppSQLite3Exception& sqliteException) {
        ecode = sqliteException.errorCode();
    }
    catch (...) {
        ecode = -1;
    }

    return ecode;
}

bool DBmgr::ifColExist(const char *tbl, const char *col)
{
    CppSQLite3Statement stmt = _db->compileStatement("SELECT sql FROM sqlite_master WHERE type='table' AND name = ?");
    stmt.bind(1, tbl);

    std::string sql;
    CppSQLite3Query query = stmt.execQuery();
    while (!query.eof())
    {
        sql = query.getStringField(0);
        break;
    }

    return std::string::npos != sql.find(col);
}

bool DBmgr::ifTblOrIndexExist(const char *name, int type)
{
    int exist = 0;

    try {
        std::string sql;
        if (1 == type) {
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?";
        }
        else {
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?";
        }

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        stmt.bind(1, name);

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()) {
            exist = query.getIntField(0);
        }
    }
    catch (...) {
        exist = 0;
    }

    return exist > 0;
}

int DBmgr::insertEvidence(const TEVIDENCEINFO &evidence)
{
    try
    {
        //HCE: hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra
        CppSQLite3Statement stmt = _db->compileStatement(scEvidenceInsert.c_str());
        stmt.bind(1, evidence.cFileHash.c_str());
        stmt.bind(2, (sqlite_int64)evidence.iBlocknum);
        stmt.bind(3, evidence.cFileName.c_str());
        stmt.bind(4, evidence.cCustomInfo.c_str());
        stmt.bind(5, evidence.cRightOwner.c_str());
        stmt.bind(6, evidence.iFileState);
        stmt.bind(7, (sqlite_int64)evidence.tRegisTime);
        stmt.bind(8, (sqlite_int64)evidence.iFileSize);
        stmt.bind(9, "");

        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getEvidences(std::list<TEVIDENCEINFO> &evidences, int page, int size)
{
    int ret = 0;

    try
    {
        CppSQLite3Statement stmt;
        std::string sql;
        if (page == -1) {
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC;";
        }
        else {
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1) {
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof())
        {
            //HCE: hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra
            TEVIDENCEINFO evi;
            evi.cFileHash = query.getStringField("hash");
            evi.cFileName = query.getStringField("filename");
            evi.cCustomInfo = query.getStringField("custominfo");
            evi.cRightOwner = query.getStringField("owner");
            evi.iFileState = query.getIntField("filestate");
            evi.tRegisTime = query.getInt64Field("regtime");
            evi.iFileSize = query.getInt64Field("filesize");
            evi.iBlocknum = query.getInt64Field("blocknum");

            evidences.push_back(evi);

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getNoConfiringList(std::list<TEVIDENCEINFO>& evidences)
{
    int ret = 0;

    try
    {
        CppSQLite3Statement stmt;
        std::string sql;

        sql = "SELECT * FROM evidence_tbl WHERE filestate!=? ORDER BY regtime DESC;";

        stmt = _db->compileStatement(sql.c_str());
        stmt.bind(1, CONFIRMED);

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof())
        {
            //HCE: hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra
            TEVIDENCEINFO evi;
            evi.cFileHash = query.getStringField("hash");
            evi.cFileName = query.getStringField("filename");
            evi.cCustomInfo = query.getStringField("custominfo");
            evi.cRightOwner = query.getStringField("owner");
            evi.iFileState = query.getIntField("filestate");
            evi.tRegisTime = query.getInt64Field("regtime");
            evi.iFileSize = query.getInt64Field("filesize");
            evi.iBlocknum = query.getInt64Field("blocknum");

            evidences.push_back(evi);

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::updateEvidence(const TEVIDENCEINFO &evidence, int type)
{
    try {
        //HCE: hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra
        std::string sql;
        if (1 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE hash=?;";
        }
        else if (2 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE hash=? AND regtime=?;";
        }
        else if (3 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE filestate=?;";
        }
        else if (4 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?,blocknum=? "
                "WHERE hash=? AND regtime=?;";
        }

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        if (1 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, evidence.cFileHash.c_str());
        }
        else if (2 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, evidence.cFileHash.c_str());
            stmt.bind(3, (sqlite_int64)evidence.tRegisTime);
        }
        else if (3 == type) {
            stmt.bind(1, REJECTED);
            stmt.bind(2, CONFIRMING);
        }
        else if (4 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, (sqlite_int64)evidence.iBlocknum);
            stmt.bind(3, evidence.cFileHash.c_str());
            stmt.bind(4, (sqlite_int64)evidence.tRegisTime);
        }

        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::delEvidence(std::string hash)
{
    try {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM evidence_tbl WHERE hash=?;");
        stmt.bind(1, hash.c_str());
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::delEvidence(const TEVIDENCEINFO &evidence)
{
    try
    {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM evidence_tbl WHERE hash=? AND regtime=?;");
        stmt.bind(1, evidence.cFileHash.c_str());
        stmt.bind(2, (sqlite_int64)evidence.tRegisTime);
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::createTbls()
{
    _db->execDML(DBSQL::EVIDENCES_TBL.c_str());
    _db->execDML(DBSQL::HYPERBLOCK_TBL.c_str());
    _db->execDML(DBSQL::LOCALBLOCK_TBL.c_str());
    _db->execDML(DBSQL::ONCHAINED_TBL.c_str());
    _db->execDML(DBSQL::BATCHONCHAINED_TBL.c_str());
    _db->execDML(DBSQL::HASHINFO_TBL.c_str());
    _db->execDML(DBSQL::HEADER_TBL.c_str());
    _db->execDML(DBSQL::SINGLEHEADERS_TBL.c_str());
    _db->execDML(DBSQL::HEADERHASHINFO_TBL.c_str());
    _db->execDML(DBSQL::HEADERINDEX_TBL.c_str());
    _db->execDML(DBSQL::HBLOCKS_TBL.c_str());
    _db->execDML(DBSQL::LBLOCKS_TBL.c_str());
    _db->execDML(DBSQL::UPQUEUE_TBL.c_str());
    _db->execDML(DBSQL::MYSELF_TBL.c_str());
    _db->execDML(DBSQL::NEIGHBORNODE_TBL.c_str());
    _db->execDML(DBSQL::ONCHAINDATA_TBL.c_str());
    _db->execDML(DBSQL::SENDMSGINFO_TBL.c_str());
    return 0;
}

int DBmgr::updateDB()
{
    //HC: 兼容老版本db,增加表neighbornodes字段,sqlite目前不支持修改字段类型
    //HCE: Compatible with the old version of DB, add the table NeighborNodes field, 
    //HCE: SQLite currently does not support modifying the field type
    //TO DO in the future
    if (ifTblOrIndexExist("neighbornodes", 1)) {
        if (!ifColExist("neighbornodes", "lasttime")) {
            exec("alter table neighbornodes ADD lasttime integer default 0");
        }
    }

    if (ifTblOrIndexExist("singleheader", 1)) {
        exec("DROP TABLE singleheader");
    }
    return 0;
}

int DBmgr::deleteHyperblockAndLocalblock(uint64 hid)
{
    try {
        exec("DELETE FROM hyperblock WHERE id=?", static_cast<sqlite_int64>(hid));
        exec("DELETE FROM localblock WHERE hid=?", static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::rollbackHyperblockAndLocalblock(uint64 hid)
{
    try {
        exec("DELETE FROM hyperblock WHERE id>=?", static_cast<sqlite_int64>(hid));
        exec("DELETE FROM localblock WHERE hid>=?", static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::deleteHyperblockAndLocalblock(uint64 hid, const T_SHA256& headerhash)
{
    try {
        exec("DELETE FROM lblocks WHERE hid=? AND hhash=(SELECT hash FROM hblocks WHERE id=? AND headerhash=?)", hid, hid, headerhash.toHexString());
        exec("DELETE FROM hblocks WHERE id=? AND headerhash=?", hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::deleteHeader(uint64 hid, const T_SHA256& headerhash)
{
    try {
        exec("DELETE FROM header WHERE id=? AND headerhash=?", hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::deleteHeaderIndex(uint64 hid, const T_SHA256& headerhash)
{
    try {
        exec("DELETE FROM headerindex WHERE id=? AND headerhash=?", hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::rollbackSingleHeaderInfo(uint64 hid)
{
    try {
        exec("DELETE FROM singleheaders WHERE id<=?",
            static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception & ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::rollbackHeaderHashInfo(uint64 hid)
{
    try {
        exec("DELETE FROM headerhashinfo WHERE id>=?",
            static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::rollbackHashInfo(uint64 hid)
{
    try {
        exec("DELETE FROM hyperblockhashinfo WHERE id>=?", static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::deleteSingleHeaderInfo(uint64 hid, const T_SHA256& headerhash)
{
    try {
        exec("DELETE FROM singleheaders WHERE id=? AND headerhash=?", hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::insertHyperblock(const T_HYPERBLOCK& hyperblock)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << hyperblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << hyperblock.body;
        string body = ssBuf.str();

        exec("insert or replace into hyperblock(id,hash_prev,header,body) values(?,?,?,?)",
            hyperblock.GetID(),
            hyperblock.GetPreHash().toHexString(),
            header, body);
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return -1;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateHyperblock(const T_HYPERBLOCK& hyperblock)
{
    return insertHyperblock(hyperblock);
}

int DBmgr::insertLocalblock(const T_LOCALBLOCK& localblock, uint64 hid, uint16 chainnum)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << localblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << localblock.body;
        string body = ssBuf.str();

        ssBuf.str("");
        uint32 payloadnum = static_cast<uint32>(localblock.payloadMTree.size());
        oa << payloadnum;
        oa << boost::serialization::make_array(localblock.payloadMTree.data(), payloadnum);
        string mt = ssBuf.str();
        exec("insert or replace into localblock(id,hid,chain_num,header,body,payloadMTree) values(?,?,?,?,?,?)",
            localblock.GetID(), hid, chainnum,
            header, body, mt);
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return -1;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::getLocalblock(T_LOCALBLOCK& localblock, uint64 hid, uint16 id, uint16 chain_num)
{
    int ret = -1;
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM localblock WHERE hid=? AND id=? AND chain_num=?;", [&localblock, &ret, hid](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            localblock.SetChainNum(q.getIntField("chain_num"));
            localblock.SetPreHID(hid - 1);
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                ret = 0;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
            catch (runtime_error& e) {
                g_console_logger->warn("{}", e.what());
            }
        }, hid, id, chain_num);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getLocalblock(T_LOCALBLOCK& localblock, const T_SHA256& hhash, const T_LOCALBLOCKADDRESS& addr)
{
    int ret = -1;
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM lblocks WHERE hhash=? AND hid=? AND id=? AND chain_num=?;", [&localblock, &ret, addr](CppSQLite3Query& q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            localblock.SetChainNum(q.getIntField("chain_num"));
            localblock.SetPreHID(addr.hid - 1);
            try {
                const unsigned char* p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                ret = 0;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
            catch (runtime_error & e) {
                g_console_logger->warn("{}", e.what());
            }
        }, hhash.toHexString(), addr.hid, addr.id, addr.chainnum);
    }
    catch (CppSQLite3Exception & ex) {
        return DBERROR(ex);
    }

    return ret;
}


int DBmgr::getLocalchain(uint64 hid, int chain_num, int &blocks, int &chain_difficulty)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT count(*) as blocks FROM localblock WHERE hid=? AND chain_num=?;",
            [&blocks](CppSQLite3Query & q) {
            blocks = q.getIntField("blocks");
        }, hid, chain_num);
        //TO DO: how to compute chain_difficulty?
        chain_difficulty = blocks;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getLocalBlocks(std::list<T_LOCALBLOCK> &queue, uint64 nHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM localblock WHERE hid=? order by chain_num;", [&queue, nHyperID](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_LOCALBLOCK localblock;
                localblock.SetChainNum(q.getIntField("chain_num"));
                localblock.SetPreHID(nHyperID - 1);
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                queue.emplace_back(localblock);
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
            catch (std::exception& e) {
                g_consensus_console_logger->error("{}", e.what());
            }
            catch (...) {
                g_consensus_console_logger->error("unknown exception occurs");
            }
        }, nHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getHyperBlockbyHeaderHash(T_HYPERBLOCK &h, uint64 hid, const T_SHA256 &headerhash)
{

    try {
        CppSQLite3Statement stmt;
        query("select * from hblocks where id=? AND headerhash=? ;", [&h](CppSQLite3Query & q) {
            stringstream ssBuf;
            int len = 0;
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
                ia >> h.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> h.body;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
        }, hid, headerhash.toHexString());
        return 0;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return -1;
}

int DBmgr::getHyperBlock(T_HYPERBLOCK &h, const T_SHA256 &hhash)
{

    try {
        CppSQLite3Statement stmt;
        query("select * from hyperblock where id = (SELECT id FROM hyperblock WHERE hash_prev=?);", [&h](CppSQLite3Query & q) {
            stringstream ssBuf;
            int len = 0;
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
                ia >> h.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> h.body;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
        }, hhash.toHexString());
        return 0;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return -1;
}

int DBmgr::getHyperBlocks(std::list<T_HYPERBLOCK> &queue, uint64 nStartHyperID, uint64 nEndHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblock WHERE id>=? AND id<=? order by id;", [&queue](CppSQLite3Query & q) {
            stringstream ssBuf;
            int len = 0;
            try {
                T_HYPERBLOCK hyperblock;
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
                ia >> hyperblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> hyperblock.body;

                queue.emplace_back(hyperblock);
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
        }, nStartHyperID, nEndHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getAllHyperblockNumInfo(std::set<uint64> &queue)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT id FROM hyperblock ORDER BY id;",
            [&queue](CppSQLite3Query & q) {
            queue.insert(q.getInt64Field("id"));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getHyperblockshead(T_HYPERBLOCKHEADER& header, uint64 nStartHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblock WHERE id=?;",
            [&header](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> header;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
        }, nStartHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getLocalblocksPayloadTotalSize(uint64 nStartHyperID, size_t& size)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT sum(length(hex(body))) as s FROM localblock WHERE hid=?;",
            [&size](CppSQLite3Query & q) {
            size = static_cast<size_t>(q.getInt64Field("s"));
        }, nStartHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::delUpqueue(std::string hash)
{
    try {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM upqueue WHERE hash=?;");
        stmt.bind(1, hash.c_str());
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int64 DBmgr::addUpqueue(string sHash)
{
    try {
        uint64_t uiTime = time(NULL);
        CppSQLite3Statement stmt = _db->compileStatement(scUpqueueInsert.c_str());
        stmt.bind(1, sHash.c_str());
        stmt.bind(2, (sqlite_int64)uiTime);
        stmt.execDML();
        return sqlite3_last_insert_rowid(_db->getDB());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getUpqueue(std::list<TUPQUEUE> &queue, int page, int size)
{
    int ret = 0;

    try {
        CppSQLite3Statement stmt;
        std::string sql;
        if (page == -1) {
            sql = "SELECT * FROM upqueue";
        }
        else {
            sql = "SELECT * FROM upqueue LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1) {
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof()) {
            //HCE: hash,ctime
            TUPQUEUE evi;
            evi.uiID = query.getInt64Field("id");
            evi.strHash = query.getStringField("hash");
            evi.uiTime = query.getInt64Field("ctime");

            queue.push_back(evi);

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getLatestHyperBlockNo()
{
    int ret = 0;
    try {
        CppSQLite3Statement stmt;
        std::string sql = "SELECT max(id) as hid FROM hyperblock";

        stmt = _db->compileStatement(sql.c_str());

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()) {
            return query.getIntField("hid");
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

bool DBmgr::isBlockExistedbyHash(const T_SHA256& hash)
{
    int num = 0;
    query("SELECT count(*) as num FROM hblocks WHERE hash = ? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    },
        hash.toHexString());

    return num != 0;
}

bool DBmgr::isBlockExistedbyHeaderHash(uint64 hid, const T_SHA256& headerhash)
{
    int num = 0;
    query("SELECT count(*) as num FROM hblocks WHERE id=? AND headerhash=? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    }, hid, headerhash.toHexString());

    return num != 0;
}

bool DBmgr::isBlockExistedOnBestChain(uint64 hid)
{
    int num = 0;
    query("SELECT count(*) as num FROM hyperblockhashinfo WHERE id>=? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    }, hid);

    return num != 0;
}

int DBmgr::getAllHeaderHashInfo(std::map<uint64, T_SHA256> &headerhashmap)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM headerhashinfo ORDER BY id;",
            [&headerhashmap](CppSQLite3Query & q) {
            headerhashmap[q.getInt64Field("id")] = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getAllBlockHashInfo(std::map<uint64, T_SHA256> &hashmap)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblockhashinfo ORDER BY id;",
            [&hashmap](CppSQLite3Query & q) {
			hashmap[q.getInt64Field("id")] = CCommonStruct::StrToHash256(string(q.getStringField("hash")));
	    });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getAllHeaderHashInfo(std::set<pair<uint64, T_SHA256>> &headerhashset)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT id, headerhash FROM header ORDER BY id;",
            [&headerhashset](CppSQLite3Query & q) {
            uint64 id = q.getInt64Field("id");
            T_SHA256 hhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            headerhashset.insert(make_pair(id, hhash));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::updateHeaderHashInfo(const uint64 hid, const T_SHA256& headerhash)
{
    try {
        exec("insert or replace into headerhashinfo(id,headerhash) values(?,?);",
            hid, headerhash.toHexString());

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateHashInfo(const uint64 hid, const T_SHA256& headerhash, const T_SHA256& hash)
{
    try {
        exec("insert or replace into hyperblockhashinfo(id,headerhash,hash) values(?,?,?);",
            hid,
            headerhash.toHexString(),
            hash.toHexString());

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateBatchOnChainState(const string &batchid, const string &requestid, const string& batchdata)
{
    try {
        exec("insert or replace into batchonchained(batchid,requestid,data,ctime) values(?,?,?,?);",
            batchid.c_str(),
            requestid.c_str(),
            batchdata,
            (uint64_t)time(NULL));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateBatchOnChainState(const string &requestid, const string &newrequestid)
{
    try {
        exec("UPDATE batchonchained SET requestid=?,retry=retry+1,ctime=? WHERE requestid=?;",
            newrequestid.c_str(),
            (uint64_t)time(NULL),
            requestid.c_str());

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::InsertOnChainState(const string& requestid, const T_LOCALBLOCKADDRESS& address)
{
    return exec("insert or replace into localblockonchained(requestid,hid,chain_num,id) values(?,?,?,?)",
        requestid.c_str(),
        address.hid,
        address.chainnum,
        address.id);
}

int DBmgr::updateOnChainState(const string &requestid, const T_LOCALBLOCKADDRESS& address)
{
    int nRowsChanged = exec("update localblockonchained set hid=?,chain_num=?,id=? where requestid=?",
        address.hid,
        address.chainnum,
        address.id,
        requestid.c_str());
    return nRowsChanged;
}

int DBmgr::RecordRequestTime(const string& requestid, const string& accesspoint, int& queuenum) {
    if (!bRecord)
        return 0;

    int num = 0;
    query("SELECT count(*) as num FROM onchaindata where requestid=?;",
        [&num](CppSQLite3Query& q) {
            num = q.getIntField("num");
        }, requestid.c_str());

    if (num > 0)
        return 0;

    exec("insert into onchaindata(requestid,requesttime,accesspoint,queuenum) values(?,?,?,?);",
        requestid.c_str(),
        time(nullptr),
        accesspoint.c_str(),
        queuenum);

    return 1;
}

void DBmgr::RecordOnchain1Time(const string& requestid) {
    if (!bRecord)
        return;

    exec("update onchaindata set onchain1time=? where requestid=? and onchain1time=0;",
        time(nullptr),
        requestid.c_str());
}

void DBmgr::RecordOnchain2Time(const string& requestid) {
    if (!bRecord)
        return;

    exec("update onchaindata set onchain2time=? where requestid=? and onchain2time=0;",
        time(nullptr),
        requestid.c_str());
}

void DBmgr::RecordOnchainTime(const string& requestid) {
    if (!bRecord)
        return;

    exec("update onchaindata set onchaintime=? where requestid=? and onchaintime=0;",
        time(nullptr),
        requestid.c_str());
}

void DBmgr::RecordMatureTime(const string& requestid) {
    if (!bRecord)
        return;

    exec("update onchaindata set maturetime=? where requestid=? and maturetime=0;",
        time(nullptr),
        requestid.c_str());
}

void DBmgr::ResetOnchainTime(uint64 hid) {
    if (!bRecord)
        return;

    exec("update onchaindata set onchaintime=0,maturetime=0 where requestid in (select requestid from localblockonchained where hid=?);", hid);
}

void DBmgr::RecordMsgInfo(uint64 msgsize, string function, string toPeer) {
    if (!bRecord)
        return;

    time_t now = time(nullptr);
    int64 timecircle = now / NEXTBUDDYTIME;
    exec("insert into sendmsginfo(msgsize,sendtime,timecircle,function,to_id) values(?,?,?,?,?);",
        msgsize,
        (uint64)now,
        timecircle,
        function.c_str(),
        toPeer.c_str());
}

void DBmgr::initOnChainState(uint64 hid)
{
    exec("update localblockonchained set hid=0,chain_num=0,id=0 where hid=?", hid);
}

void DBmgr::rehandleOnChainState(uint64 hid)
{
    exec("update localblockonchained set hid=0,chain_num=0,id=0 where hid>=?", hid);
}

bool DBmgr::getRequestID(const string &batchid, string &requestid)
{
    bool isfound = false;
    query("SELECT requestid FROM batchonchained WHERE batchid = ? ; ",
        [this, &requestid, &isfound](CppSQLite3Query & q) {
        requestid = q.getStringField("requestid");
        isfound = true;
    }, batchid.c_str());

    return isfound;
}

int DBmgr::getRequestIDs(vector<string> &requestIDvec)
{
    try {
        query("SELECT requestid FROM batchonchained WHERE succeed=0 AND retry<10 order by ctime LIMIT 10;",
            [&requestIDvec](CppSQLite3Query & q) {
            requestIDvec.push_back(q.getStringField("requestid"));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateSucceedRequestIDs(const string &requestid)
{
    try {
        exec("UPDATE batchonchained SET succeed=1 WHERE requestid=?;", requestid);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getBatchOnChainData(const string &requestid, string &data)
{
    try {
        query("SELECT data FROM batchonchained WHERE requestid=?;",
            [&data](CppSQLite3Query & q) {
            int len;
            const unsigned char * p = q.getBlobField("data", len);
            data.assign((char*)p, len);
        }, requestid);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

bool DBmgr::getOnChainStateFromRequestID(const string &requestid, T_LOCALBLOCKADDRESS &addr)
{
    bool isfound = false;
    addr.hid = UINT64_MAX;
    query("SELECT hid,chain_num,id FROM localblockonchained WHERE requestid = ? ; ",
        [this, &addr, &isfound](CppSQLite3Query & q) {
        addr.hid = q.getInt64Field("hid");
        addr.chainnum = q.getIntField("chain_num");
        addr.id = q.getIntField("id");
        isfound = true;
    }, requestid.c_str());

    return isfound;
}

bool DBmgr::isBlockExisted(uint64 hid)
{
    int num = 0;
    query("SELECT count(*) as num FROM hyperblock WHERE id = ? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    },
        hid);

    return num != 0;
}

int DBmgr::dbError(const char * funcname, int line, CppSQLite3Exception& ex)
{
    char errbuf[64] = { 0 };
    std::snprintf(errbuf, 64, "Exception in %s(%d): (%d)%s", funcname,
        line,
        ex.errorCode(),
        ex.errorMessage());
    g_daily_logger->error(errbuf);
    g_console_logger->error(errbuf);

    return ex.errorCode();
}

bool DBmgr::isHeaderIndexExisted(uint64 hid)
{
    int num = 0;
    query("SELECT count(*) as num FROM headerindex WHERE id = ? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    },
        hid);

    return num != 0;
}

int DBmgr::getHeaderIndexRecordNumber()
{
    try {
        CppSQLite3Statement stmt;
        std::string sql = "SELECT count(id) as total FROM headerindex";
        //std::string sql = "SELECT max(rowid) as total FROM headerindex";

        stmt = _db->compileStatement(sql.c_str());

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()) {
            return query.getIntField("total");
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

//bool DBmgr::isHeaderExistedbyHash(T_SHA256 hash)
//{
//    int num = 0;
//    query("SELECT count(*) as num FROM header WHERE headerhash = ? ; ",
//        [this, &num](CppSQLite3Query & q) {
//        num = q.getIntField("num");
//    }, hash.toHexString());
//
//    return num != 0;
//}

int DBmgr::getHeadersByID(std::map<T_SHA256,T_HYPERBLOCKHEADER> &headermap, uint64 nStartHyperID, uint64 nEndHyperID)
{
    try {
        query("SELECT * FROM header WHERE id>=? AND id<=? order by id;",
            [&headermap](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_SHA256 headerhash;
                T_HYPERBLOCKHEADER header;
                headerhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> header;
                headermap[headerhash] = header;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }

        }, nStartHyperID, nEndHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::getHeadersByID(std::list<T_HYPERBLOCKHEADER> &headerlist, uint64 nStartHyperID, uint64 nEndHyperID)
{
    try {
        query("SELECT header FROM header WHERE id>=? AND id<=? order by id;",
            [&headerlist](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_HYPERBLOCKHEADER header;
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> header;
                headerlist.emplace_back(header);
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }

        }, nStartHyperID, nEndHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::getHeaderByHash(T_HYPERBLOCKHEADER &header, uint64 hid, const T_SHA256& headerhash)
{
    try {
        query("SELECT header FROM header WHERE id=? AND headerhash=?;",
            [&header](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> header;
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }

        }, hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getFurcatedHeaderHash(uint64 hid, const T_SHA256& headerhash, vector<T_SHA256> &headerhashvec)
{
    try {
        query("SELECT headerhash FROM header WHERE id=? AND headerhash!=?;",
            [&headerhashvec](CppSQLite3Query & q) {
            T_SHA256 hhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            headerhashvec.push_back(hhash);
        }, hid, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::updateSingleHeaderInfo(const T_SINGLEHEADER& singleheader)
{
    try {
        exec("insert or replace into singleheaders(id,headerhash,preheaderhash,from_id) values(?,?,?,?)",
            singleheader.id,
            singleheader.headerhash.toHexString(),
            singleheader.preheaderhash.toHexString(),
            singleheader.from_id);

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getAllSingleHeaderInfo(multimap<uint64, T_SINGLEHEADER> &singleheadermap)
{
    try {
        query("SELECT * FROM singleheaders;",
            [&singleheadermap](CppSQLite3Query & q) {
            T_SINGLEHEADER singleheader;

            singleheader.id = q.getInt64Field("id");
            singleheader.headerhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            singleheader.preheaderhash = CCommonStruct::StrToHash256(string(q.getStringField("preheaderhash")));
            singleheader.from_id = q.getStringField("from_id");

            singleheadermap.insert(make_pair(singleheader.id, std::move(singleheader)));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::updateHeaderInfo(const uint64 hid, const T_SHA256& headerhash, const T_HYPERBLOCKHEADER& header)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << header;
        string headerstring = ssBuf.str();

        exec("insert or replace into header(id,headerhash,header) values(?,?,?)",
            hid,
            headerhash.toHexString(),
            headerstring);

    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return -1;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getHeaderIndex(MAP_T_HEADERINDEX& headerindexmap, int page, int size)
{
    int ret = 0;

    try
    {
        CppSQLite3Statement stmt;
        std::string sql;
        if (page == -1) {
            sql = "SELECT * FROM headerindex ORDER BY id;";
        }
        else {
            sql = "SELECT * FROM headerindex ORDER BY id LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1) {
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof())
        {
            T_HEADERINDEX headerindex;

            headerindex.id = query.getInt64Field("id");
            headerindex.prehash = CCommonStruct::StrToHash256(string(query.getStringField("prehash")));
            headerindex.headerhash = CCommonStruct::StrToHash256(string(query.getStringField("headerhash")));
            headerindex.preheaderhash = CCommonStruct::StrToHash256(string(query.getStringField("preheaderhash")));
            headerindex.ctime = query.getInt64Field("ctime");
            headerindex.weight = query.getIntField("weight");
            headerindex.total_weight = query.getInt64Field("total_weight");
            headerindex.from_id = query.getStringField("from_id");

            headerindexmap[headerindex.headerhash] = headerindex;

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getAllHeaderIndex(MAP_T_HEADERINDEX &headerindexmap)
{
    try {
        query("SELECT * FROM headerindex ORDER BY id;",
            [&headerindexmap](CppSQLite3Query & q) {
            T_HEADERINDEX headerindex;

            headerindex.id = q.getInt64Field("id");
            headerindex.prehash = CCommonStruct::StrToHash256(string(q.getStringField("prehash")));
            headerindex.headerhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            headerindex.preheaderhash = CCommonStruct::StrToHash256(string(q.getStringField("preheaderhash")));
            headerindex.ctime = q.getInt64Field("ctime");
            headerindex.weight = q.getIntField("weight");
            headerindex.total_weight = q.getInt64Field("total_weight");
            headerindex.from_id = q.getStringField("from_id");

            headerindexmap[headerindex.headerhash] = headerindex;
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getHeaderIndexByHash(T_HEADERINDEX &headerindex, const T_SHA256& headerhash)
{
    try {
        query("SELECT * FROM headerindex WHERE headerhash=?;",
            [&headerindex](CppSQLite3Query & q) {
            headerindex.id = q.getInt64Field("id");
            headerindex.prehash = CCommonStruct::StrToHash256(string(q.getStringField("prehash")));
            headerindex.headerhash = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            headerindex.preheaderhash = CCommonStruct::StrToHash256(string(q.getStringField("preheaderhash")));
            headerindex.ctime = q.getInt64Field("ctime");
            headerindex.weight = q.getIntField("weight");
            headerindex.total_weight = q.getInt64Field("total_weight");
            headerindex.from_id = q.getStringField("from_id");
        }, headerhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateHeaderIndex(const T_HEADERINDEX& headerindex)
{
    try {
        exec("insert or replace into headerindex(id,headerhash,preheaderhash,prehash,ctime,weight,total_weight,from_id) values(?,?,?,?,?,?,?,?)",
            headerindex.id,
            headerindex.headerhash.toHexString(),
            headerindex.preheaderhash.toHexString(),
            headerindex.prehash.toHexString(),
            headerindex.ctime,
            headerindex.weight,
            headerindex.total_weight,
            headerindex.from_id);

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::SaveHyperblock(const T_HYPERBLOCK& hyperblock)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << hyperblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << hyperblock.body;
        string body = ssBuf.str();

        exec("insert or replace into hblocks(id,headerhash,hash,header,body) values(?,?,?,?,?)",
            hyperblock.GetID(),
            hyperblock.calculateHeaderHashSelf().toHexString(),
            hyperblock.GetHashSelf().toHexString(),
            header, body);
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return -1;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::SaveLocalblock(const T_LOCALBLOCK& localblock, uint64 hid, uint16 chainnum, const T_SHA256& hhash)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << localblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << localblock.body;
        string body = ssBuf.str();

        exec("insert or replace into lblocks(id,hid,chain_num,hhash,header,body) values(?,?,?,?,?,?)",
            localblock.GetID(), hid, chainnum, hhash.toHexString(), header, body);
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return -1;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getLocalBlocks(std::list<T_LOCALBLOCK> &queue, const T_SHA256& hhash)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM lblocks WHERE hhash=? order by chain_num;", [&queue](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_LOCALBLOCK localblock;
                uint64 nHyperID = q.getInt64Field("hid");
                localblock.SetChainNum(q.getIntField("chain_num"));
                localblock.SetPreHID(nHyperID - 1);
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                queue.emplace_back(localblock);
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
            catch (std::exception& e) {
                g_consensus_console_logger->error("{}", e.what());
            }
            catch (...) {
                g_consensus_console_logger->error("unknown exception occurs");
            }
        }, hhash.toHexString());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getLocalBlocks(std::list<T_LOCALBLOCK>& queue, const T_LOCALBLOCKADDRESS& addr)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM lblocks WHERE hid=? AND chain_num=? AND id=?;", [&queue](CppSQLite3Query& q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_LOCALBLOCK localblock;
                uint64 nHyperID = q.getInt64Field("hid");
                localblock.SetChainNum(q.getIntField("chain_num"));
                localblock.SetPreHID(nHyperID - 1);
                const unsigned char* p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                queue.emplace_back(localblock);
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
            catch (std::exception& e) {
                g_consensus_console_logger->error("{}", e.what());
            }
            catch (...) {
                g_consensus_console_logger->error("unknown exception occurs");
            }
            }, addr.hid, addr.chainnum, addr.id);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}
