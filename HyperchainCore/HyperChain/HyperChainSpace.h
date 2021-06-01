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

#pragma once

#include "headers/commonstruct.h"
#include "utility/MutexObj.h"
#include "node/MsgHandler.h"

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include "../Types.h"
using namespace std;
using std::chrono::system_clock;

#define MATURITY_SIZE    50
#define MAX_BLOCKHEADER_NUMS  1088
#define MAX_BLOCKHEADERHASH_NUMS  65536
#define INFORMALNET_GENESISBLOCKID  48600
#define INFORMALNET_GENESISBLOCK_HEADERHASH CCommonStruct::StrToHash256("91bc676065c8613c130050e14c9fd9bd287501e934ac1b7f40894c9c9781c5c1")

typedef struct _headerinfo
{
    uint64 id;
    vector <uint16> section;
    vector <T_SHA256> hashMTRootList;
    system_clock::time_point sync_time = system_clock::now();
    bool ready = false;

    void Set(uint64 hid);
    void Set(vector <T_SHA256>& hashMTRootlist);

    bool IsSameChain(_headerinfo other);

}T_HEADERINFO, *T_PHEADERINFO;

typedef struct _chaininfo
{
    bool checked = false;
    T_HEADERINFO headerinfo;
    list<string> nodelist;
    map<uint64, T_SHA256> headerhash;
    uint64 sync_hash_hid = 0;
    system_clock::time_point sync_hash_time = system_clock::now();
    uint64 sync_header_hid = 0;
    system_clock::time_point sync_header_time = system_clock::now();
}T_CHAININFO, *T_PCHAININFO;

typedef struct _theaderhashinfo
{
    T_SHA256 headerhash;
    set<string> nodeids;
    _theaderhashinfo(T_SHA256 hash, string nodeid) {
        headerhash = hash;
        nodeids.insert(nodeid);
    }

    void PutNodeID(string nodeid) {
        nodeids.insert(nodeid);
        return;
    }

    T_SHA256 GetHeaderHash()const {
        return headerhash;
    }

    size_t GetVote()const {
        return nodeids.size();
    }

}T_HEADERHASHINFO, *T_PHEADERHASHINFO;

typedef list<T_HEADERHASHINFO> LIST_T_HEADERHASHINFO;
typedef LIST_T_HEADERHASHINFO::iterator ITR_LIST_T_HEADERHASHINFO;

typedef map<uint64, LIST_T_HEADERHASHINFO> MAP_T_UNCONFIRMEDHEADERHASH;
typedef MAP_T_UNCONFIRMEDHEADERHASH::iterator ITR_MAP_T_UNCONFIRMEDHEADERHASH;

typedef map<uint64, LIST_T_HYPERBLOCK> MAP_T_UNCONFIRMEDBLOCK;
typedef MAP_T_UNCONFIRMEDBLOCK::iterator ITR_MAP_T_UNCONFIRMEDBLOCK;

typedef map<string, LIST_T_HYPERBLOCKHEADER> MAP_T_UNCONFIRMEDBLOCKHEADER;
typedef MAP_T_UNCONFIRMEDBLOCKHEADER::iterator ITR_MAP_T_UNCONFIRMEDBLOCKHEADER;

enum class CHECK_RESULT :char {
    INVALID_DATA = 0,
    VALID_DATA,
    UNCONFIRMED_DATA,
    INCOMPATIBLE_DATA
};

class DBmgr;
class CHyperChainSpace
{
public:
    CHyperChainSpace(string nodeid);
    ~CHyperChainSpace() { stop(); }

    void start(DBmgr* db);
    void stop() {
        _isstop = true;
        _msghandler.stop();

        for (auto& t : m_threads) {
            t.join();
        }
        m_threads.clear();

        if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
            m_threadPullAppBlocks->join();
        }
    }

    void NoHyperBlock(uint64 hid, string nodeid);
    void NoHyperBlockHeader(uint64 hid, string nodeid);
    void NoHeaderHashMTRoot(uint64 hid, string nodeid);
    void NoHyperBlockHeaderHash(uint64 hid, string nodeid);
    void PutHyperBlock(T_HYPERBLOCK &hyperblock, string from_nodeid, vector<CUInt128> &multicastnodes);
    bool GetHyperBlockHeader(uint64 hid, uint16 range, vector<T_HYPERBLOCKHEADER>& blockheader);
    void PutHyperBlockHeaderList(vector<T_HYPERBLOCKHEADER>& blockheader, string from_nodeid);
    void PutHyperBlockHeader(T_HYPERBLOCKHEADER& blockheader, string from_nodeid);
    bool GetHyperBlockHeaderHash(uint64 hid, uint32 range, vector<T_SHA256> &vecheaderhash);
    bool GetHyperBlockHeaderHash(uint64 hid, T_SHA256 &headerhash);
    //void PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash);
    //void PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid);
    void PutHyperBlockHeaderHash(uint64 hid, uint32 range, vector<T_SHA256>& headerhash, string from_nodeid);
    void GetHyperBlockHealthInfo(map<uint64, uint32> &out_BlockHealthInfo);
    int GetRemoteHyperBlockByID(uint64 globalHID);
    int GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid);
    int BatchGetRemoteHyperBlockByID(uint64 globalHID, uint32 nblkcnt, const string& nodeid);
    int GetRemoteHyperBlockByPreHash(uint64 globalHID, std::set<CUInt128>& activeNodes);
    int GetRemoteHyperBlockByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid, T_SHA256 headerhash, std::set<CUInt128>& activeNodes);
    int GetRemoteHeaderHash(uint64 globalHID, uint32 range);
    int GetRemoteBlockHeader(uint64 startHID, uint16 range, string nodeid);
    int GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr);

    void GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app);

    bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA);
    bool GetLocalBlocksByHIDDirectly(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA);
    //bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA);

    bool GetLocalBlockPayload(const T_LOCALBLOCKADDRESS& addr, string& payload);
    bool GetLocalBlock(const T_LOCALBLOCKADDRESS& addr, T_LOCALBLOCK& localblock);
    bool GetLocalBlockByHash(T_SHA256 hash, T_LOCALBLOCK& localblock);
    bool GetLocalBlockByHeaderHash(T_SHA256 headerhash, T_LOCALBLOCK& localblock);
    bool GetLocalBlocksByAddress(const T_LOCALBLOCKADDRESS& addr, std::list<T_LOCALBLOCK>& localblocks);
    bool GetLocalBlockByHyperBlockHash(const T_LOCALBLOCKADDRESS& addr, const T_SHA256& hhash, T_LOCALBLOCK& localblock);


    bool getHyperBlock(uint64 hid, T_HYPERBLOCK &hyperblock);
    bool getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock);
    bool getHyperBlockByPreHash(uint64 hid, T_SHA256 &prehash, T_HYPERBLOCK &hyperblock);
    bool updateHyperBlockCache(T_HYPERBLOCK &hyperblock);
    void PullHyperDataByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid);

    bool CheckHyperBlockHash(uint64 hid, const T_SHA256& hash);
    void SaveHyperblock(const T_HYPERBLOCK &hyperblock);

    void GetHyperChainData(map<uint64, set<string>>& chainspacedata);
    void GetHyperChainShow(map<string, string>& chainspaceshow);
    void GetLocalHIDsection(vector <string>& hidsection);
    T_SHA256 GetLatestHyperBlockHash() { return m_LatestHyperBlock.GetHashSelf(); }
    size_t GetLocalChainIDSize();

    uint64 GetMaxBlockID();
    void GetLatestHyperBlockIDAndHash(uint64 &id, T_SHA256 &hash, uint64& ctm);
    bool IsLatestHyperBlockReady();
    void GetLatestHyperBlock(T_HYPERBLOCK& hyperblock);
    void GetLocalHIDs(uint64 nStartHID, set<uint64>& setHID);
    void GetMulticastNodes(vector<CUInt128> &MulticastNodes);
    void AnalyzeChainSpaceData(string strbuf, string nodeid);
    bool GetLocalChainSpaceData(string& msgbuf);
    bool GetHeaderHashMTRootData(uint64 headerid, string& msgbuf);
    void AnalyzeHeaderHashMTRootData(string strbuf, string nodeid);

    uint64 GetLocalLatestHID() { return m_localHID.empty() ? UINT64_MAX : *m_localHID.rbegin(); }
    uint64 GetHeaderHashCacheLatestHID();
    uint64 GetGlobalLatestHyperBlockNo();

    std::string MQID()
    {
        return _msghandler.details();
    }


private:
    void CheckLocalData();
    void CheckLocalHeaderReady();
    void SyncHyperBlockData();
    void SyncAllHyperBlockData();
    void loadHeaderIDCache();
    void loadHyperBlockCache();
    void loadHyperBlockIDCache();
    void loadHyperBlockHashCache();
    void CollatingChainSpaceDate();
    void PullHyperDataByHID(uint64 hid, string nodeid);
    void BatchPullHyperDataByHID(uint64 hid, uint32 ncnt, const string &nodeid);
    void SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock);
    void RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash);
    bool isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash);
    void SyncBlockHeaderData(std::set<CUInt128> &activeNodes);
    void SyncBlockHeaderData(std::set<CUInt128> &activeNodes, T_CHAININFO &chainInfo, bool isBestChain);
    void SyncBlockHeaderData(std::set<CUInt128> &activeNodes, T_CHAININFO &chainInfo, uint64 headerHID);
    bool isAcceptHyperBlock(uint64 blockNum, const T_HYPERBLOCK &remoteHyperBlock, bool isAlreadyExisted);
    bool isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock, uint64 blockid, uint64 blockcount, const T_SHA256& hhashself);
    bool isBetterThanLocalChain(const T_HEADERINDEX &localHeaderIndex, const T_HEADERINDEX &HeaderIndex);
    void SplitString(const string& s, vector<std::string>& v, const std::string& c);
    bool SaveHeaderListIndex(map<pair<uint64, T_SHA256>, T_HYPERBLOCKHEADER>& headerMap, string from_nodeid, bool &Flag);
    bool SaveHeaderIndex(T_SHA256 headerhash, T_SHA256 preheaderhash, T_HYPERBLOCKHEADER header, string from_nodeid, bool &Flag);
    uint64 CheckDiffPos(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhash, T_HEADERINFO& headerinfo);
    T_SHA256 GenerateHeaderHashMTRoot(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhashmap);
    void GenerateHeaderHashMTRootList(vector<uint16>& location, vector<T_SHA256>& hashMTRootlist, map<uint64, T_SHA256>& headerhashmap);
    void GenerateHIDSection(const std::set<uint64>& localHID, vector <string>& localHIDsection);
    int  GetHeaderByHash(T_HYPERBLOCKHEADER& header, uint64 hid, const T_SHA256& headerhash);
    void removeFromSingleHeaderMap(uint64 hid, T_SHA256 headerhash);
    void DeleteSingleHeader(uint64 hid, T_SHA256 headerhash);
    bool isInSingleHeaderMap(uint64 hid, T_SHA256 headerhash);
    bool SwitchLocalBestChain();
    uint64 GetMaxHeaderID();

    void startMQHandler();
    CHECK_RESULT CheckDependency(const T_HYPERBLOCK &hyperblock, string nodeid);
    void PutHyperBlockHeader(vector<T_HYPERBLOCKHEADER>& blockheaders, string from_nodeid, bool &isSingle);
    void publishNewHyperBlock(uint32_t hidFork, const T_HYPERBLOCK &hyperblock, bool isLatest, bool needSwitch);
    void PullHeaderHashMTRoot(uint64 hid, string nodeid);
    void PullHeaderHash(uint64 hid, uint32 range, string nodeid);
    void PullBlockHeaderData(uint64 hid, uint16 range, string nodeid);
    //int  GetRemoteBlockHeader(uint64 startHID, uint16 range);
    void DispatchService(void *wrk, zmsg *msg);
    void PullHeaderHashMTRootInfo();
    void DealwithChainInfo();
    void PullChainSpace();
    void PullHeaderHashInfo();
    void PullBlockHeader();
    void PullHyperBlock();
    void PullAllHyperBlock();
    void CollatingChainSpace();

private:

    bool m_FullNode = false;

    string m_mynodeid;
    uint64 m_gensisblockID = 0;
    T_SHA256 m_gensisblockHeaderhash;
    std::set<uint64> m_localHID;
    vector <string> m_localHIDsection;
    vector<CUInt128> m_MulticastNodes;

    DBmgr* m_db = nullptr;

    uint64 sync_hid = 0;
    system_clock::time_point sync_time;

    bool m_LatestBlockReady = false;
    T_HYPERBLOCK m_LatestHyperBlock;
    std::atomic<uint64> uiMaxBlockNum = 0;
    std::atomic<uint64> uiGlobalMaxBlockNum = 0;
    std::atomic<uint64> uiCollateMaxBlockNum = 0;

    map<uint64, T_SHA256> m_BlockHashMap;

    bool m_localHeaderReady = false;
    std::atomic<uint64> uiMaxHeaderID = 0;

    std::set<uint64> m_localHeaderID;
    vector <string> m_localHeaderIDsection;
    map<uint64, T_SHA256> m_HeaderHashMap;

    vector<list<pair<uint64, T_SHA256>>> m_BlocksHeaderHash;

    vector<list<pair<uint64, T_SHA256>>>::iterator m_HashChain;

    MAP_T_HEADERINDEX m_HeaderIndexMap;

    map<uint64, std::set<string>> m_ReqHeaderHashNodes;

    multimap<uint64, T_SINGLEHEADER> m_SingleHeaderMap;

    MAP_T_UNCONFIRMEDBLOCK m_UnconfirmedBlockMap;

    MAP_T_UNCONFIRMEDHEADERHASH m_UnconfirmedHashMap;

    bool m_ChainspaceReady = false;
    map<uint64, std::set<string>> m_Chainspace;

    map<uint64, uint32> m_BlockHealthInfo;

    map<string, string> m_chainspaceshow;

    T_HEADERINFO m_minheaderinfo;
    map<string, T_HEADERINFO> m_chainspaceheader;
    map<string, uint64> m_chainspaceheaderID;
    map<string, uint64> m_chainspacesyncheaderID;
    bool m_HaveFixedData = false;
    bool m_ChainInfoReady = false;
    std::set<pair<uint64, T_SHA256>> m_chainheaderhashSet;
    map<uint8, T_CHAININFO> m_chainInfoMap;
    uint8 m_bestchainID = UINT8_MAX;

    std::list<thread>  m_threads;
    unique_ptr<thread> m_threadPullAppBlocks;
    bool _isstop = false;


    MsgHandler _msghandler;
    zmq::socket_t *_hyperblock_pub = nullptr;

    enum class SERVICE : short
    {
        GetMaxBlockID = 1,
        GetLatestHyperBlockIDAndHash,
        IsLatestHyperBlockReady,
        GetLatestHyperBlock,
        GetHyperBlockByID,
        GetHyperBlockByHash,
        GetHyperBlockByPreHash,
        CheckHyperBlockHash,
        GetLocalBlocksByHID,
        //GetLocalBlockPayload,
        GetLocalBlockByAddr,
        GetLocalBlockByHash,
        GetLocalBlockByHeaderHash,
        GetLocalHIDs,

        GetLocalChainSpaceData,
        AnalyzeChainSpaceData,
        GetHeaderHashMTRootData,
        AnalyzeHeaderHashMTRootData,
        UpdateHyperBlockCache,
        GetMulticastNodes,
        SaveHyperblock,
        PutHyperBlock,
        NoHyperBlock,

        GetHyperChainShow,
        GetHyperChainData,
        GetLocalHIDsection,
        GetLocalChainIDSize,
        GetHyperBlockHealthInfo,
        GetHeaderHashCacheLatestHID,
        GetGlobalLatestHyperBlockNo,

        GetRemoteHyperBlockByID,
        GetRemoteHyperBlockByIDFromNode,
        BatchGetRemoteHyperBlockByIDFromNode,
        GetRemoteBlockHeaderFromNode,
        GetHyperBlockHeaderHash,
        PutHyperBlockHeaderHash,
        NoHyperBlockHeaderHash,
        GetHyperBlockHeader,
        PutHyperBlockHeader,
        PutHyperBlockHeaderList,
        NoHyperBlockHeader,
    };
};
