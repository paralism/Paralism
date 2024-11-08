/*Copyright 2016-2023 hyperchain.net (Hyperchain)

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
#include "newLog.h"
#include "HyperChainSpace.h"
#include "node/Singleton.h"
#include "hyperblockTask.hpp"
#include "headerhashTask.hpp"
#include "blockheaderTask.hpp"
#include "PullChainSpaceTask.hpp"
#include "ApplicationChainTask.hpp"
#include "db/HyperchainDB.h"
#include "db/dbmgr.h"
#include "node/defer.h"
#include "consensus/buddyinfo.h"
#include "AppPlugins.h"
#include <algorithm>
#include <thread>
#include <cmath>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

void GetHeaderIDSection(uint64 headerHID, vector<uint16>& locationSection);
uint64 BinarySearch(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhashmap1, map<uint64, T_SHA256>& headerhashmap2);


void _headerinfo::Set(uint64 hid)
{
    id = hid;
    GetHeaderIDSection(id, section);
}

void _headerinfo::Set(vector <T_SHA256>& hashMTRootlist)
{
    if (section.size() == hashMTRootlist.size())
        hashMTRootList = hashMTRootlist;
}

bool _headerinfo::IsSameChain(_headerinfo other)
{
    if (id == other.id) {
        if (section.size() != other.section.size())
            return false;

        for (size_t i = 0; i != section.size(); ++i) {
            if (section[i] == other.section[i] && hashMTRootList[i] != other.hashMTRootList[i])
                return false;
        }

        return true;
    }

    size_t j = min(section.size(), other.section.size());
    for (size_t k = 0; k != j; ++k) {
        if (section[0] != other.section[0])
            return false;

        if (section[k] == other.section[k] && hashMTRootList[k] != other.hashMTRootList[k])
            return false;
    }

    return true;
}


CHyperChainSpace::CHyperChainSpace(string nodeid)
{
    m_mynodeid = nodeid;

    HC_MAIN_PROGRAM_ARGS;

    if (mapHCArgs.count("-fullnode"))
        m_FullNode = true;
}

void CHyperChainSpace::startMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&CHyperChainSpace::DispatchService, this, std::placeholders::_1, std::placeholders::_2);

    _msghandler.registerWorker(HYPERCHAINSPACE_SERVICE, fwrk);
    _msghandler.registerTaskWorker(HYPERCHAINSPACE_T_SERVICE);

    //HCE: Create sockets used internally by hyperchainspace
    _msghandler.registerTimer(29 * 1000, std::bind(&CHyperChainSpace::PullChainSpace, this));
    _msghandler.registerTimer(20 * 1000, std::bind(&CHyperChainSpace::PullHeaderHashMTRootInfo, this));
    _msghandler.registerTimer(20 * 1000, std::bind(&CHyperChainSpace::DealwithChainInfo, this));
    _msghandler.registerTimer(20 * 1000, std::bind(&CHyperChainSpace::PullHeaderHashInfo, this));
    _msghandler.registerTimer(21 * 1000, std::bind(&CHyperChainSpace::PullBlockHeader, this));
    _msghandler.registerTimer(19 * 1000, std::bind(&CHyperChainSpace::PullHyperBlock, this));
    _msghandler.registerTimer(3 * 1000, std::bind(&CHyperChainSpace::PullHyperBlockRepeatly, this));
    if (m_FullNode) {
        _msghandler.registerTimer(300 * 1000, std::bind(&CHyperChainSpace::PullAllHyperBlock, this));
    }
    //HCE: don't clear the expired hyper block
    //_msghandler.registerTimer(36 * 3600 * 1000, std::bind(&CHyperChainSpace::CollatingChainSpace, this));

    _hyperblock_pub = new zmq::socket_t(*g_inproc_context, ZMQ_PUB);
    _hyperblock_pub->bind(HYPERBLOCK_PUB_SERVICE);

    _msghandler.registerTaskType<PullChainSpaceTask>(TASKTYPE::HYPER_CHAIN_SPACE_PULL);
    _msghandler.registerTaskType<PullChainSpaceRspTask>(TASKTYPE::HYPER_CHAIN_SPACE_PULL_RSP);
    _msghandler.registerTaskType<GetHyperBlockByNoReqTask>(TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ);
    _msghandler.registerTaskType<GetHyperBlockByPreHashReqTask>(TASKTYPE::GET_HYPERBLOCK_BY_PREHASH_REQ);
    _msghandler.registerTaskType<GetHeaderHashMTRootReqTask>(TASKTYPE::GET_HEADERHASHMTROOT_REQ);
    _msghandler.registerTaskType<GetHeaderHashMTRootRspTask>(TASKTYPE::GET_HEADERHASHMTROOT_RSP);
    _msghandler.registerTaskType<GetHeaderHashReqTask>(TASKTYPE::GET_HEADERHASH_REQ);
    _msghandler.registerTaskType<GetHeaderHashRspTask>(TASKTYPE::GET_HEADERHASH_RSP);
    _msghandler.registerTaskType<GetBlockHeaderReqTask>(TASKTYPE::GET_BLOCKHEADER_REQ);
    _msghandler.registerTaskType<GetBlockHeaderRspTask>(TASKTYPE::GET_BLOCKHEADER_RSP);
    _msghandler.registerTaskType<BoardcastHyperBlockTask>(TASKTYPE::BOARDCAST_HYPER_BLOCK);
    _msghandler.registerTaskType<NoHyperBlockRspTask>(TASKTYPE::NO_HYPERBLOCK_RSP);
    _msghandler.registerTaskType<NoBlockHeaderRspTask>(TASKTYPE::NO_BLOCKHEADER_RSP);
    _msghandler.registerTaskType<NoBlockHeaderRspTask>(TASKTYPE::NO_HEADERHASHMTROOT_RSP);

    SERVICEForEach([this](SERVICE i) {
            m_chainactioncoststt.AddAction((int32_t)i, SERVICEValueName(i));
        });

    _msghandler.enableStatis(true);
    _msghandler.start("CHyperChainSpace");
    cout << "CHyperChainSpace MQID: " << MQID() << endl;
}

void CHyperChainSpace::GetHyperBlockHealthInfo(map<uint64, uint32>& out_BlockHealthInfo)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty())
            return;

        out_BlockHealthInfo.clear();
        for (auto& elem : m_Chainspace) {
            out_BlockHealthInfo[elem.first] = elem.second.size();
        }
        return;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHealthInfo, &out_BlockHealthInfo);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

uint64 CHyperChainSpace::GetGlobalLatestHyperBlockNo()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiGlobalMaxBlockNum;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetGlobalLatestHyperBlockNo);

        uint64 hid = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, hid);
            delete rspmsg;
        }

        return hid;
    }
}

void getPayloads(T_HYPERBLOCK& h, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPayload)
{
    uint16 uiChainNum = 1;

    for (auto& childchain : h.GetChildChains()) {
        for (auto& block : childchain) {
            T_APPTYPE appt = block.GetAppType();
            if (block.GetAppType() == app) {
                T_LOCALBLOCKADDRESS address;
                address.set(h.GetID(), uiChainNum, block.GetID());
                vecPayload.emplace_back(address, block.GetPayLoad());
            }
        }
        uiChainNum++;
    }

}


bool CHyperChainSpace::GetLocalBlocksByHIDDirectly(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA)
{
    T_HYPERBLOCK h;

    if (!CHyperchainDB::getHyperBlock(h, globalHID)) {
        return false;
    }

    hhash = h.GetHashSelf();
    getPayloads(h, app, vecPA);
    return true;
}

bool CHyperChainSpace::GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        T_HYPERBLOCK h;
        if (!getHyperBlock(globalHID, h)) {
            return false;
        }
        hhash = h.GetHashSelf();
        getPayloads(h, app, vecPA);
        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalBlocksByHID, globalHID, &app, &hhash, &vecPA);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

//bool CHyperChainSpace::GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA)
//{
//    T_SHA256 hhash;
//    return GetLocalBlocksByHID(globalHID, app, hhash, vecPA);
//}

//HCE: get the application block path(T_LOCALBLOCKADDRESS) from low_addr to high_addr
void CHyperChainSpace::GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app)
{
    //HCE: the best method is get the virtual path, then get the necessary local block.
    //if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
    //    //already pulled
    //    m_threadPullAppBlocks->join();
    //}
    //m_threadPullAppBlocks.reset(new std::thread(&CHyperChainSpace::PullAppDataThread, this, low_addr, high_addr, app));
}


int CHyperChainSpace::GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr)
{
    if (!m_localHID.count(addr.hid)) {
        //HCE: fix me: get only a local block, not a whole hyper block
        return GetRemoteHyperBlockByID(addr.hid);
    }
    return 0;
}

int CHyperChainSpace::GetRemoteBlockHeader(uint64 startHID, uint16 range, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        PullBlockHeaderData(startHID, range, nodeid);
        g_daily_logger->info("PullBlockHeaderData() starthid: [{}], range: [{}], nodeid: [{}]", startHID, range, nodeid);
        g_console_logger->info("PullBlockHeaderData() starthid: [{}], range: [{}], nodeid: [{}]", startHID, range, nodeid);
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteBlockHeaderFromNode, startHID, range, nodeid);
        return 0;
    }
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        g_daily_logger->info("GetRemoteHyperBlockByID, blockid: [{}], nodeid: [{}]", globalHID, nodeid);
        PullHyperDataByHID(globalHID, nodeid);
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteHyperBlockByIDFromNode, globalHID, nodeid);
        return 0;
    }
}


int CHyperChainSpace::BatchGetRemoteHyperBlockByID(uint64 globalHID, uint32 nblkcnt, const string& nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        BatchPullHyperDataByHID(globalHID, nblkcnt, nodeid);
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::BatchGetRemoteHyperBlockByIDFromNode, globalHID, nblkcnt, nodeid);
        return 0;
    }
}


int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty() || m_Chainspace.find(globalHID) == m_Chainspace.end())
            return -1;

        //HCE: Get the list of active nodes
        std::set<CUInt128> ActiveNodes;
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->GetAllNodes(ActiveNodes);
        if (ActiveNodes.empty()) {
            g_daily_logger->error("GetRemoteHyperBlockByID failed! ActiveNodes empty!");
            g_console_logger->error("GetRemoteHyperBlockByID failed! ActiveNodes empty!");
            return -1;
        }

        return GetRemoteHyperBlockByPreHash(globalHID, ActiveNodes);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteHyperBlockByID, globalHID);

        int ret = -1;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

int CHyperChainSpace::GetRemoteHyperBlockByID_UntilSuccess(uint64 startHID, uint64 endHID, const string& nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        for (uint64 i = startHID; i < endHID; ++i) {
            if (m_mapPullingHyperBlock.count(i) == 0) {
                PullHB_RECORD record;
                record.firstrequest = std::time(nullptr);
                record.lastrequest = record.firstrequest;
                m_mapPullingHyperBlock.insert({ i, record });
            }
        }
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteHyperBlockByID_UntilSuccess, startHID, endHID, nodeid);
        return 0;
    }
}


int CHyperChainSpace::GetRemoteHyperBlockByPreHash(uint64 syncHID, std::set<CUInt128>& activeNodes)
{
    if (m_Chainspace.empty() || m_Chainspace.find(syncHID) == m_Chainspace.end()) {
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in m_Chainspace", syncHID);
        g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in m_Chainspace", syncHID);
        return -1;
    }

    T_SHA256 headerhash;
    if (!GetHyperBlockHeaderHash(syncHID, headerhash)) {
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! GetHyperBlockHeaderHash, hid:[{}]", syncHID);
        g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! GetHyperBlockHeaderHash, hid:[{}]", syncHID);
        return -1;
    }

    if (m_HeaderIndexMap.find(headerhash) == m_HeaderIndexMap.end()) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}], headerhash: [{}] in m_HeaderIndexMap", syncHID, HeaderHash);
        g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}], headerhash: [{}] in m_HeaderIndexMap", syncHID, HeaderHash);
        return -1;
    }

    T_SHA256 hhash = m_HeaderIndexMap[headerhash].headerhash;
    T_SHA256 prehash = m_HeaderIndexMap[headerhash].prehash;
    string nodeid = m_HeaderIndexMap[headerhash].from_id;

    if (m_BlockHashMap.find(syncHID) != m_BlockHashMap.end() &&
        m_BlockHashMap.find(syncHID - 1) != m_BlockHashMap.end() &&
        m_BlockHashMap[syncHID - 1] == prehash) {
        //HCE: HyperBlock(syncHID) already exists
        return 0;
    }

    int ret = GetRemoteHyperBlockByPreHash(syncHID, prehash, nodeid, hhash, activeNodes);
    if (ret < 0) {
        char PreHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(PreHash, prehash);
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! hid: {}, prehash: [{}]", syncHID, PreHash);
        g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! hid: {}, prehash: [{}]", syncHID, PreHash);
    }

    return ret;
}

int CHyperChainSpace::GetRemoteHyperBlockByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid, T_SHA256 headerhash, std::set<CUInt128>& activeNodes)
{
    bool inSyncBlockMap = false;
    system_clock::time_point synctime;
    system_clock::time_point curr;
    using seconds = std::chrono::duration<double, ratio<1>>;
    seconds timespan;

    if (!m_SyncBlockMap.empty() && m_SyncBlockMap.find(globalHID) != m_SyncBlockMap.end()) {
        inSyncBlockMap = true;
        synctime = m_SyncBlockMap[globalHID].sync_block_time;
        curr = system_clock::now();
        timespan = std::chrono::duration_cast<seconds>(curr - synctime);

        if (timespan.count() < 3) {
            //HCE: the same HID only sync once in 3 seconds
            return 0;
        }
    } 

    if (m_Chainspace.empty() || m_Chainspace.find(globalHID) == m_Chainspace.end()) {
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in m_Chainspace", globalHID);
        g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in m_Chainspace", globalHID);
        return -1;
    }

    if (activeNodes.empty()) {
        g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! ActiveNodes empty!");
        g_console_logger->error("GetRemoteHyperBlockByPreHash failed! ActiveNodes empty!");
        return -1;
    }

    if (inSyncBlockMap) {
        bool findnew = false;
        T_SYNCBLOCKINFO sinfo = m_SyncBlockMap[globalHID];
        for (set<string>::iterator iter = m_Chainspace[globalHID].begin(); iter != m_Chainspace[globalHID].end(); iter++) {
            //HC: 检查该nodeid是否在活跃节点列表中
            if (!activeNodes.count(CUInt128(*iter)))
                continue;

            if (find(sinfo.nodelist.begin(), sinfo.nodelist.end(), *iter) == sinfo.nodelist.end()) {
                findnew = true;

                PullHyperDataByPreHash(globalHID, prehash, *iter);

                sinfo.sync_block_time = system_clock::now();
                sinfo.nodelist.push_back(*iter);
                sinfo.retry_times++;

                m_SyncBlockMap[globalHID] = std::move(sinfo);

                return 0;
            }
        }

        if (!findnew) {
            //HC: 已经向所有的活跃邻居节点都发送过同步超块请求。当间隔超过10秒钟后，清空缓存数据，重新发送请求。
            //HCE: Synchronous hyperblock requests have been sent to all active neighbor nodes.
            //HCE: When the interval exceeds 10 seconds, clear the cached data and resend the request.
            if (timespan.count() < 10)
                return 0;

            m_SyncBlockMap.erase(globalHID);
        }
    }

    if (!nodeid.empty() && nodeid != "myself" && 
        activeNodes.count(CUInt128(nodeid)) && 
        m_Chainspace[globalHID].count(nodeid)) {
        PullHyperDataByPreHash(globalHID, prehash, nodeid);

        T_SYNCBLOCKINFO sinfo;
        sinfo.nodelist.push_back(nodeid);
        sinfo.retry_times++;

        m_SyncBlockMap[globalHID] = std::move(sinfo);

        return 0;
    }

    if (!m_chainInfoMap.empty()) {
        auto iter = m_chainInfoMap.begin();
        for (; iter != m_chainInfoMap.end(); iter++) {
            map<uint64, T_SHA256> hashmap = iter->second.headerhash;
            auto itr = hashmap.find(globalHID);
            if (itr == hashmap.end() || itr->second != headerhash)
                continue;

            for (auto ir : iter->second.nodelist) {
                if (activeNodes.count(CUInt128(ir)) && m_Chainspace[globalHID].count(ir)) {
                    PullHyperDataByPreHash(globalHID, prehash, ir);

                    T_SYNCBLOCKINFO sinfo;
                    sinfo.nodelist.push_back(ir);
                    sinfo.retry_times++;

                    m_SyncBlockMap[globalHID] = std::move(sinfo);

                    return 0;
                }
            }
        }
    }

    for (set<string>::iterator iter = m_Chainspace[globalHID].begin(); iter != m_Chainspace[globalHID].end(); iter++) {
        //HCE: Check whether the nodeid is in the list of active nodes
        if (activeNodes.count(CUInt128(*iter))) {
            PullHyperDataByPreHash(globalHID, prehash, *iter);

            T_SYNCBLOCKINFO sinfo;
            sinfo.nodelist.push_back(*iter);
            sinfo.retry_times++;

            m_SyncBlockMap[globalHID] = std::move(sinfo);

            return 0;
        }
    }

    g_daily_logger->error("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in ActiveNodes", globalHID);
    g_console_logger->warn("GetRemoteHyperBlockByPreHash failed! Can't find hid: [{}] in ActiveNodes", globalHID);

    return -1;
}

bool CHyperChainSpace::GetHyperBlockHeaderHash(uint64 hid, T_SHA256& headerhash)
{
    if (m_HeaderHashMap.count(hid)) {
        headerhash = m_HeaderHashMap[hid];
        return true;
    }

    /*T_HYPERBLOCK preHyperBlock;
    if (CHyperchainDB::getHyperBlock(preHyperBlock, hid)) {
        headerhash = preHyperBlock.calculateHeaderHashSelf();
        m_HeaderHashMap[hid] = headerhash;
        if (hid > uiMaxHeaderID)
            uiMaxHeaderID = hid;
        return true;
    }*/

    return false;
}

bool CHyperChainSpace::GetHyperBlockHeaderHash(uint64 id, uint32 range, vector<T_SHA256>& vecheaderhash)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        for (uint64 hid = id; hid < id + range; hid++) {
            if (m_HeaderHashMap.count(hid)) {
                vecheaderhash.push_back(m_HeaderHashMap[hid]);
            }
            else {
                g_daily_logger->error("GetHyperBlockHeaderHash failed! Can't find block [{}] in m_HeaderHashMap", hid);
                g_console_logger->warn("GetHyperBlockHeaderHash failed! Can't find block [{}] in m_HeaderHashMap", hid);
                return false;
            }
            /*T_HYPERBLOCK preHyperBlock;
            if (CHyperchainDB::getHyperBlock(preHyperBlock, hid)) {
                T_SHA256 headerhash = preHyperBlock.calculateHeaderHashSelf();
                m_HeaderHashMap[hid] = headerhash;
                vecheaderhash.push_back(headerhash);
                if (hid > uiMaxHeaderID)
                    uiMaxHeaderID = hid;
            }*/
        }

        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHeaderHash, id, range, &vecheaderhash);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, uint32 range, vector<T_SHA256>& headerhash, string from_nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (headerhash.size() != range) {
            g_daily_logger->error("PutHyperBlockHeaderHash failed! hid: [{}], range: [{}], nodeid: [{}], headerhash.size() != range!", hid, range, from_nodeid);
            g_console_logger->warn("PutHyperBlockHeaderHash failed! hid: [{}], range: [{}], nodeid: [{}], headerhash.size() != range!", hid, range, from_nodeid);
            return;
        }

        if (m_chainInfoMap.empty())
            return;

        uint8 chainNum = 0;
        bool found = false;

        for (auto it = m_chainInfoMap.begin(); !found && it != m_chainInfoMap.end(); it++) {
            if (find(it->second.nodelist.begin(), it->second.nodelist.end(), from_nodeid) != it->second.nodelist.end()) {
                chainNum = it->first;
                found = true;
                break;
            }
        }

        if (!found) {
            g_daily_logger->error("PutHyperBlockHeaderHash failed! Can't find from_nodeid [{}] in m_chainInfoMap!", from_nodeid);
            g_console_logger->warn("PutHyperBlockHeaderHash failed! Can't find from_nodeid [{}] in m_chainInfoMap!", from_nodeid);
            return;
        }

        g_daily_logger->info("PutHyperBlockHeaderHash hid: [{}], range: [{}], nodeid: [{}]", hid, range, from_nodeid);
        g_console_logger->info("PutHyperBlockHeaderHash hid: [{}], range: [{}], nodeid: [{}]", hid, range, from_nodeid);

        int id = hid;
        for (auto& hh : headerhash) {
            m_chainInfoMap[chainNum].headerhash.insert(make_pair(id, hh));
            id++;
        }

        m_chainInfoMap[chainNum].sync_hash_hid = --id;

        g_daily_logger->info("PutHyperBlockHeaderHash sync_hash_hid: [{}], headerinfo.id: [{}]",
            m_chainInfoMap[chainNum].sync_hash_hid, m_chainInfoMap[chainNum].headerinfo.id);
        g_console_logger->info("PutHyperBlockHeaderHash sync_hash_hid: [{}], headerinfo.id: [{}]",
            m_chainInfoMap[chainNum].sync_hash_hid, m_chainInfoMap[chainNum].headerinfo.id);

        if (m_chainInfoMap[chainNum].sync_hash_hid < m_chainInfoMap[chainNum].headerinfo.id) {
            _msghandler.registerTimer(2 * 1000, std::bind(&CHyperChainSpace::PullHeaderHashInfo, this), true);
            return;
        }

        if (m_chainInfoMap[chainNum].sync_hash_hid == m_chainInfoMap[chainNum].headerinfo.id) {
            //HCE: Verify HashMTRoot
            vector<T_SHA256> hashMTRootlist;
            GenerateHeaderHashMTRootList(m_chainInfoMap[chainNum].headerinfo.section, hashMTRootlist, m_chainInfoMap[chainNum].headerhash);

            bool isSame = true;
            vector<T_SHA256> hMTRootlist = m_chainInfoMap[chainNum].headerinfo.hashMTRootList;
            if (hMTRootlist.size() == hashMTRootlist.size()) {
                for (int i = 0; i < hMTRootlist.size(); i++) {
                    if (hMTRootlist[i] != hashMTRootlist[i]) {
                        isSame = false;
                        break;
                    }
                }

                if (isSame)
                    m_chainInfoMap[chainNum].checked = true;
            }

            g_daily_logger->info("PutHyperBlockHeaderHash m_chainInfoMap[{}].checked={}", chainNum, m_chainInfoMap[chainNum].checked);
            g_console_logger->info("PutHyperBlockHeaderHash m_chainInfoMap[{}].checked={}", chainNum, m_chainInfoMap[chainNum].checked);
        }
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlockHeaderHash, hid, range, &headerhash, from_nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

//void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash)
//{
//    m_HeaderHashMap[hid] = headerhash;
//}

void CHyperChainSpace::SaveHyperblock(const T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        T_SHA256 hash = hyperblock.GetHashSelf();

        if (m_db->isBlockExistedbyHash(hash))
            return;

        //DBmgr::Transaction t = m_db->beginTran();

        auto subItr = hyperblock.GetChildChains().begin();
        uint16 chainnum = 0;
        for (; subItr != hyperblock.GetChildChains().end(); subItr++) {
            chainnum++;
            auto ssubItr = (*subItr).begin();
            for (; ssubItr != (*subItr).end(); ssubItr++) {
                m_db->SaveLocalblock(*ssubItr, hyperblock.GetID(), chainnum, hash);
            }
        }

        m_db->SaveHyperblock(hyperblock);
        //t.set_trans_succ();
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::SaveHyperblock, &hyperblock);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


CHECK_RESULT CHyperChainSpace::CheckDependency(const T_HYPERBLOCK& hyperblock, string nodeid)
{
    uint64_t blockid = hyperblock.GetID();
    T_SHA256 blockheaderhash = hyperblock.calculateHeaderHashSelf();

    if (blockid == 0 || blockid == UINT64_MAX)
        return CHECK_RESULT::INVALID_DATA;

    //HC: 测试网，小于数据校验起始块的数据不做前向依赖检查
	//HCE: INFORMAL_NET, data smaller than the data verification start block is not checked for forward dependence
    if (pro_ver == ProtocolVer::NET::INFORMAL_NET && blockid < m_gensisblockID) {
        return CHECK_RESULT::VALID_DATA;
    }

    SaveHyperblock(hyperblock);

    T_HYPERBLOCKHEADER header = hyperblock.GetHeader();
    PutHyperBlockHeader(header, nodeid);

    T_SHA256 headerhash;
    if (GetHyperBlockHeaderHash(blockid, headerhash)) {
        if (headerhash == blockheaderhash)
            return CHECK_RESULT::VALID_DATA;

        //HC: 超块头hash不一致可能有两种情况：1.数据分叉 2.不合法数据
        //HC: 回溯校验，直到Hash一致或者达到块成熟度
		//HCE: There are two possible cases of hyperblock header hash inconsistency: 1. Data fork 2. Illegal data
		//HCE: Backcheck until the hash is consistent or block maturity is reached
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->info("I have hyper block: [{}] headerhash: [{}] in hash cache", blockid, HeaderHash);

        char pHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(pHeaderHash, blockheaderhash);
        g_daily_logger->info("hyper block: [{}] headerhash: [{}] incompatible", blockid, pHeaderHash);
    }


    //HC: 孤立超块头需要获取前向依赖的超块头
    //HCE: Orphaned block headers need to get the block headers that are dependent forward
    if (isInSingleHeaderMap(blockid, blockheaderhash))
        return CHECK_RESULT::UNCONFIRMED_DATA;

    return CHECK_RESULT::INCOMPATIBLE_DATA;
}

int CHyperChainSpace::GetRemoteHeaderHash(uint64 startHID, uint32 range)
{
    if (m_Chainspace.empty())
        return -1;

    map<uint64, set<string>>::iterator it = m_Chainspace.find(startHID);
    if (it == m_Chainspace.end())
        return -1;

    //HCE: Get the list of active nodes
    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("GetRemoteHeaderHash failed! ActiveNodes empty!");
        g_console_logger->error("GetRemoteHeaderHash failed! ActiveNodes empty!");
        return -1;
    }

    int i;
    set<string> nodeset = it->second;

    set<string>::iterator iter = nodeset.begin();
    for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
        //HCE: Check whether the nodeid is in the list of active nodes
        if (ActiveNodes.count(CUInt128(*iter))) {
            PullHeaderHash(startHID, range, *iter);
            m_ReqHeaderHashNodes[startHID].insert(*iter);
            i++;
        }
    }

    return i;
}

int CHyperChainSpace::GetHeaderByHash(T_HYPERBLOCKHEADER& header, uint64 hid, const T_SHA256& headerhash)
{
    int ret = m_db->getHeaderByHash(header, hid, headerhash);
    if (ret != 0) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->error("getHeaderByHash failed! hid: [{}], hash: [{}]", hid, HeaderHash);
        g_console_logger->warn("getHeaderByHash failed! hid: [{}], hash: [{}]", hid, HeaderHash);
    }

    return ret;
}

void CHyperChainSpace::DeleteSingleHeader(uint64 hid, T_SHA256 headerhash)
{
    int ret = m_db->deleteSingleHeaderInfo(hid, headerhash);
    if (ret != 0) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->error("deleteSingleHeaderInfo failed!({}) hid: [{}], headerhash: [{}]", ret, hid, HeaderHash);
        g_console_logger->warn("deleteSingleHeaderInfo failed!({}) hid: [{}], headerhash: [{}]", ret, hid, HeaderHash);
    }
}

void CHyperChainSpace::removeFromSingleHeaderMap(uint64 hid, T_SHA256 headerhash)
{
    if (m_SingleHeaderMap.empty() || m_SingleHeaderMap.count(hid) == 0)
        return;

    for (multimap<uint64, T_SINGLEHEADER>::iterator mi = m_SingleHeaderMap.lower_bound(hid);
        mi != m_SingleHeaderMap.upper_bound(hid); ) {
        if (mi->second.headerhash == headerhash) {
            m_SingleHeaderMap.erase(mi++);
            return;
        }

        mi++;
    }
}

bool CHyperChainSpace::isInSingleHeaderMap(uint64 hid, T_SHA256 headerhash)
{
    if (m_SingleHeaderMap.empty() || m_SingleHeaderMap.count(hid) == 0)
        return false;

    for (multimap<uint64, T_SINGLEHEADER>::iterator mi = m_SingleHeaderMap.lower_bound(hid);
        mi != m_SingleHeaderMap.upper_bound(hid); ++mi) {
        if (mi->second.headerhash == headerhash)
            return true;
    }

    return false;
}

bool CHyperChainSpace::isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash)
{
    if (m_UnconfirmedBlockMap.empty())
        return false;

    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.find(hid);
    if (it == m_UnconfirmedBlockMap.end())
        return false;

    char HyperblockHash[FILESIZEL] = { 0 };
    CCommonStruct::Hash256ToStr(HyperblockHash, blockhash);

    LIST_T_HYPERBLOCK blocklist = it->second;
    ITR_LIST_T_HYPERBLOCK iter = blocklist.begin();
    for (; iter != blocklist.end(); iter++) {
        if (blockhash == iter->GetHashSelf()) {
            g_daily_logger->info("hyper block: [{}] hash: [{}] in unconfirmed block cache", hid, HyperblockHash);
            return true;
        }
    }

    return false;
}

void CHyperChainSpace::RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash)
{
    if (m_UnconfirmedBlockMap.empty())
        return;

    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.find(hid + 1);
    if (it == m_UnconfirmedBlockMap.end())
        return;

    bool found = false;
    T_HYPERBLOCK hyperblock;
    LIST_T_HYPERBLOCK blocklist = it->second;
    ITR_LIST_T_HYPERBLOCK iter = blocklist.begin();
    for (; iter != blocklist.end(); iter++) {
        if (headerhash == iter->GetPreHeaderHash()) {
            hyperblock = *iter;
            found = true;
            break;
        }
    }

    if (found) {
        m_UnconfirmedBlockMap.erase(it);
        updateHyperBlockCache(hyperblock);
    }

    return;
}

//void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid)
//{
//    bool found = false;
//    bool confirmed = false;
//
//    ITR_MAP_T_UNCONFIRMEDHEADERHASH it = m_UnconfirmedHashMap.find(hid);
//    if (it == m_UnconfirmedHashMap.end()) {
//        T_HEADERHASHINFO headerhashinfo(headerhash, from_nodeid);
//        m_UnconfirmedHashMap[hid].push_back(std::move(headerhashinfo));
//        return;
//    }
//
//    LIST_T_HEADERHASHINFO headerhashlist = it->second;
//    ITR_LIST_T_HEADERHASHINFO iter = headerhashlist.begin();
//    for (; iter != headerhashlist.end(); iter++) {
//        if (headerhash == iter->GetHeaderHash()) {
//            iter->PutNodeID(from_nodeid);
//            found = true;
//            break;
//        }
//    }
//
//    if (found == false) {
//        T_HEADERHASHINFO headerhashinfo(headerhash, from_nodeid);
//        headerhashlist.push_back(std::move(headerhashinfo));
//    }
//
//    //HC: 如果vote超过半数，headerhash可以确认有效
//    int vote = m_ReqHeaderHashNodes[hid].size();
//    int threshold = ceil(vote * 0.6);
//    iter = headerhashlist.begin();
//    for (; iter != headerhashlist.end(); iter++) {
//        if (iter->GetVote() >= threshold) {
//            m_HeaderHashMap[hid] = headerhash;
//            confirmed = true;
//            break;
//        }
//    }
//
//    if (confirmed == true) {
//        //HC: 清理m_UnconfirmedHashMap中的数据
//        m_UnconfirmedHashMap.erase(it);
//
//        RehandleUnconfirmedBlock(hid, headerhash);
//
//        //HC: 清理m_ReqHeaderHashNodes中的数据
//        m_ReqHeaderHashNodes.erase(hid);
//    }
//
//    return;
//}

void CHyperChainSpace::loadHeaderIndexCache()
{
    int page = -1;
    int num = m_db->getHeaderIndexRecordNumber();
    if (num == 0)
        return;

    int pgs = num / 10000;
    if (pgs > 0)
        page = pgs;

    if (page == -1) {
        m_db->getHeaderIndex(m_HeaderIndexMap, page);
        return;
    }

    for (int pg = 0; pg <= page; pg++) {
        m_db->getHeaderIndex(m_HeaderIndexMap, pg);
    }

    cout << "m_HeaderIndexMap.size:" << m_HeaderIndexMap.size() << endl;
}

void CHyperChainSpace::loadHyperBlockCache()
{
    uint64 nHyperId = GetLocalLatestHID();
    if (nHyperId == UINT64_MAX)
        return;

    T_HYPERBLOCK hyperBlock;
    if (CHyperchainDB::getHyperBlock(hyperBlock, nHyperId)) {
        uiMaxBlockNum = hyperBlock.GetID();
        m_LatestHyperBlock = std::move(hyperBlock);
        g_daily_logger->info("loadHyperBlockCache, uiMaxBlockNum:{}", hyperBlock.GetID());
    }
}

void CHyperChainSpace::loadHyperBlockIDCache()
{
    int ret = m_db->getAllHyperblockNumInfo(m_localHID);
    if (ret != 0) {
        g_daily_logger->error("loadHyperBlockIDCache failed!");
        g_console_logger->error("loadHyperBlockIDCache failed!");
    }
}

void CHyperChainSpace::loadHeaderIDCache()
{
    if (m_HeaderHashMap.empty())
        return;

    for (auto it = m_HeaderHashMap.begin(); it != m_HeaderHashMap.end(); it++)
        m_localHeaderID.insert(it->first);
}

void CHyperChainSpace::loadHyperBlockHashCache()
{
    int ret = m_db->getAllBlockHashInfo(m_BlockHashMap);
    if (ret != 0) {
        g_daily_logger->error("loadHyperBlockHashCache failed!");
        g_console_logger->error("loadHyperBlockHashCache failed!");
    }
}

void CHyperChainSpace::GenerateHIDSection(const std::set<uint64>& localHID, vector <string>& localHIDsection)
{
    if (localHID.empty())
        return;

    //HC: 每次都重新生成localHIDsection内容，以后可优化为持续增长
    //HCE: Regenerate localHIDsection content each time and optimize for continuous growth later
    localHIDsection.clear();

    uint64 nstart = *(localHID.begin());
    uint64 nend = nstart;
    string data;

    for (auto& li : localHID) {
        //HC: 将本地IDlist 同步到块空间map
        //HC: m_hpspacedata[li].insert(m_mynodeid); m_hpspacedata不保存本地超块信息
        //HC: 将超块IDlist数据 格式化（"ID-ID"）到 vector
        //HCE: Synchronize the local IDlist to the block space map
        //HCE: m_hpspacedata do not save local superblock information
        if (li == nend || li - nend == 1)
            nend = li;
        else {
            //HCE: "nstart-nend"
            if (nstart == nend)
                data = to_string(nstart);
            else
                data = to_string(nstart) + "-" + to_string(nend);

            localHIDsection.push_back(data);

            nstart = li;
            nend = nstart;
        }
    }

    if (nstart == nend)
        data = to_string(nstart);
    else
        data = to_string(nstart) + "-" + to_string(nend);

    localHIDsection.push_back(data);
}

uint64 CHyperChainSpace::GetMaxHeaderID()
{
    if (m_localHeaderIDsection.empty())
        return 0;

    uint64 hid = 0;
    string strIDtoID = m_localHeaderIDsection[0];
    string::size_type ns = strIDtoID.find("-");

    if ((ns != string::npos) && (ns > 0)) {
        hid = stoull(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));
    }
    else {
        hid = stoull(strIDtoID);
    }

    return hid;
}

void CHyperChainSpace::NoHyperBlock(uint64 hid, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty())
            return;

        map<uint64, set<string>>::iterator it = m_Chainspace.find(hid);
        if (it == m_Chainspace.end())
            return;

        set<string> nodeset = it->second;
        nodeset.erase(nodeid);
        if (nodeset.empty()) {
            m_Chainspace.erase(it);

            if (hid == uiGlobalMaxBlockNum)
                uiGlobalMaxBlockNum--;
        }
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::NoHyperBlock, hid, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::NoHyperBlockHeader(uint64 hid, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_chainspaceheader.empty())
            return;

        auto it = m_chainspaceheader.find(nodeid);
        if (it == m_chainspaceheader.end())
            return;

        if (hid <= it->second.id)
            m_chainspaceheader.erase(it);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::NoHyperBlockHeader, hid, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::GetHeaderHashMTRootData(uint64 headerid, string& msgbuf)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (uiMaxHeaderID == 0 || uiMaxHeaderID < headerid)
            return false;

        vector<uint16> locationSection;
        vector<T_SHA256> hashMTRootlist;
        GetHeaderIDSection(headerid, locationSection);
        GenerateHeaderHashMTRootList(locationSection, hashMTRootlist, m_HeaderHashMap);

        msgbuf += "HeaderID=";
        msgbuf += to_string(headerid);
        msgbuf += ";";

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        uint32 hashnum = hashMTRootlist.size();
        oa << hashnum;
        for (auto iter = hashMTRootlist.begin(); iter != hashMTRootlist.end(); iter++) {
            oa << (*iter);
        }

        msgbuf += "HeaderHashMTRootList=";
        msgbuf += ssBuf.str();

        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHeaderHashMTRootData);
        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret, msgbuf);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::AnalyzeHeaderHashMTRootData(string strbuf, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (strbuf.empty() || strbuf.length() <= 9)
            return;

        //HCE: "HeaderID=6700;HeaderHashMTRootList=binary_oarchive"
        string::size_type no = strbuf.find("HeaderID=");
        string::size_type nr = strbuf.find(";HeaderHashMTRootList=");
        if (no == string::npos || nr == string::npos)
            return;

        //HCE: HeaderID=6700
        string buf = strbuf.substr(no + 9, nr - no - 9);
        uint64 id = stoull(buf);

        auto it = m_chainspaceheader.find(nodeid);
        if (it == m_chainspaceheader.end() || (it->second.id != id)) {
            g_daily_logger->error("AnalyzeHeaderHashMTRootData() failed! hid: [{}], nodeid: [{}]", id, nodeid);
            g_console_logger->warn("AnalyzeHeaderHashMTRootData() failed! hid: [{}], nodeid: [{}]", id, nodeid);
            return;
        }

        //HCE: HeaderHashMTRootList=binary_oarchive
        string sBuf = strbuf.substr(nr + 22);
        stringstream ssBuf(sBuf);
        vector<T_SHA256> hashlist;

        try {
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            uint32 hashnum = 0;
            ia >> hashnum;
            for (uint32 i = 0; i < hashnum; i++) {
                T_SHA256 hash;
                ia >> hash;
                hashlist.push_back(std::move(hash));
            }
        }
        catch (std::exception& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        it->second.Set(hashlist);
        it->second.ready = true;

        g_daily_logger->info("AnalyzeHeaderHashMTRootData() hid: [{}], nodeid: [{}]", id, nodeid);
        g_console_logger->info("AnalyzeHeaderHashMTRootData() hid: [{}], nodeid: [{}]", id, nodeid);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::AnalyzeHeaderHashMTRootData, strbuf, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


bool CHyperChainSpace::GetLocalChainSpaceData(string& msgbuf)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_localHIDsection.empty())
            return false;

        msgbuf = "BlockID=";
        for (auto& li : m_localHIDsection) {
            msgbuf += li;
            msgbuf += ";";
        }

        if (!m_localHeaderReady)
            return true;

        msgbuf += "HeaderID=";
        msgbuf += to_string(uiMaxHeaderID);
        msgbuf += ";";

        /*if (uiMaxHeaderID == 0 || m_HeaderHashMTRootList.empty())
            return true;

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        uint32 hashnum = m_HeaderHashMTRootList.size();
        oa << hashnum;
        for (auto iter = m_HeaderHashMTRootList.begin(); iter != m_HeaderHashMTRootList.end(); iter++) {
            oa << (*iter);
        }

        msgbuf += "HeaderHashMTRootList=";
        msgbuf += ssBuf.str();*/

        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalChainSpaceData);
        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret, msgbuf);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::AnalyzeChainSpaceData(string strbuf, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (strbuf.empty() || strbuf.length() <= 8)
            return;

        //HCE: "BlockID=0;6667-6677;6679-6690;HeaderID=6700"
        string::size_type np = strbuf.find("BlockID=");
        if (np == string::npos)
            return;

        //HCE: "BlockID=0;6667-6677;6679-6690;HeaderID=6700"
        m_chainspaceshow[nodeid] = strbuf;

        string::size_type no = strbuf.find("HeaderID=");

        if (no == string::npos) {
            strbuf = strbuf.substr(np + 8);
        }
        else {
            string buf = strbuf.substr(no + 9);
            m_chainspaceheaderID[nodeid] = stoull(buf);

            strbuf = strbuf.substr(np + 8, no - np - 8);
        }

        vector<string> vecHID;
        SplitString(strbuf, vecHID, ";");

        vector<string>::iterator vit;
        string::size_type ns = 0;
        string strIDtoID;
        uint64 nstart, nend, ID;

        for (auto& sid : vecHID) {
            strIDtoID = sid;

            ns = strIDtoID.find("-");
            if ((ns != string::npos) && (ns > 0)) {
                nstart = stoull(strIDtoID.substr(0, ns));
                nend = stoull(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));

                for (ID = nstart; ID <= nend; ID++) {
                    //if (!FindIDExistInChainIDList(ID))
                    m_Chainspace[ID].insert(nodeid);
                }

            }
            else {
                ID = stoull(strIDtoID);
                //if (!FindIDExistInChainIDList(ID))
                m_Chainspace[ID].insert(nodeid);
            }
        }

        map<uint64, set<string>>::reverse_iterator it = m_Chainspace.rbegin();
        if (it == m_Chainspace.rend())
            return;

        if (uiGlobalMaxBlockNum < it->first)
            uiGlobalMaxBlockNum = it->first;

        if (!m_ChainspaceReady)
            m_ChainspaceReady = true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::AnalyzeChainSpaceData, strbuf, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


void CHyperChainSpace::SplitString(const string& s, vector<std::string>& v, const std::string& c)
{
    string::size_type pos1 = 0, pos2;
    pos2 = s.find(c);
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
}

bool CHyperChainSpace::GetLocalBlock(const T_LOCALBLOCKADDRESS& addr, T_LOCALBLOCK& localblock)
{
    if (!m_db) {
        return false;
    }
    int ret = m_db->getLocalblock(localblock, addr.hid, addr.id, addr.chainnum);
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CHyperChainSpace::GetLocalBlockByHash(T_SHA256 hash, T_LOCALBLOCK& localblock)
{
    if (!m_db) {
        return false;
    }
    int ret = 0;/*m_db->getLocalblockByHash(localblock, hash);*/
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CHyperChainSpace::GetLocalBlockByHeaderHash(T_SHA256 headerhash, T_LOCALBLOCK& localblock)
{
    if (!m_db) {
        return false;
    }
    int ret = 0;/*m_db->getLocalblockByHeaderhash(localblock, headerhash);*/
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CHyperChainSpace::GetLocalBlocksByAddress(const T_LOCALBLOCKADDRESS& addr, std::list<T_LOCALBLOCK>& localblocks)
{
    if (!m_db) {
        return false;
    }
    int ret = m_db->getLocalBlocks(localblocks, addr);
    if (ret == 0) {
        return true;
    }
    return false;
}


bool CHyperChainSpace::GetLocalBlockByHyperBlockHash(const T_LOCALBLOCKADDRESS& addr, const T_SHA256& hhash, T_LOCALBLOCK& localblock)
{
    if (!m_db) {
        return false;
    }
    int ret = m_db->getLocalblock(localblock, hhash, addr);
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CHyperChainSpace::GetLocalBlockPayload(const T_LOCALBLOCKADDRESS& addr, string& payload)
{
    if (!m_db) {
        return false;
    }
    T_LOCALBLOCK lb;
    int ret = m_db->getLocalblock(lb, addr.hid, addr.id, addr.chainnum);
    if (ret == 0) {
        payload = std::forward<string>(lb.body.payload);
        return true;
    }
    return false;

    /*if (_msghandler.getID() == std::this_thread::get_id()) {
        if (!m_db) {
            return false;
        }
        T_LOCALBLOCK lb;
        int ret = m_db->getLocalblock(lb, addr.hid, addr.id, addr.chainnum);
        if (ret == 0) {
            payload = std::forward<string>(lb.body.payload);
            return true;
        }
        return false;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalBlockPayload, &addr);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret, payload);
            delete rspmsg;
        }

        return ret;
    }*/
}

void CHyperChainSpace::start(DBmgr* db)
{
    m_db = db;


    //HC: 加载本地超块号到内存缓存
    //HCE: Load the local hyperblock number into the memory cache
    cout << "HyperChainSpace::loadHyperBlockIDCache... " << endl;
    loadHyperBlockIDCache();


    //HC: 生成本地超块号区间段格式
    //HCE: Generates a local hyperblock number interval segment format
    GenerateHIDSection(m_localHID, m_localHIDsection);

    //HC: 加载本地最新超块到内存缓存
    //HCE: Load the latest local hyperblock into the memory cache
    cout << "HyperChainSpace::loadLatestHyperBlockCache... " << endl;
    loadHyperBlockCache();

    //HC: 加载本地超块Hash到内存缓存
    //HCE: Load the local hyperblock hash into the memory cache
    cout << "HyperChainSpace::loadHyperBlockHashCache... " << endl;
    loadHyperBlockHashCache();

    //HC: 加载本地所有HeaderHash到内存缓存
    //HCE: Load all local HeaderHash into the memory cache
    cout << "HyperChainSpace::loadAllHeaderHashInfo... " << endl;
    m_db->getAllHeaderHashInfo(m_chainheaderhashSet);

    //HC: 加载本地最优链HeaderHash到内存缓存
    //HCE: Load all local HeaderHash of the optimal chain into the memory cache
    cout << "HyperChainSpace::loadBestChainHeaderHashInfo... " << endl;
    m_db->getAllHeaderHashInfo(m_HeaderHashMap);

    if (!m_HeaderHashMap.empty()) {
        //HC: 加载本地超块头ID到内存缓存
        //HCE: Load the local hyperblock header ID into the memory cache
        loadHeaderIDCache();

        //HC: 生成本地超块头ID区间段格式
        //HCE: Generates a local hyperblock header number interval segment format
        GenerateHIDSection(m_localHeaderID, m_localHeaderIDsection);

        uiMaxHeaderID = GetMaxHeaderID();
    }


    //this_thread::sleep_for(chrono::seconds(20));

    //HC: 加载创始块ID和Hash
    //HCE: Load genesis block ID and Hash
    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        //HCE: The starting block for INFORMAL_NET data validation is INFORMALNET_GENESISBLOCKID
        m_gensisblockID = INFORMALNET_GENESISBLOCKID;
        m_gensisblockHeaderhash = INFORMALNET_GENESISBLOCK_HEADERHASH;

        //HC: NodeManager模块，用来区分不同创始块网络
        //HCE: NodeManager module, used to distinguish between different genesis block networks
        genesis_block_header_hash = INFORMALNET_GENESISBLOCK_HEADERHASH;
    }
    else if (pro_ver == ProtocolVer::NET::SAND_BOX) {
        m_gensisblockID = 0;

        if (!m_HeaderHashMap.empty() && m_HeaderHashMap.find(0) != m_HeaderHashMap.end()) {
            m_gensisblockHeaderhash = m_HeaderHashMap[0];

            //HC: NodeManager模块，用来区分不同创始块网络
            //HCE: NodeManager module, used to distinguish between different genesis block networks
            genesis_block_header_hash = m_HeaderHashMap[0];
        }
    }

    /*if (uiMaxHeaderID > 0) {
        GetHeaderIDSection(uiMaxHeaderID, m_HeaderHashMTRootSection);
        GenerateHeaderHashMTRootList(m_HeaderHashMTRootSection, m_HeaderHashMTRootList, m_HeaderHashMap);
    }*/

    //HC: 加载本地HeaderIndex到内存缓存
    //HCE: Load all local HeaderIndex into the memory cache
    using seconds = std::chrono::duration<double, ratio<1>>;
    seconds timespan;

    cout << "HyperChainSpace::loadAllHeaderIndex... " << endl;

    system_clock::time_point time1 = system_clock::now();
    loadHeaderIndexCache();
    //m_db->getAllHeaderIndex(m_HeaderIndexMap);
    system_clock::time_point time2 = system_clock::now();
    timespan = std::chrono::duration_cast<seconds>(time2 - time1);
    cout << "HyperChainSpace::loadAllHeaderIndex spend [" << timespan.count() << "] second" << endl;

    //HC: 加载本地SingleHeader到内存缓存
    //HCE: Load all local SingleHeader into the memory cache
    cout << "HyperChainSpace::loadAllSingleHeaderInfo... " << endl;
    m_db->getAllSingleHeaderInfo(m_SingleHeaderMap);

    startMQHandler();

    cout << "HyperChainSpace::CheckLocalData()" << endl;
    CheckLocalData();

}

void CHyperChainSpace::CheckLocalData()
{
    uint64 localHID = GetLocalLatestHID();

    if (localHID == UINT64_MAX)
        return;

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET && uiMaxHeaderID < m_gensisblockID && localHID > m_gensisblockID) {
        //HC: 测试网，兼容老版数据
        //HCE: INFORMAL_NET, compatible with older data
        for (uint64 i = m_gensisblockID; i <= localHID; i++) {
            T_HYPERBLOCKHEADER header;
            if (!m_db->getHyperblockshead(header, i)) {
                PutHyperBlockHeader(header, "myself");
            }
        }
    }
}

void CHyperChainSpace::PullHyperDataByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid)
{
    GetHyperBlockByPreHashReqTask task(globalHID, prehash, nodeid);
    task.exec();
}

void CHyperChainSpace::PullHyperDataByHID(uint64 hid, string nodeid)
{
    GetHyperBlockByNoReqTask task(hid, nodeid);
    task.exec();
}

void CHyperChainSpace::BatchPullHyperDataByHID(uint64 hid, uint32 ncnt, const string& nodeid)
{
    GetHyperBlockByNoReqTask task(hid, nodeid, ncnt);
    task.exec();
}

void CHyperChainSpace::PullHeaderHashMTRoot(uint64 hid, string nodeid)
{
    GetHeaderHashMTRootReqTask task(hid, nodeid);
    task.exec();
}

void CHyperChainSpace::PullHeaderHash(uint64 hid, uint32 range, string nodeid)
{
    GetHeaderHashReqTask task(hid, range, nodeid);
    task.exec();
}

void CHyperChainSpace::PullBlockHeaderData(uint64 hid, uint16 range, string nodeid)
{
    GetBlockHeaderReqTask task(hid, range, nodeid);
    task.exec();
}

void CHyperChainSpace::PullChainSpace()
{
    auto acss = m_chainactioncoststt.NewStatt("PullChainSpace");

    if (_isstop) {
        return;
    }

    PullChainSpaceTask task;
    task.exec();
}

uint64 CHyperChainSpace::GetMaxBlockID()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiMaxBlockNum;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetMaxBlockID);

        uint64 nblockNo = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, nblockNo);
            delete rspmsg;
        }

        return nblockNo;
    }
}

void CHyperChainSpace::GetLatestHyperBlockIDAndHash(uint64& id, T_SHA256& hash, uint64& ctm) {
    if (_msghandler.getID() == std::this_thread::get_id()) {
        id = m_LatestHyperBlock.GetID();
        hash = m_LatestHyperBlock.GetHashSelf();
        ctm = m_LatestHyperBlock.GetCTime();
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLatestHyperBlockIDAndHash);

        if (rspmsg) {
            MQMsgPop(rspmsg, id, hash, ctm);
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::IsLatestHyperBlockReady()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_LatestBlockReady;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::IsLatestHyperBlockReady);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::GetLatestHyperBlock(T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        hyperblock = m_LatestHyperBlock;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLatestHyperBlock, &hyperblock);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetLocalHIDs(uint64 nStartHID, set<uint64>& setHID)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        auto iter = m_localHID.lower_bound(nStartHID);
        for (; iter != m_localHID.end(); ++iter) {
            setHID.insert(*iter);
        }
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalHIDs, nStartHID, &setHID);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetHyperChainShow(map<string, string>& chainspaceshow)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        chainspaceshow = m_chainspaceshow;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperChainShow, &chainspaceshow);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetHyperChainData(map<uint64, set<string>>& chainspacedata)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        chainspacedata = m_Chainspace;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperChainData, &chainspacedata);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetLocalHIDsection(vector <string>& hidsection)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        hidsection = m_localHIDsection;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalHIDsection, &hidsection);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

size_t CHyperChainSpace::GetLocalChainIDSize()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_localHID.size();
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalChainIDSize);

        size_t idnums = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, idnums);
            delete rspmsg;
        }

        return idnums;
    }
}

uint64 CHyperChainSpace::GetHeaderHashCacheLatestHID()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiMaxHeaderID;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHeaderHashCacheLatestHID);

        uint64 hid = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, hid);
            delete rspmsg;
        }

        return hid;
    }
}

void CHyperChainSpace::DispatchService(void* wrk, zmsg* msg)
{
    HCMQWrk* realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();
    string u = msg->pop_front();

    int service_t = 0;
    memcpy(&service_t, u.c_str(), sizeof(service_t));

    m_currentHandlingService = (SERVICE)service_t;
    defer{
        m_currentHandlingService = SERVICE::DoNothing;
    };

    auto acss = m_chainactioncoststt.NewStatt(service_t);

    switch ((SERVICE)service_t) {
    case SERVICE::GetMaxBlockID: {
        uint64 nblockNo = GetMaxBlockID();
        MQMsgPush(msg, nblockNo);
        break;
    }
    case SERVICE::GetLatestHyperBlockIDAndHash: {
        uint64 id = 0;
        T_SHA256 hash;
        uint64 ctm = 0;

        GetLatestHyperBlockIDAndHash(id, hash, ctm);
        MQMsgPush(msg, id, hash, ctm);
        break;
    }
    case SERVICE::IsLatestHyperBlockReady: {
        bool ret = IsLatestHyperBlockReady();
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLatestHyperBlock: {
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);
        GetLatestHyperBlock(*pHyperblock);
        break;
    }
    case SERVICE::GetHyperBlockByID: {
        uint64_t blockid;
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, blockid, pHyperblock);

        bool ret = getHyperBlock(blockid, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlockByHash: {
        T_SHA256 hhash;
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, hhash, pHyperblock);

        bool ret = getHyperBlock(hhash, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlockByPreHash: {
        uint64_t blockid;
        T_SHA256 prehash;
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, blockid, prehash, pHyperblock);

        bool ret = getHyperBlockByPreHash(blockid, prehash, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::CheckHyperBlockHash: {
        uint64_t blockid;
        bool needdownload;
        T_SHA256* hash;
        MQMsgPop(msg, blockid, hash, needdownload);

        bool ret = CheckHyperBlockHash(blockid, *hash, needdownload);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlockHash: {
        uint64_t blockid;
        T_SHA256* hash;
        MQMsgPop(msg, blockid, hash);

        bool ret = GetHyperBlockHash(blockid, *hash);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlocksHashs: {
        uint64_t blockid;
        uint32 num;
        bool needdownload;
        vector<T_SHA256>* vechash;
        MQMsgPop(msg, blockid, num, vechash, needdownload);

        bool ret = GetHyperBlocksHashs(blockid, num, *vechash, needdownload);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalBlocksByHID: {
        uint64_t blockid;
        T_APPTYPE* pApp = nullptr;
        T_SHA256* hhash;
        vector<T_PAYLOADADDR>* pvecPA = nullptr;
        MQMsgPop(msg, blockid, pApp, hhash, pvecPA);

        bool ret = GetLocalBlocksByHID(blockid, *pApp, *hhash, *pvecPA);
        MQMsgPush(msg, ret);
        break;
    }
    /*case SERVICE::GetLocalBlockPayload: {
        T_LOCALBLOCKADDRESS* paddr = nullptr;
        MQMsgPop(msg, paddr);

        string payload;
        bool ret = GetLocalBlockPayload(*paddr, payload);
        MQMsgPush(msg, ret, payload);
        break;
    }*/
    case SERVICE::GetLocalBlockByAddr: {
        T_LOCALBLOCKADDRESS* paddr = nullptr;
        T_LOCALBLOCK* pLocalblock = nullptr;
        MQMsgPop(msg, paddr, pLocalblock);

        bool ret = GetLocalBlock(*paddr, *pLocalblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalBlockByHash: {
        T_SHA256 hash;
        T_LOCALBLOCK* pLocalblock = nullptr;
        MQMsgPop(msg, hash, pLocalblock);

        bool ret = GetLocalBlockByHash(hash, *pLocalblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalBlockByHeaderHash: {
        T_SHA256 headerhash;
        T_LOCALBLOCK* pLocalblock = nullptr;
        MQMsgPop(msg, headerhash, pLocalblock);

        bool ret = GetLocalBlockByHeaderHash(headerhash, *pLocalblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalHIDs: {
        uint64_t blockid;
        set<uint64>* psetHID = nullptr;
        MQMsgPop(msg, blockid, psetHID);
        GetLocalHIDs(blockid, *psetHID);
        break;
    }
    case SERVICE::GetLocalChainSpaceData: {
        string strbuf;
        bool ret = GetLocalChainSpaceData(strbuf);
        MQMsgPush(msg, ret, strbuf);
        break;
    }
    case SERVICE::AnalyzeChainSpaceData: {
        string strbuf;
        string nodeid;
        MQMsgPop(msg, strbuf, nodeid);
        AnalyzeChainSpaceData(strbuf, nodeid);
        break;
    }
    case SERVICE::GetHeaderHashMTRootData: {
        string strbuf;
        uint64_t headerid;
        MQMsgPop(msg, headerid);
        bool ret = GetHeaderHashMTRootData(headerid, strbuf);
        MQMsgPush(msg, ret, strbuf);
        break;
    }
    case SERVICE::AnalyzeHeaderHashMTRootData: {
        string strbuf;
        string nodeid;
        MQMsgPop(msg, strbuf, nodeid);
        AnalyzeHeaderHashMTRootData(strbuf, nodeid);
        break;
    }
    case SERVICE::UpdateHyperBlockCache: {
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);

        bool ret = updateHyperBlockCache(*pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetMulticastNodes: {
        vector<CUInt128>* pnodes;
        MQMsgPop(msg, pnodes);
        GetMulticastNodes(*pnodes);
        break;
    }
    case SERVICE::NoHyperBlock: {
        uint64_t blockid;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);
        NoHyperBlock(blockid, nodeid);
        break;
    }
    case SERVICE::PutHyperBlock: {
        T_HYPERBLOCK* pHyperblock = nullptr;
        string nodeid;
        vector<CUInt128>* pnodes = nullptr;
        MQMsgPop(msg, pHyperblock, nodeid, pnodes);
        PutHyperBlock(*pHyperblock, nodeid, *pnodes);
        break;
    }
    case SERVICE::SaveHyperblock: {
        T_HYPERBLOCK* pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);
        SaveHyperblock(*pHyperblock);
        break;
    }
    case SERVICE::GetHyperChainShow: {
        map<string, string>* pChainspaceShow = nullptr;
        MQMsgPop(msg, pChainspaceShow);
        GetHyperChainShow(*pChainspaceShow);
        break;
    }
    case SERVICE::GetHyperChainData: {
        map<uint64, set<string>>* pChainspaceData = nullptr;
        MQMsgPop(msg, pChainspaceData);
        GetHyperChainData(*pChainspaceData);
        break;
    }
    case SERVICE::GetLocalHIDsection: {
        vector <string>* pHidsection = nullptr;
        MQMsgPop(msg, pHidsection);
        GetLocalHIDsection(*pHidsection);
        break;
    }
    case SERVICE::GetLocalChainIDSize: {
        size_t idnums = GetLocalChainIDSize();
        MQMsgPush(msg, idnums);
        break;
    }
    case SERVICE::GetHyperBlockHealthInfo: {
        map<uint64, uint32>* pBlockHealthInfo = nullptr;
        MQMsgPop(msg, pBlockHealthInfo);
        GetHyperBlockHealthInfo(*pBlockHealthInfo);
        break;
    }
    case SERVICE::GetHeaderHashCacheLatestHID: {
        uint64 hid = GetHeaderHashCacheLatestHID();
        MQMsgPush(msg, hid);
        break;
    }
    case SERVICE::GetGlobalLatestHyperBlockNo: {
        uint64 hid = GetGlobalLatestHyperBlockNo();
        MQMsgPush(msg, hid);
        break;
    }
    case SERVICE::GetRemoteHyperBlockByID: {
        uint64 blockid = 0;
        MQMsgPop(msg, blockid);

        int ret = GetRemoteHyperBlockByID(blockid);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetRemoteHyperBlockByID_UntilSuccess: {
        uint64 startHID = 0;
        uint64 endHID = 0;
        string nodeid;
        MQMsgPop(msg, startHID, endHID, nodeid);

        GetRemoteHyperBlockByID_UntilSuccess(startHID, endHID, nodeid);
        return;
    }
    case SERVICE::GetRemoteHyperBlockByIDFromNode: {
        uint64 blockid = 0;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);

        GetRemoteHyperBlockByID(blockid, nodeid);
        return;
    }
    case SERVICE::BatchGetRemoteHyperBlockByIDFromNode: {
        uint64 blockid = 0;
        uint32 ncnt = 0;
        string nodeid;
        MQMsgPop(msg, blockid, ncnt, nodeid);

        BatchGetRemoteHyperBlockByID(blockid, ncnt, nodeid);
        return;
    }

    case SERVICE::GetRemoteBlockHeaderFromNode: {
        uint64 blockid = 0;
        uint16 range = 0;
        string nodeid;
        MQMsgPop(msg, blockid, range, nodeid);

        GetRemoteBlockHeader(blockid, range, nodeid);
        return;
    }
    case SERVICE::GetHyperBlockHeaderHash: {
        uint64 hid = 0;
        uint32 range = 0;
        vector<T_SHA256>* pvecheaderhash = nullptr;
        MQMsgPop(msg, hid, range, pvecheaderhash);

        bool ret = GetHyperBlockHeaderHash(hid, range, *pvecheaderhash);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::PutHyperBlockHeaderHash: {
        uint64 hid = 0;
        uint32 range = 0;
        vector<T_SHA256>* pvecheaderhash = nullptr;
        string nodeid;
        MQMsgPop(msg, hid, range, pvecheaderhash, nodeid);
        PutHyperBlockHeaderHash(hid, range, *pvecheaderhash, nodeid);
        break;
    }
    case SERVICE::GetHyperBlockHeader: {
        uint64 hid = 0;
        uint16 range = 0;
        vector<T_HYPERBLOCKHEADER>* pvecblockheader = nullptr;
        MQMsgPop(msg, hid, range, pvecblockheader);

        bool ret = GetHyperBlockHeader(hid, range, *pvecblockheader);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::PutHyperBlockHeader: {
        T_HYPERBLOCKHEADER* phyperblockheader = nullptr;
        string nodeid;
        MQMsgPop(msg, phyperblockheader, nodeid);
        PutHyperBlockHeader(*phyperblockheader, nodeid);
        break;
    }
    case SERVICE::PutHyperBlockHeaderList: {
        vector<T_HYPERBLOCKHEADER>* phyperblockheaderlist = nullptr;
        string nodeid;
        MQMsgPop(msg, phyperblockheaderlist, nodeid);
        PutHyperBlockHeaderList(*phyperblockheaderlist, nodeid);
        break;
    }
    case SERVICE::NoHyperBlockHeader: {
        uint64_t blockid;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);
        NoHyperBlockHeader(blockid, nodeid);
        break;
    }
    case SERVICE::MQCostStatistics: {
        string info = GetMQCostStatistics();
        MQMsgPush(msg, info);
        break;
    }

    default:
        break;
    }
    realwrk->reply(reply_who, msg);
}

void CHyperChainSpace::SyncBlockHeaderData(std::set<CUInt128>& activeNodes)
{
    if (m_chainspaceheaderID.empty())
        return;

    uint64 startHID = 0;
    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        //HCE: The starting block for INFORMAL_NET data validation is INFORMALNET_GENESISBLOCKID
        startHID = m_gensisblockID - 1;
    }

    uint64 nums = 0;
    uint16 range = 0;
    bool haveNewHeader = false;
    uint64 sync_header_hid = 0;

    for (auto it = m_chainspaceheaderID.begin(); it != m_chainspaceheaderID.end(); it++) {
        sync_header_hid = startHID;

        if (!m_chainspacesyncheaderID.empty() &&
            m_chainspacesyncheaderID.find(it->first) != m_chainspacesyncheaderID.end())
            sync_header_hid = m_chainspacesyncheaderID[it->first];

        if (sync_header_hid >= it->second)
            continue;

        if (activeNodes.count(CUInt128(it->first))) {
            nums = it->second - sync_header_hid;
            if (nums <= 0)
                continue;

            g_daily_logger->info("SyncBlockHeaderData() ---111---");
            g_console_logger->info("SyncBlockHeaderData() ---111---");

            range = (uint16)(nums > MAX_BLOCKHEADER_NUMS ? MAX_BLOCKHEADER_NUMS : nums);
            GetRemoteBlockHeader(sync_header_hid + 1, range, it->first);

            if (m_localHeaderReady)
                m_localHeaderReady = false;

            if (!haveNewHeader)
                haveNewHeader = true;
        }
    }

    if (!haveNewHeader && !m_localHeaderReady)
        m_localHeaderReady = true;
}

void CHyperChainSpace::SyncBlockHeaderData(std::set<CUInt128>& activeNodes, T_CHAININFO& chainInfo, bool isBestChain)
{
    if (!chainInfo.checked)
        return;

    uint64 nums = 0;
    uint16 range = 0;
    bool haveNewHeader = false;
    uint64 sync_header_hid = 0;

    for (auto& ir : chainInfo.nodelist) {
        if (activeNodes.count(CUInt128(ir))) {
            sync_header_hid = chainInfo.sync_header_hid;

            if (!m_chainspacesyncheaderID.empty() &&
                m_chainspacesyncheaderID.find(ir) != m_chainspacesyncheaderID.end())
                sync_header_hid = m_chainspacesyncheaderID[ir];

            if (sync_header_hid >= m_chainspaceheaderID[ir])
                continue;

            nums = m_chainspaceheaderID[ir] - sync_header_hid;
            if (nums <= 0)
                continue;

            g_daily_logger->info("SyncBlockHeaderData() ---222---");
            g_console_logger->info("SyncBlockHeaderData() ---222---");

            range = (uint16)(nums > MAX_BLOCKHEADER_NUMS ? MAX_BLOCKHEADER_NUMS : nums);
            GetRemoteBlockHeader(sync_header_hid + 1, range, ir);

            if (m_localHeaderReady)
                m_localHeaderReady = false;

            if (!haveNewHeader)
                haveNewHeader = true;
        }
    }

    if (isBestChain && !haveNewHeader && !m_localHeaderReady)
        m_localHeaderReady = true;
}

void CHyperChainSpace::SyncBlockHeaderData(std::set<CUInt128>& activeNodes, T_CHAININFO& chainInfo, uint64 headerHID)
{
    if (!chainInfo.checked)
        return;


    uint64 startHID = 0;
    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        //HCE: The starting block for INFORMAL_NET data validation is INFORMALNET_GENESISBLOCKID
        startHID = m_gensisblockID - 1;
    }

    if (chainInfo.sync_header_hid <= startHID) {
        //HCE: New node
        chainInfo.sync_header_hid = startHID;

        if (headerHID > 0) {
            //HCE: Rebooted node
            chainInfo.sync_header_hid = CheckDiffPos(startHID, headerHID, chainInfo.headerhash, chainInfo.headerinfo);
            g_daily_logger->info("SyncBlockHeaderData(), uiMaxHeaderID: [{}]，CheckDiffPos() return [{}]", headerHID, chainInfo.sync_header_hid);
            g_console_logger->info("SyncBlockHeaderData(), uiMaxHeaderID: [{}]，CheckDiffPos() return [{}]", headerHID, chainInfo.sync_header_hid);

            if (uiCollateMaxBlockNum == 0 || uiCollateMaxBlockNum > chainInfo.sync_header_hid)
                uiCollateMaxBlockNum = chainInfo.sync_header_hid;
        }
    }

    if (chainInfo.sync_header_hid >= chainInfo.sync_hash_hid) {
        return;
    }

    //for (uint64 hid = chainInfo.sync_header_hid + 1; hid <= chainInfo.sync_hash_hid; hid++) {
    //    T_SHA256 hhash = chainInfo.headerhash[hid];
    //    if (m_HeaderIndexMap.find(hhash) == m_HeaderIndexMap.end()/*!m_chainheaderhashSet.count(make_pair(hid, hhash))*/)
    //        break;

    //    chainInfo.sync_header_hid++;
    //}

    using seconds = std::chrono::duration<double, ratio<1>>;
    system_clock::time_point curr = system_clock::now();
    seconds timespan = std::chrono::duration_cast<seconds>(curr - chainInfo.sync_header_time);

    if (timespan.count() < 2)
        return;

    uint64 nums = chainInfo.sync_hash_hid - chainInfo.sync_header_hid;
    if (nums <= 0)
        return;

    g_daily_logger->info("SyncBlockHeaderData() ---333---");
    g_console_logger->info("SyncBlockHeaderData() ---333---");

    uint16 range = (uint16)(nums > MAX_BLOCKHEADER_NUMS ? MAX_BLOCKHEADER_NUMS : nums);
    for (auto& ir : chainInfo.nodelist) {
        if (activeNodes.count(CUInt128(ir))) {
            GetRemoteBlockHeader(chainInfo.sync_header_hid + 1, range, ir);

            if (m_localHeaderReady)
                m_localHeaderReady = false;

            chainInfo.sync_header_time = system_clock::now();
            break;
        }
    }
}

void CHyperChainSpace::SyncAllHyperBlockData()
{
    if (m_localHIDsection.size() == 1) {
        return;
    }

    //HCE: Get the list of active nodes
    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("SyncAllHyperBlockData failed! ActiveNodes empty!");
        g_console_logger->error("SyncAllHyperBlockData failed! ActiveNodes empty!");
        return;
    }

    int num = 0;
    int failnum = 0;
    uint64 syncHID = m_gensisblockID;

    for (; num < 20 && syncHID <= uiMaxBlockNum; syncHID++) {
        if (m_localHID.count(syncHID))
            continue;

        if (m_Chainspace.empty() || m_Chainspace.find(syncHID) == m_Chainspace.end())
            continue;

        int ret = GetRemoteHyperBlockByPreHash(syncHID, ActiveNodes);
        if (ret < 0) {
            failnum++;

            if (failnum >= 50)
                break;

            continue;
        }

        num++;
    }

    if (syncHID < uiMaxBlockNum) {
        _msghandler.registerTimer(30 * 1000, std::bind(&CHyperChainSpace::PullAllHyperBlock, this), true);
    }

}


void CHyperChainSpace::SyncHyperBlockData()
{
    uint64 localHID = GetLocalLatestHID();

    if (localHID >= uiMaxHeaderID) {
        m_LatestBlockReady = true;
        return;
    }

    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("SyncHyperBlockData failed! ActiveNodes empty!");
        g_console_logger->error("SyncHyperBlockData failed! ActiveNodes empty!");
        return;
    }

    uint64 syncHID = uiMaxHeaderID;
    int ret = GetRemoteHyperBlockByPreHash(syncHID, ActiveNodes);
    if (ret < 0)
        return;

}

void CHyperChainSpace::PullHeaderHashMTRootInfo()
{
    auto acss = m_chainactioncoststt.NewStatt("PullHeaderHashMTRootInfo");
    if (_isstop) {
        return;
    }

    if (!m_ChainspaceReady || m_chainspaceheaderID.empty()) {
        return;
    }

    /*if (m_localHeaderReady) {
        return;
    }*/

    uint64 headerid;
    vector<uint16> locationSection;

    for (auto it = m_chainspaceheaderID.begin(); it != m_chainspaceheaderID.end(); it++) {
        if (it->second < m_gensisblockID + MAX_BLOCKHEADER_NUMS)
            continue;

        headerid = it->second - MATURITY_SIZE;

        T_HEADERINFO headerinfo;
        headerinfo.Set(headerid);

        if (m_chainspaceheader.empty()) {
            m_minheaderinfo = headerinfo;
            m_chainspaceheader[it->first] = std::move(headerinfo);
            continue;
        }

        //HCE: Each node is assigned a value only once
        if (m_chainspaceheader.find(it->first) != m_chainspaceheader.end())
            continue;

        if (headerinfo.section[0] == m_minheaderinfo.section[0]) {
            m_chainspaceheader[it->first] = std::move(headerinfo);
            continue;
        }

        if (headerinfo.section[0] > m_minheaderinfo.section[0]) {
            headerinfo.Set(m_minheaderinfo.id);
            m_chainspaceheader[it->first] = std::move(headerinfo);
            continue;
        }

        if (headerinfo.section[0] < m_minheaderinfo.section[0]) {
            m_minheaderinfo = headerinfo;
            m_chainspaceheader[it->first] = std::move(headerinfo);
            continue;
        }
    }

    //HC: 当所有邻居节点的链空间数据高度小于MAX_BLOCKHEADER_NUMS时，m_HaveFixedData赋值为CHECK_RESULT::INVALID_DATA，
    //HC: 程序跳过PullHeaderHashMTRootInfo和PullHeaderHashInfo逻辑，直接进入PullBlockHeader逻辑；
    //HC: 否则m_HaveFixedData赋值为CHECK_RESULT::VALID_DATA
    //HCE: When the chain space data height of all neighbor nodes is less than MAX_BLOCKHEADER_NUMS, m_HaveFixedData is assigned CHECK_RESULT::INVALID_DATA, 
    //HCE: The program skips PullHeaderHashMTRootInfo and PullHeaderHashInfo and goes directly to PullBlockHeader;
    //HCE: Otherwise, m_HaveFixedData is assigned CHECK_RESULT::VALID_DATA
    if (m_chainspaceheader.empty()) {
        m_HaveFixedData = CHECK_RESULT::INVALID_DATA;
        return;
    }
    
    m_HaveFixedData = CHECK_RESULT::VALID_DATA;

    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("PullHeaderHashMTRootInfo failed! ActiveNodes empty!");
        g_console_logger->error("PullHeaderHashMTRootInfo failed! ActiveNodes empty!");
        return;
    }

    for (auto iter = m_chainspaceheader.begin(); iter != m_chainspaceheader.end(); iter++) {
        if (iter->second.ready)
            continue;

        using seconds = std::chrono::duration<double, ratio<1>>;
        system_clock::time_point curr = system_clock::now();
        seconds timespan = std::chrono::duration_cast<seconds>(curr - iter->second.sync_time);

        if (timespan.count() < 2)
            continue;

        if (iter->second.section[0] > m_minheaderinfo.section[0])
            (iter->second).Set(m_minheaderinfo.id);

        if (ActiveNodes.count(CUInt128(iter->first))) {
            PullHeaderHashMTRoot(iter->second.id, iter->first);
            g_daily_logger->info("PullHeaderHashMTRoot() hid: [{}], nodeid: [{}]", iter->second.id, iter->first);
            g_console_logger->info("PullHeaderHashMTRoot() hid: [{}], nodeid: [{}]", iter->second.id, iter->first);
            iter->second.sync_time = system_clock::now();
            break;
        }
    }
}

void CHyperChainSpace::DealwithChainInfo()
{
    auto acss = m_chainactioncoststt.NewStatt("DealwithChainInfo");
    if (_isstop) {
        return;
    }

    if (!m_ChainspaceReady) {
        return;
    }

    if (CHECK_RESULT::VALID_DATA != m_HaveFixedData || m_chainspaceheader.empty()) {
        return;
    }

    bool found;
    for (auto it = m_chainspaceheader.begin(); it != m_chainspaceheader.end(); it++) {
        found = false;

        if (!it->second.ready)
            continue;

        if (m_chainInfoMap.empty()) {
            T_CHAININFO cinfo;
            cinfo.nodelist.push_back(it->first);
            cinfo.headerinfo = it->second;
            m_chainInfoMap[0] = std::move(cinfo);

            continue;
        }

        for (auto iter = m_chainInfoMap.begin(); iter != m_chainInfoMap.end(); iter++) {
            T_HEADERINFO hinfo = iter->second.headerinfo;
            if (it->second.IsSameChain(hinfo)) {
                if (it->second.id > hinfo.id && !iter->second.checked) {
                    iter->second.headerinfo = it->second;
                    if (*iter->second.nodelist.begin() != it->first) {
                        iter->second.nodelist.remove(it->first);
                        iter->second.nodelist.push_front(it->first);
                    }
                }
                else {
                    if (find(iter->second.nodelist.begin(), iter->second.nodelist.end(), it->first) == iter->second.nodelist.end())
                        iter->second.nodelist.push_back(it->first);
                }

                found = true;
                break;
            }
        }

        if (!found) {
            T_CHAININFO cinfo;

            uint8 n = m_chainInfoMap.size();
            cinfo.nodelist.push_back(it->first);
            cinfo.headerinfo = it->second;
            m_chainInfoMap[n] = std::move(cinfo);
        }
    }

    if (!m_chainInfoMap.empty() && !m_ChainInfoReady)
        m_ChainInfoReady = true;

    g_daily_logger->info("DealwithChainInfo() m_chainInfoMap.size: [{}], m_ChainInfoReady: [{}]", m_chainInfoMap.size(), m_ChainInfoReady);
    g_console_logger->info("DealwithChainInfo() m_chainInfoMap.size: [{}], m_ChainInfoReady: [{}]", m_chainInfoMap.size(), m_ChainInfoReady);
}

void CHyperChainSpace::PullHeaderHashInfo()
{
    auto acss = m_chainactioncoststt.NewStatt("PullHeaderHashInfo");
    if (_isstop)
        return;

    if (!m_ChainInfoReady)
        return;

    if (CHECK_RESULT::VALID_DATA != m_HaveFixedData || m_chainInfoMap.empty()) {
        return;
    }

    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("PullHeaderHashInfo failed! ActiveNodes empty!");
        g_console_logger->error("PullHeaderHashInfo failed! ActiveNodes empty!");
        return;
    }

    uint64 startHID = 0;
    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        startHID = m_gensisblockID - 1;
    }

    /*for (auto iter = m_chainInfoMap.begin(); iter != m_chainInfoMap.end(); iter++) {
        if (iter->second.nodelist.size() > (m_chainspaceheader.size() / 2)) {
            m_bestchainID = iter->first;
            break;
        }
    }*/

    for (auto iter = m_chainInfoMap.begin(); iter != m_chainInfoMap.end(); iter++) {
        if (iter->second.sync_hash_hid < startHID)
            iter->second.sync_hash_hid = startHID;

        g_daily_logger->info("PullHeaderHashInfo() m_chainInfoMap[{}], sync_hash_hid: [{}], headerinfo.id: [{}]",
            iter->first, iter->second.sync_hash_hid, iter->second.headerinfo.id);
        g_console_logger->info("PullHeaderHashInfo() m_chainInfoMap[{}], sync_hash_hid: [{}], headerinfo.id: [{}]",
            iter->first, iter->second.sync_hash_hid, iter->second.headerinfo.id);

        if (iter->second.sync_hash_hid < iter->second.headerinfo.id) {
            //TODO: 链数据同步过程中，邻居节点发生了链切换如何处理
            if (iter->second.checked) {
                iter->second.checked = false;
            }

            using seconds = std::chrono::duration<double, ratio<1>>;
            system_clock::time_point curr = system_clock::now();
            seconds timespan = std::chrono::duration_cast<seconds>(curr - iter->second.sync_hash_time);

            if (timespan.count() < 2)
                return;

            uint64 nums = iter->second.headerinfo.id - iter->second.sync_hash_hid;
            uint32 range = (uint32)(nums > MAX_BLOCKHEADERHASH_NUMS ? MAX_BLOCKHEADERHASH_NUMS : nums);

            for (auto& ir : iter->second.nodelist) {
                if (ActiveNodes.count(CUInt128(ir))) {
                    PullHeaderHash(iter->second.sync_hash_hid + 1, range, ir);
                    g_daily_logger->info("PullHeaderHash() hid: [{}], range: [{}], nodeid: [{}]",
                        iter->second.sync_hash_hid + 1, range, ir);
                    g_console_logger->info("PullHeaderHash() hid: [{}], range: [{}], nodeid: [{}]",
                        iter->second.sync_hash_hid + 1, range, ir);
                    iter->second.sync_hash_time = system_clock::now();
                    break;
                }
            }
        }
    }
}

void CHyperChainSpace::CheckLocalHeaderReady()
{
    if (m_localHeaderIDsection.empty() || m_localHeaderIDsection.size() > 1) {
        m_localHeaderReady = false;
        return;
    }

    if ((uiMaxHeaderID != UINT64_MAX && uiMaxHeaderID >= uiGlobalMaxBlockNum) || m_db->isHeaderIndexExisted(uiGlobalMaxBlockNum)) {
        m_localHeaderReady = true;
    }
}

void CHyperChainSpace::PullBlockHeader()
{
    auto acss = m_chainactioncoststt.NewStatt("PullBlockHeader");
    if (_isstop) {
        return;
    }

    if (!m_ChainspaceReady) {
        return;
    }

    std::set<CUInt128> ActiveNodes;
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty()) {
        g_daily_logger->error("PullBlockHeader failed! ActiveNodes empty!");
        g_console_logger->error("PullBlockHeader failed! ActiveNodes empty!");
        return;
    }

    CheckLocalHeaderReady();

    if (CHECK_RESULT::INVALID_DATA == m_HaveFixedData) {
        SyncBlockHeaderData(ActiveNodes);
        return;
    }

    if (m_chainInfoMap.empty())
        return;

    if (m_chainInfoMap.size() > 1) {
        for (auto iter = m_chainInfoMap.begin(); iter != m_chainInfoMap.end(); iter++) {
            if (iter->second.checked && iter->second.nodelist.size() > (m_chainspaceheader.size() / 2)) {
                m_bestchainID = iter->first;
                break;
            }
        }
    }

    uint64 headerHID = uiMaxHeaderID;

    if (m_bestchainID != UINT8_MAX) {
        if (m_chainInfoMap[m_bestchainID].checked) {
            if (m_chainInfoMap[m_bestchainID].sync_header_hid < m_chainInfoMap[m_bestchainID].sync_hash_hid) {
                SyncBlockHeaderData(ActiveNodes, m_chainInfoMap[m_bestchainID], headerHID);
                return;
            }

            SyncBlockHeaderData(ActiveNodes, m_chainInfoMap[m_bestchainID], true);
            return;
        }
    }

    for (auto iter = m_chainInfoMap.begin(); iter != m_chainInfoMap.end(); iter++) {
        if (iter->second.checked) {
            if (iter->second.sync_header_hid < iter->second.sync_hash_hid) {
                SyncBlockHeaderData(ActiveNodes, iter->second, headerHID);
                return;
            }

            SyncBlockHeaderData(ActiveNodes, iter->second, false);
            return;
        }
    }
}

string CHyperChainSpace::GetPullingHyperBlock()
{
    std::lock_guard<boost::fibers::mutex> guard(m_pullingHBfibermtx);

    stringstream ss;
    for (auto& elm : m_mapPullingHyperBlock) {
        ss << StringFormat("HID: %d   %s   %s   %d\n", elm.first,
            toReadableTime(elm.second.firstrequest),
            toReadableTime(elm.second.lastrequest),
            elm.second.nTimes);
    }
    if (ss.str().empty()) {
        ss << "No any hyper block is pulling\n";
    }
    return ss.str();
}

void CHyperChainSpace::PullHyperBlockRepeatly()
{
    auto acss = m_chainactioncoststt.NewStatt("PullHyperBlockRepeatly");
    if (!m_pullingHBfibermtx.try_lock())
        return;

    defer{
        m_pullingHBfibermtx.unlock();
    };

    auto now = std::time(nullptr);
    int nTotalNum = 0;
    std::list<uint32_t> waitingremove;
    for (auto &elm : m_mapPullingHyperBlock) {
        if (_isstop || nTotalNum >= 5) {
            break;
        }

        if (m_localHID.count(elm.first)) {
            waitingremove.push_back(elm.first);
            continue;
        }
        if (elm.second.nTimes == 0 || now - elm.second.lastrequest > 18) {
            elm.second.lastrequest = now;
            elm.second.nTimes++;
            GetRemoteHyperBlockByID(elm.first);
            nTotalNum++;
        }
    }

    for (auto hid : waitingremove) {
        m_mapPullingHyperBlock.erase(hid);
    }
}

void CHyperChainSpace::PullHyperBlock()
{
    auto acss = m_chainactioncoststt.NewStatt("PullHyperBlock");
    if (_isstop) {
        return;
    }

    if (!m_localHeaderReady) {
        return;
    }

    SyncHyperBlockData();
}

void CHyperChainSpace::PullAllHyperBlock()
{
    if (_isstop) {
        return;
    }

    if (!m_localHeaderReady) {
        return;
    }

    if (m_FullNode) {
        SyncAllHyperBlockData();
    }
}

void CHyperChainSpace::CollatingChainSpace()
{
    if (_isstop) {
        return;
    }

    CollatingChainSpaceDate();
}

//HCE: Get once and clear
void CHyperChainSpace::GetMulticastNodes(vector<CUInt128>& nodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        nodes = m_MulticastNodes;
        m_MulticastNodes.clear();
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetMulticastNodes, &nodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::PutHyperBlock(T_HYPERBLOCK& hyperblock, string from_nodeid, vector<CUInt128>& multicastnodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        uint64 blockid = hyperblock.GetID();

        if (0 == from_nodeid.compare("myself")) {
            //HCE: block id check
            if (uiMaxBlockNum > blockid) {
                g_daily_logger->warn("Create invalid hyper block: [{}] for block id check failed, Current MaxBlockID: [{}]", blockid, uiMaxBlockNum);
                g_console_logger->warn("Create invalid hyper block: [{}] for block id check failed, Current MaxBlockID: [{}]", blockid, uiMaxBlockNum);
                return;
            }

            m_MulticastNodes = multicastnodes;
        }

        //HCE: dependency check
        CHECK_RESULT ret = CheckDependency(hyperblock, from_nodeid);
        if (CHECK_RESULT::VALID_DATA == ret) {
            //HCE: put hyper block into hyper block cache
            updateHyperBlockCache(hyperblock);

            //HCE: clear m_SyncBlockMap data
            if (!m_SyncBlockMap.empty()) {
                auto it = m_SyncBlockMap.find(blockid);
                if (it == m_SyncBlockMap.end())
                    return;

                if (find(it->second.nodelist.begin(), it->second.nodelist.end(), from_nodeid) != it->second.nodelist.end()) {
                    m_SyncBlockMap.erase(it);
                }
            }
            return;
        }

        if (0 == from_nodeid.compare("myself")) {
            g_daily_logger->warn("Create invalid hyper block: {} for dependency check failed", blockid);
            g_console_logger->warn("Create invalid hyper block: {} for dependency check failed", blockid);
            return;
        }

        if (CHECK_RESULT::INVALID_DATA == ret) {
            g_daily_logger->warn("Received invalid hyper block: {} for dependency check failed", blockid);
            g_console_logger->warn("Received invalid hyper block: {} for dependency check failed", blockid);
            return;
        }

        if (CHECK_RESULT::UNCONFIRMED_DATA == ret) {
            g_console_logger->warn("Received hyper block: {} for dependency check failed", blockid);

            if (!m_localHeaderReady || blockid - MATURITY_SIZE > uiMaxHeaderID) {
                return;
            }

            uint64 startid = blockid > MATURITY_SIZE ? blockid - MATURITY_SIZE : 0;
            if (pro_ver == ProtocolVer::NET::INFORMAL_NET && startid < m_gensisblockID) {
                //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
                startid = m_gensisblockID;
            }

            uint16 range = (uint16)(blockid - startid);
            PullBlockHeaderData(startid + 1, range, from_nodeid);
            g_daily_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
            g_console_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
        }
    }
    else {
        //MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlock, &hyperblock, from_nodeid, &multicastnodes);
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlock, &hyperblock, from_nodeid, &multicastnodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::GetHyperBlockHeader(uint64 hid, uint16 range, vector<T_HYPERBLOCKHEADER>& vecblockheader)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (!m_db) {
            return false;
        }

        vector<T_SHA256> vecheaderhash;
        if (!GetHyperBlockHeaderHash(hid, range, vecheaderhash))
            return false;

        map<T_SHA256, T_HYPERBLOCKHEADER> mapblockheader;
        m_db->getHeadersByID(mapblockheader, hid, range + hid);

        for (auto& headerhash : vecheaderhash) {
            if (mapblockheader.count(headerhash))
                vecblockheader.push_back(mapblockheader[headerhash]);
        }

        return vecblockheader.size() > 0;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHeader, hid, range, &vecblockheader);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

//HCE: We choose the hyper block chain whose total_weight(local blocks counts) is more.
//HCE: If total_weight(local blocks counts) is same, we choose the hyper block chain whose ctime earlier.
//HCE: When total_weight and ctime both are same, we choose the hyper block chain whose hash is more less.
bool CHyperChainSpace::isBetterThanLocalChain(const T_HEADERINDEX& localHeaderIndex, const T_HEADERINDEX& HeaderIndex)
{
    if (HeaderIndex.total_weight < localHeaderIndex.total_weight) {
        return false;
    }

    if (HeaderIndex.total_weight > localHeaderIndex.total_weight) {
        return true;
    }

    if (HeaderIndex.ctime > localHeaderIndex.ctime) {
        return false;
    }

    if (HeaderIndex.ctime < localHeaderIndex.ctime) {
        return true;
    }

    if (HeaderIndex.headerhash < localHeaderIndex.headerhash) {
        return true;
    }

    return false;
}

void CHyperChainSpace::CollatingChainSpaceDate()
{
    int num = 0;
    int ret = 0;
    bool foundBlocksHeaderHash = false;
    T_SHA256 headerhash;
    uint64 maxblockid = uiCollateMaxBlockNum > 0 ? uiCollateMaxBlockNum : uiMaxBlockNum;

    if (!m_LatestBlockReady)
        return;

    if (maxblockid <= m_gensisblockID + MATURITY_SIZE)
        return;

    uint64 startid = maxblockid - MATURITY_SIZE;
    vector<T_SHA256> vecheaderhash;

    g_daily_logger->info("CollatingChainSpaceDate, startid: [{}]", startid);

    for (uint64 blockid = startid; blockid > m_gensisblockID; blockid--) {
        if (!GetHyperBlockHeaderHash(blockid, headerhash)) {
            g_daily_logger->error("CollatingChainSpaceDate() GetHyperBlockHeaderHash failed! hid:[{}]", blockid);
            g_console_logger->warn("CollatingChainSpaceDate() GetHyperBlockHeaderHash failed! hid:[{}]", blockid);
            continue;
        }

        vecheaderhash.clear();
        ret = m_db->getFurcatedHeaderHash(blockid, headerhash, vecheaderhash);
        if (ret != 0) {
            g_daily_logger->error("CollatingChainSpaceDate() getFurcatedHeaderHash failed! hid:[{}], ret:[{}]", blockid, ret);
            g_console_logger->warn("CollatingChainSpaceDate() getFurcatedHeaderHash failed! hid:[{}], ret:[{}]", blockid, ret);
            continue;
        }

        if (vecheaderhash.empty()) {
            num++;
            if (num >= MATURITY_SIZE) {
                //HC: 连续MATURITY_SIZE个块都没有分叉
                //HCE: There were no bifurcations for MATURITY_SIZE consecutive data
                break;
            }

            continue;
        }

        num = 0;
        for (auto& hhash : vecheaderhash) {
            foundBlocksHeaderHash = false;

            //HC: 清理BlocksHeaderHash缓存中的备选链
            //HCE: Clean up alternative chains in the BlocksHeaderHash cache
            for (auto tr = m_BlocksHeaderHash.begin(); tr != m_BlocksHeaderHash.end(); tr++) {
                if ((*tr).empty())
                    continue;

                if (*((*tr).begin()) != make_pair(blockid, hhash))
                    continue;

                DBmgr::Transaction t = m_db->beginTran();
                for (auto& hh : (*tr)) {
                    //HC: 清理HeaderIndex缓存和磁盘数据
                    //HCE: Clean up the HeaderIndex cache and disk data
                    if (m_HeaderIndexMap.find(hh.second) != m_HeaderIndexMap.end()) {
                        m_HeaderIndexMap.erase(hh.second);
                        m_db->deleteHeaderIndex(hh.first, hh.second);
                    }

                    //HC: 清理超块和子块磁盘数据
                    //HCE: Clean up the hyperblock and localblocks data
                    m_db->deleteHyperblockAndLocalblock(hh.first, hh.second);

                    //HCE: Clean up header
                    m_db->deleteHeader(hh.first, hh.second);

                    m_chainheaderhashSet.erase(make_pair(hh.first, hh.second));
                }
                t.set_trans_succ();


                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, hhash);
                g_daily_logger->info("CollatingChainSpaceDate, clear m_BlocksHeaderHash [{}, {}]", blockid, HeaderHash);

                (*tr).clear();
                m_BlocksHeaderHash.erase(tr);
                foundBlocksHeaderHash = true;
                break;
            }

            if (foundBlocksHeaderHash)
                continue;

            DBmgr::Transaction t = m_db->beginTran();

            //HC: 清理HeaderIndex缓存和磁盘数据
            //HCE: Clean up the HeaderIndex cache and disk data
            if (m_HeaderIndexMap.find(hhash) != m_HeaderIndexMap.end()) {
                m_HeaderIndexMap.erase(hhash);
                m_db->deleteHeaderIndex(blockid, hhash);
            }

            //HC: 清理超块和子块磁盘数据
            //HCE: Clean up the hyperblock and localblocks data
            m_db->deleteHyperblockAndLocalblock(blockid, hhash);

            //HCE: Clean up header
            m_db->deleteHeader(blockid, hhash);

            m_chainheaderhashSet.erase(make_pair(blockid, hhash));

            t.set_trans_succ();
        }
    }

    //HC: 清理SingleHeader缓存和磁盘数据
    //HCE: Clean up the SingleHeader cache and disk data
    for (auto it = m_SingleHeaderMap.begin(); it != m_SingleHeaderMap.end(); ) {
        if (it->first > startid)
            break;

        m_SingleHeaderMap.erase(it++);
    }

    m_db->rollbackSingleHeaderInfo(startid);

    if (uiCollateMaxBlockNum > 0) {
        uiCollateMaxBlockNum += 20;

        if (uiCollateMaxBlockNum >= uiMaxBlockNum)
            uiCollateMaxBlockNum = 0;
    }
}

bool CHyperChainSpace::SaveHeaderListIndex(map<pair<uint64, T_SHA256>, T_HYPERBLOCKHEADER>& headerMap, string from_nodeid, bool& Flag)
{
    int ret;
    bool isBetter = false;
    bool AcceptFlag = false;
    bool IsGensisBlock = false;
    uint64 total = 0;
    uint16 weight = 0;
    uint64 hid = 0;
    T_SHA256 headerhash;

    auto bg = headerMap.begin();
    uint64 begin_hid = bg->first.first;
    T_SHA256 begin_headerhash = bg->first.second;
    T_SHA256 begin_preheaderhash = bg->second.GetPreHeaderHash();

    g_daily_logger->info("SaveHeaderListIndex, begin_hid: [{}], size: [{}]", begin_hid, headerMap.size());

    //using seconds = std::chrono::duration<double, ratio<1>>;
    //seconds timespan;

    if ((pro_ver == ProtocolVer::NET::SAND_BOX && begin_hid == m_gensisblockID) || (pro_ver == ProtocolVer::NET::INFORMAL_NET &&
        begin_hid == m_gensisblockID && begin_headerhash == m_gensisblockHeaderhash)) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        total = 0;
        AcceptFlag = true;
        IsGensisBlock = true;
        m_gensisblockHeaderhash = begin_headerhash;

        //HC: NodeManager模块，用来区分不同创始块网络
        genesis_block_header_hash = begin_headerhash;
    }
    else {
        auto it = m_HeaderIndexMap.find(begin_preheaderhash);
        if (it != m_HeaderIndexMap.end()) {
            total = it->second.total_weight;
            AcceptFlag = true;
        }
    }

    if (!AcceptFlag) {
        vector<T_SINGLEHEADER> vecSingleHeader;
        for (auto it = headerMap.begin(); it != headerMap.end(); it++) {
            if (isInSingleHeaderMap(it->first.first, it->first.second))
                continue;

            hid = it->first.first;
            headerhash = it->first.second;

            //HCE: SingleHeader
            T_SINGLEHEADER singleheader;
            singleheader.id = hid;
            singleheader.headerhash = headerhash;
            singleheader.preheaderhash = it->second.GetPreHeaderHash();
            singleheader.from_id = from_nodeid;

            vecSingleHeader.push_back(singleheader);
            m_SingleHeaderMap.insert(make_pair(hid, std::move(singleheader)));
        }

        if (!vecSingleHeader.empty()) {
            //system_clock::time_point time1 = system_clock::now();

            DBmgr::Transaction t = m_db->beginTran();
            for (auto& single_header : vecSingleHeader) {
                //HCE: save to singleheader table
                ret = m_db->updateSingleHeaderInfo(single_header);
                if (ret != 0) {
                    char HeaderHash[FILESIZEL] = { 0 };
                    CCommonStruct::Hash256ToStr(HeaderHash, single_header.headerhash);
                    g_daily_logger->error("updateSingleHeaderInfo failed!({}) id: [{}], headerhash: [{}]", ret, single_header.id, HeaderHash);
                    g_console_logger->warn("updateSingleHeaderInfo failed!({}) id: [{}], headerhash: [{}]", ret, single_header.id, HeaderHash);
                }
            }
            t.set_trans_succ();

            //system_clock::time_point time2 = system_clock::now();
            //timespan = std::chrono::duration_cast<seconds>(time2 - time1);
            //g_basic_logger->info("updateSingleHeaderInfo( begin_hid: {} ) spend [{}] second", begin_hid, timespan.count());
        }
        return isBetter;
    }

    vector<T_HEADERINDEX> vecHeaderIndex;

    for (auto it = headerMap.begin(); it != headerMap.end(); it++) {
        hid = it->first.first;
        headerhash = it->first.second;

        auto irt = m_HeaderIndexMap.find(headerhash);
        if (irt != m_HeaderIndexMap.end()) {
            total = irt->second.total_weight;
            continue;
        }
        else {
            weight = (uint16)it->second.GetChildBlockCount();

            T_HEADERINDEX headerindex;

            headerindex.id = hid;
            headerindex.prehash = it->second.GetPreHash();
            headerindex.headerhash = headerhash;
            headerindex.preheaderhash = it->second.GetPreHeaderHash();
            headerindex.ctime = it->second.GetCTime();
            headerindex.weight = weight;
            headerindex.total_weight = total + weight;
            headerindex.from_id = from_nodeid;

            total = headerindex.total_weight;

            vecHeaderIndex.push_back(headerindex);

            m_HeaderIndexMap[headerhash] = std::move(headerindex);
        }
    }

    if (!vecHeaderIndex.empty()) {
        //system_clock::time_point time3 = system_clock::now();

        DBmgr::Transaction t = m_db->beginTran();
        for (auto& header_index : vecHeaderIndex) {
            //HCE: save to headerindex table
            ret = m_db->updateHeaderIndex(header_index);
            if (ret != 0) {
                g_daily_logger->error("updateHeaderIndex failed!({}) hid: [{}]", ret, header_index.id);
                g_console_logger->warn("updateHeaderIndex failed!({}) hid: [{}]", ret, header_index.id);
            }
        }
        t.set_trans_succ();

        //system_clock::time_point time4 = system_clock::now();
        //timespan = std::chrono::duration_cast<seconds>(time4 - time3);
        //g_basic_logger->info("updateHeaderIndex( begin_hid: {} ) spend [{}] second", begin_hid, timespan.count());
    }

    //HC: 检查超块头是否可以加入本地最优链
    //HCE: Check whether the superblock can join the local optimal chain
    if (IsGensisBlock == true ||
        (!m_HeaderHashMap.empty() &&
            uiMaxHeaderID == begin_hid - 1 &&
            m_HeaderHashMap[uiMaxHeaderID] == begin_preheaderhash)) {

        //system_clock::time_point time5 = system_clock::now();

        DBmgr::Transaction t = m_db->beginTran();
        for (auto it = headerMap.begin(); it != headerMap.end(); it++) {
            hid = it->first.first;
            headerhash = it->first.second;
            //HC: 加入最优链末尾
            //HCE: Add to the end of the optimal chain
            m_HeaderHashMap[hid] = headerhash;
            m_db->updateHeaderHashInfo(hid, headerhash);
            m_localHeaderID.insert(hid);
        }
        t.set_trans_succ();

        //system_clock::time_point time6 = system_clock::now();
        //timespan = std::chrono::duration_cast<seconds>(time6 - time5);
        //g_basic_logger->info("updateHeaderHashInfo( begin_hid: {} ) spend [{}] second", begin_hid, timespan.count());

        GenerateHIDSection(m_localHeaderID, m_localHeaderIDsection);

        uiMaxHeaderID = GetMaxHeaderID();

        /*char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_console_logger->info("IsBestHeader {} [{}]", hid, HeaderHash);*/

        Flag = true;

        return isBetter;
    }

    //HC: 加入备选链末尾
    //HCE: Add to the end of the alternative chain
    bool finded = false;
    for (auto tr = m_BlocksHeaderHash.begin(); tr != m_BlocksHeaderHash.end(); tr++) {
        if ((*tr).empty())
            continue;

        auto end = (*tr).rbegin();
        if (*end == make_pair(begin_hid - 1, begin_preheaderhash)) {
            for (auto it = headerMap.begin(); it != headerMap.end(); it++) {
                (*tr).push_back(it->first);

                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, it->first.second);
                g_daily_logger->info("SaveHeaderListIndex, push_back[{}, {}]", it->first.first, HeaderHash);
            }

            g_daily_logger->info("SaveHeaderListIndex, 111 change m_HashChain");
            m_HashChain = tr;
            finded = true;
            break;
        }

        auto ir = headerMap.find(*end);
        if (ir != headerMap.end()) {
            for (auto it = ir++; it != headerMap.end(); it++) {
                (*tr).push_back(it->first);

                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, it->first.second);
                g_daily_logger->info("SaveHeaderListIndex, push_back[{}, {}]", it->first.first, HeaderHash);
            }

            g_daily_logger->info("SaveHeaderListIndex, 222 change m_HashChain");
            m_HashChain = tr;
            finded = true;
            break;
        }
    }

    if (!finded) {
        list<pair<uint64, T_SHA256>> listhash;
        for (auto it = headerMap.begin(); it != headerMap.end(); it++) {
            listhash.emplace_back(it->first);
        }
        m_BlocksHeaderHash.push_back(std::move(listhash));
        g_daily_logger->info("SaveHeaderListIndex, 333 change m_HashChain");
        m_HashChain = m_BlocksHeaderHash.end() - 1;
    }

    T_HEADERINDEX LBestHeaderIndex = m_HeaderIndexMap[m_HeaderHashMap[uiMaxHeaderID]];
    T_HEADERINDEX headerindex = m_HeaderIndexMap[(*m_HashChain).rbegin()->second];

    if (isBetterThanLocalChain(LBestHeaderIndex, headerindex)) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerindex.headerhash);
        g_daily_logger->info("isBetterThanLocalChain is true. id:[{}], total_weight:[{}], headerhash:[{}]",
            headerindex.id, headerindex.total_weight, HeaderHash);

        char LHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(LHeaderHash, LBestHeaderIndex.headerhash);
        g_daily_logger->info("isBetterThanLocalChain is true. local id:[{}], local total_weight:[{}], local headerhash:[{}]",
            LBestHeaderIndex.id, LBestHeaderIndex.total_weight, LHeaderHash);

        isBetter = true;

        return isBetter;
    }

    Flag = true;

    return isBetter;
}

bool CHyperChainSpace::SaveHeaderIndex(T_SHA256 headerhash, T_SHA256 preheaderhash, T_HYPERBLOCKHEADER header, string from_nodeid, bool& Flag)
{
    int ret;
    bool isBetter = false;
    bool AcceptFlag = false;
    bool IsGensisBlock = false;
    uint64 total = 0;
    uint16 weight = 0;
    uint64 hid = header.GetID();

    char HeaderHash[FILESIZEL] = { 0 };
    CCommonStruct::Hash256ToStr(HeaderHash, headerhash);

    g_daily_logger->info("SaveHeaderIndex, hid: [{}], headerhash: [{}]", hid, HeaderHash);

    if ((pro_ver == ProtocolVer::NET::SAND_BOX && hid == m_gensisblockID) || (pro_ver == ProtocolVer::NET::INFORMAL_NET &&
        hid == m_gensisblockID && headerhash == m_gensisblockHeaderhash)) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        total = 0;
        AcceptFlag = true;
        IsGensisBlock = true;
        m_gensisblockHeaderhash = headerhash;

        //HC: NodeManager模块，用来区分不同创始块网络
        genesis_block_header_hash = headerhash;
    }
    else {
        auto it = m_HeaderIndexMap.find(preheaderhash);
        if (it != m_HeaderIndexMap.end()) {
            total = it->second.total_weight;
            AcceptFlag = true;
        }
    }

    if (!AcceptFlag) {
        if (!isInSingleHeaderMap(hid, headerhash)) {
            //HCE: SingleHeader
            T_SINGLEHEADER singleheader;

            singleheader.id = hid;
            singleheader.headerhash = headerhash;
            singleheader.preheaderhash = preheaderhash;
            singleheader.from_id = from_nodeid;

            m_SingleHeaderMap.insert(make_pair(hid, std::move(singleheader)));

            //HCE: save to singleheader table
            ret = m_db->updateSingleHeaderInfo(singleheader);
            if (ret != 0) {
                /*char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, headerhash);*/
                g_daily_logger->error("updateSingleHeaderInfo failed!({}) id: [{}], headerhash: [{}]", ret, hid, HeaderHash);
                g_console_logger->warn("updateSingleHeaderInfo failed!({}) id: [{}], headerhash: [{}]", ret, hid, HeaderHash);
            }

            //HC: 前一个块头不存在，向来源节点要前MATURITY_SIZE个块头
            /*if (m_SingleHeaderMap.find(preheaderhash) == m_SingleHeaderMap.end()){
                uint64 startid = hid > MATURITY_SIZE ? hid - MATURITY_SIZE : 0;
                if (pro_ver ==  ProtocolVer::NET::INFORMAL_NET && startid < INFORMALNET_GENESISBLOCKID) {
                    HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
                    startid = INFORMALNET_GENESISBLOCKID;
                }

                uint16 range = hid - startid;
                PullBlockHeaderData(startid + 1, range, from_nodeid);
                g_console_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
            }*/
        }

        return isBetter;
    }

    if (m_HeaderIndexMap.find(headerhash) == m_HeaderIndexMap.end()) {
        weight = (uint16)header.GetChildBlockCount();

        T_HEADERINDEX headerindex;

        headerindex.id = hid;
        headerindex.prehash = header.GetPreHash();
        headerindex.headerhash = headerhash;
        headerindex.preheaderhash = preheaderhash;
        headerindex.ctime = header.GetCTime();
        headerindex.weight = weight;
        headerindex.total_weight = total + weight;
        headerindex.from_id = from_nodeid;

        //HCE: save to headerindex table
        ret = m_db->updateHeaderIndex(headerindex);
        if (ret != 0) {
            g_daily_logger->error("updateHeaderIndex failed!({}) hid: [{}]", ret, hid);
            g_console_logger->warn("updateHeaderIndex failed!({}) hid: [{}]", ret, hid);
        }

        m_HeaderIndexMap[headerhash] = std::move(headerindex);
    }

    //HC: 检查超块头是否可以加入本地最优链
    //HCE: Check whether the superblock can join the local optimal chain
    if (IsGensisBlock == true ||
        (!m_HeaderHashMap.empty() && uiMaxHeaderID == hid - 1 && m_HeaderHashMap[uiMaxHeaderID] == preheaderhash)) {

        m_HeaderHashMap[hid] = headerhash;
        m_db->updateHeaderHashInfo(hid, headerhash);
        m_localHeaderID.insert(hid);

        GenerateHIDSection(m_localHeaderID, m_localHeaderIDsection);
        uiMaxHeaderID = GetMaxHeaderID();

        /*char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);*/
        /*g_console_logger->info("IsBestHeader {} [{}]", hid, HeaderHash);*/

        Flag = true;

        return isBetter;
    }

    //HC: 加入备选链末尾
    //HCE: Add to the end of the alternative chain
    T_SHA256 endhash;
    bool finded = false;
    for (auto tr = m_BlocksHeaderHash.begin(); tr != m_BlocksHeaderHash.end(); tr++) {
        if ((*tr).empty())
            continue;

        auto end = (*tr).rbegin();
        if (*end == make_pair(hid - 1, preheaderhash)) {
            (*tr).push_back(make_pair(hid, headerhash));

            char HeaderHash[FILESIZEL] = { 0 };
            CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
            g_daily_logger->info("SaveHeaderIndex, push_back[{}, {}]", hid, HeaderHash);

            g_daily_logger->info("SaveHeaderIndex, 111 change m_HashChain");
            m_HashChain = tr;
            finded = true;
            break;
        }

        if (*end == make_pair(hid, headerhash)) {
            g_daily_logger->info("SaveHeaderIndex, 222 change m_HashChain");
            m_HashChain = tr;
            finded = true;
            break;
        }
    }

    if (!finded) {
        list<pair<uint64, T_SHA256>> listhash;
        listhash.emplace_back(make_pair(hid, headerhash));
        m_BlocksHeaderHash.push_back(std::move(listhash));
        g_daily_logger->info("SaveHeaderIndex, 333 change m_HashChain");
        m_HashChain = m_BlocksHeaderHash.end() - 1;
    }

    T_HEADERINDEX LBestHeaderIndex = m_HeaderIndexMap[m_HeaderHashMap[uiMaxHeaderID]];
    T_HEADERINDEX headerindex = m_HeaderIndexMap[(*m_HashChain).rbegin()->second];

    if (isBetterThanLocalChain(LBestHeaderIndex, headerindex)) {
        char NHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(NHeaderHash, headerindex.headerhash);
        g_daily_logger->info("isBetterThanLocalChain is true. id:[{}], total_weight:[{}], headerhash:[{}]",
            headerindex.id, headerindex.total_weight, NHeaderHash);

        char LHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(LHeaderHash, LBestHeaderIndex.headerhash);
        g_daily_logger->info("isBetterThanLocalChain is true. local id:[{}], local total_weight:[{}], local headerhash:[{}]",
            LBestHeaderIndex.id, LBestHeaderIndex.total_weight, LHeaderHash);

        isBetter = true;

        return isBetter;
    }

    Flag = true;

    return isBetter;
}

bool CHyperChainSpace::SwitchLocalBestChain()
{
    //bool found = false;
    //T_HEADERINDEX localheaderindex;

    uint64 begin_hid = 0;
    T_SHA256 begin_hash = T_SHA256(1);

    //HC: 前向依赖检查
    //HCE: Do a forward dependency check
    while (1) {
        begin_hid = (*m_HashChain).begin()->first;
        begin_hash = (*m_HashChain).begin()->second;

        if (m_HeaderHashMap.find(begin_hid - 1) == m_HeaderHashMap.end()) {
            g_daily_logger->error("SwitchLocalBestChain failed! Can't find hid: [{}] in m_HeaderHashMap", begin_hid - 1);
            g_console_logger->warn("SwitchLocalBestChain failed! Can't find hid : [{}] in m_HeaderHashMap", begin_hid - 1);
            return false;
        }

        if (m_HeaderIndexMap.find(begin_hash) == m_HeaderIndexMap.end()) {
            char HeaderHash[FILESIZEL] = { 0 };
            CCommonStruct::Hash256ToStr(HeaderHash, begin_hash);
            g_daily_logger->error("SwitchLocalBestChain failed! Can't find headerhash: [{}] in m_HeaderIndexMap", HeaderHash);
            g_console_logger->warn("SwitchLocalBestChain failed! Can't find headerhash: [{}] in m_HeaderIndexMap", HeaderHash);
            return false;
        }

        if (m_HeaderIndexMap[begin_hash].id != begin_hid) {
            g_daily_logger->error("SwitchLocalBestChain failed! hid: [{}], m_HashChain:[{}] not same", m_HeaderIndexMap[begin_hash].id, begin_hid);
            g_console_logger->warn("SwitchLocalBestChain failed! hid: [{}], m_HashChain:[{}] not same", m_HeaderIndexMap[begin_hash].id, begin_hid);
            return false;
        }

        T_SHA256 preheaderhash = m_HeaderIndexMap[begin_hash].preheaderhash;
        if (preheaderhash == m_HeaderHashMap[begin_hid - 1]) {
            //HC: 与最优链超块头Hash一致
            //HCE: Consistent with the optimal chain
            break;
        }

        (*m_HashChain).push_front(make_pair(begin_hid - 1, preheaderhash));
        g_daily_logger->info("SwitchLocalBestChain, hid: [{}], preheaderhash not same with m_HeaderHashMap", begin_hid - 1);
        g_console_logger->info("SwitchLocalBestChain, hid: [{}], preheaderhash not same with m_HeaderHashMap", begin_hid - 1);
    }

    //HC: 去重
    //HCE: Remove duplicate data
    for (auto itr = (*m_HashChain).begin(); itr != (*m_HashChain).end(); ) {
        if (m_HeaderHashMap.find(itr->first) == m_HeaderHashMap.end() ||
            m_HeaderHashMap[itr->first] != itr->second)
            break;

        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, itr->second);
        g_daily_logger->info("SwitchLocalBestChain, m_HashChain.erase: {}, [{}]", itr->first, HeaderHash);
        g_console_logger->info("SwitchLocalBestChain, m_HashChain.erase: {}, [{}]", itr->first, HeaderHash);
        (*m_HashChain).erase(itr++);
    }

    if ((*m_HashChain).empty())
        return false;

    uint64 hid = (*m_HashChain).begin()->first;

    //HCE: Notify consensus layer to switch.
    T_HYPERBLOCK hblk;
    if (CHyperchainDB::getHyperBlock(hblk, hid - 1)) {
        publishNewHyperBlock(hid - 2, hblk, true, true);
    }

    if (m_BlockHashMap.rbegin() != m_BlockHashMap.rend() &&
        m_BlockHashMap.rbegin()->first >= hid/*m_db->isBlockExistedOnBestChain(hid)*/) {
        //HC: 本地有需要进行数据回滚的超块
        //HCE: Rollback the hyperblock data
        DBmgr::Transaction t = m_db->beginTran();
        m_db->rollbackHyperblockAndLocalblock(hid);
        m_db->rollbackHashInfo(hid);
        t.set_trans_succ();

        g_daily_logger->info("rollbackHyperBlockCache, starting hid:{}", hid);

        for (uint64 currblockid = hid; currblockid <= uiMaxHeaderID; currblockid++) {
            m_localHID.erase(currblockid);

            //HCE: update m_BlockHashMap
            m_BlockHashMap.erase(currblockid);
        }

        GenerateHIDSection(m_localHID, m_localHIDsection);

        //HCE: update MaxBlockNum and previous hyper block
        uint64 nHyperId = GetLocalLatestHID();
        T_HYPERBLOCK hyperBlock;
        if (CHyperchainDB::getHyperBlock(hyperBlock, nHyperId)) {
            uiMaxBlockNum = nHyperId;
            m_LatestHyperBlock = std::move(hyperBlock);
            g_daily_logger->info("rollbackHyperBlockCache, uiMaxBlockNum:{}", hyperBlock.GetID());
        }

        //found = true;
    }

    //HCE: rollback headerhashinfo table
    m_db->rollbackHeaderHashInfo(hid);

    list<pair<uint64, T_SHA256>> listhash;
    for (auto ir = m_HeaderHashMap.find(hid); ir != m_HeaderHashMap.end();) {
        listhash.emplace_back(make_pair(ir->first, ir->second));

        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, ir->second);
        g_daily_logger->info("SwitchLocalBestChain, m_HeaderHashMap, delete hid:[{}], headerhash: [{}]", ir->first, HeaderHash);

        m_localHeaderID.erase(ir->first);
        m_HeaderHashMap.erase(ir++);
    }

    //HC: 将当前最优链数据保存到m_HeaderHashMap
    //HCE: Save the current optimal chain data to m_HeaderHashMap
    list<pair<uint64, T_SHA256>> blockexistlist;

    //DBmgr::Transaction t = m_db->beginTran();
    for (auto itr = (*m_HashChain).begin(); itr != (*m_HashChain).end(); itr++) {
        m_db->updateHeaderHashInfo(itr->first, itr->second);

        m_HeaderHashMap[itr->first] = itr->second;
        m_localHeaderID.insert(itr->first);


        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, itr->second);
        g_daily_logger->info("SwitchLocalBestChain, m_HeaderHashMap, insert hid:[{}], headerhash: [{}]", itr->first, HeaderHash);

        if (m_db->isBlockExistedbyHeaderHash(itr->first, itr->second)) {
            //HCE: Hyperblock data already exists
            blockexistlist.emplace_back(make_pair(itr->first, itr->second));
        }

        //HC: 暂时先不发送获取超块请求，以后调整实现方式
        //if (found) {
        //    //HC: 需要获取超块数据
        //    auto irt = m_HeaderIndexMap.find(*ir);
        //    if (irt != m_HeaderIndexMap.end()) {
        //        g_daily_logger->info("SwitchLocalBestChain, GetRemoteHyperBlockByPreHash, hid:{}", hid);
        //        GetRemoteHyperBlockByPreHash(hid, irt->second.prehash, irt->second.from_id, irt->second.headerhash);
        //    }
        //}
    }
    //t.set_trans_succ();

    GenerateHIDSection(m_localHeaderID, m_localHeaderIDsection);
    uiMaxHeaderID = GetMaxHeaderID();

    g_daily_logger->info("SwitchLocalBestChain, uiMaxHeaderID:{}", uiMaxHeaderID);

    g_daily_logger->info("SwitchLocalBestChain, clear m_HashChain");
    (*m_HashChain).clear();

    //HC: 从备选链中删除最优链数据，将m_HeaderHashMap中的旧链数据保存到备选链
    //HCE: Remove the optimal chain data from the alternative chain,
    //HCE: Save the old chain data from the m_HeaderHashMap to the alternate chain
    m_BlocksHeaderHash.erase(m_HashChain);
    m_BlocksHeaderHash.push_back(listhash);
    g_daily_logger->info("SwitchLocalBestChain, change m_HashChain");
    m_HashChain = m_BlocksHeaderHash.end() - 1;

    //HC: 写入已存在的超块数据
    //HCE: Save existing superblock data
    if (!blockexistlist.empty()) {
        for (auto tt = blockexistlist.begin(); tt != blockexistlist.end(); tt++) {
            T_HYPERBLOCK hyperblock;
            if (CHyperchainDB::getHyperBlockbyHeaderHash(hyperblock, tt->first, tt->second)) {
                updateHyperBlockCache(hyperblock);
            }
        }
    }

    return true;
}

void CHyperChainSpace::PutHyperBlockHeader(vector<T_HYPERBLOCKHEADER>& hyperblockheaders, string from_nodeid, bool& isSingle)
{
    if (hyperblockheaders.empty())
        return;

    int ret = 0;
    uint64 hid = 0;
    T_SHA256 headerhash;
    map<pair<uint64, T_SHA256>, T_HYPERBLOCKHEADER> nonheaderMap;
    map<pair<uint64, T_SHA256>, T_HYPERBLOCKHEADER> headerMap;

    //using seconds = std::chrono::duration<double, ratio<1>>;
    //seconds timespan;

    bool OnBestChainFlag = true;

    for (auto& hyperblockheader : hyperblockheaders) {
        hid = hyperblockheader.GetID();
        if (hid == UINT64_MAX) {
            g_daily_logger->error("PutHyperBlockHeaderVector failed! Incorrect data");
            g_console_logger->warn("PutHyperBlockHeaderVector failed! Incorrect data");
            return;
        }

        headerhash = hyperblockheader.calculateHeaderHashSelf();

        T_SHA256 blockheaderhash;
        if (OnBestChainFlag && GetHyperBlockHeaderHash(hid, blockheaderhash) && headerhash == blockheaderhash) {
            //HC: 已经在最优链上
            //HCE: Already on the optimal chain
            continue;
        }

        if (OnBestChainFlag)
            OnBestChainFlag = false;

        if (!m_chainheaderhashSet.count(make_pair(hid, headerhash))) {
            nonheaderMap[make_pair(hid, headerhash)] = hyperblockheader;
        }

        headerMap[make_pair(hid, headerhash)] = hyperblockheader;
    }

    if (headerMap.empty()) {
        //HCE: no data to process
        g_daily_logger->debug("PutHyperBlockHeaderVector, no header to process!");
        g_console_logger->debug("PutHyperBlockHeaderVector, no header to process!");
        return;
    }

    if (!nonheaderMap.empty()) {
        //system_clock::time_point time1 = system_clock::now();

        DBmgr::Transaction t = m_db->beginTran();
        for (auto it = nonheaderMap.begin(); it != nonheaderMap.end(); it++) {
            //HCE: save to header table
            ret = m_db->updateHeaderInfo(it->first.first, it->first.second, it->second);
            if (ret != 0) {
                g_daily_logger->error("PutHyperBlockHeaderVector, updateHeaderInfo failed! hid: [{}]", it->first.first);
                g_console_logger->warn("PutHyperBlockHeaderVector, updateHeaderInfo failed! hid: [{}]", it->first.first);
                return;
            }

            m_chainheaderhashSet.insert(make_pair(it->first.first, it->first.second));
        }
        t.set_trans_succ();

        //system_clock::time_point time2 = system_clock::now();
        //timespan = std::chrono::duration_cast<seconds>(time2 - time1);
        //g_basic_logger->info("updateHeaderInfo() spend [{}] second", timespan.count());
    }

    bool isBetter;
    bool CheckFlag = false;
    //HCE: save header list index
RETRY:
    //system_clock::time_point time3 = system_clock::now();
    isBetter = SaveHeaderListIndex(headerMap, from_nodeid, CheckFlag);
    //system_clock::time_point time4 = system_clock::now();
    //timespan = std::chrono::duration_cast<seconds>(time4 - time3);
    //g_basic_logger->info("SaveHeaderListIndex() spend [{}] second", timespan.count());

    if (!isBetter && !CheckFlag) {
        //HCE: single headers
        isSingle = true;
    }

    if (isBetter) {
        //HCE: better than local chain, need switch
        m_LatestBlockReady = false;
        SwitchLocalBestChain();
    }

    if (CheckFlag) {
        hid = headerMap.rbegin()->first.first;

        //HCE: check m_SingleHeaderMap
        if (m_SingleHeaderMap.empty() || m_SingleHeaderMap.count(hid + 1) == 0)
            return;

        string from_id;
        map<pair<uint64, T_SHA256>, T_HYPERBLOCKHEADER> headers;
        std::set<pair<T_SHA256, string>> headerhashSet;
        int nums = 0;

        while (m_SingleHeaderMap.count(hid + 1) > 0) {
            nums = 0;
            headerhashSet.clear();

            for (multimap<uint64, T_SINGLEHEADER>::iterator mi = m_SingleHeaderMap.lower_bound(hid + 1);
                mi != m_SingleHeaderMap.upper_bound(hid + 1); ++mi) {
                if (mi->second.preheaderhash == headerhash) {
                    headerhashSet.insert(make_pair(mi->second.headerhash, mi->second.from_id));
                    nums++;
                }
            }

            if (nums == 0) {
                //HCE: not found
                break;
            }

            if (nums == 1) {
                //HCE: get header
                T_HYPERBLOCKHEADER header;
                ret = GetHeaderByHash(header, hid + 1, headerhashSet.begin()->first);
                if (ret != 0) {
                    break;
                }

                hid = hid + 1;
                headerhash = headerhashSet.begin()->first;
                from_id = headerhashSet.begin()->second;

                headers[make_pair(hid, headerhash)] = std::move(header);

                continue;
            }

            if (!headers.empty()) {
                //HC: 先处理未分叉数据
                //HCE: Process unforked data first
                break;
            }

            //HC: 处理分叉数据
            //HCE: Process forked data first
            for (auto ir = headerhashSet.begin(); ir != headerhashSet.end(); ir++) {
                //HCE: get header
                T_HYPERBLOCKHEADER header;
                ret = GetHeaderByHash(header, hid + 1, ir->first);
                if (ret != 0) {
                    continue;
                }

                //HCE: delete from singleheader table
                DeleteSingleHeader(hid + 1, ir->first);

                //HCE: clear m_SingleHeaderMap
                removeFromSingleHeaderMap(hid + 1, ir->first);

                PutHyperBlockHeader(header, ir->second);
            }

            break;
        }

        if (headers.empty())
            return;

        for (auto ir = headers.begin(); ir != headers.end(); ir++) {
            //HCE: delete from singleheader table
            DeleteSingleHeader(ir->first.first, ir->first.second);

            //HCE: clear m_SingleHeaderMap
            removeFromSingleHeaderMap(ir->first.first, ir->first.second);
        }

        headerMap.clear();
        headerMap = std::move(headers);
        from_nodeid = from_id;
        CheckFlag = false;
        goto RETRY;
    }
}

void CHyperChainSpace::PutHyperBlockHeaderList(vector<T_HYPERBLOCKHEADER>& hyperblockheaders, string from_nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (hyperblockheaders.empty())
            return;

        g_daily_logger->info("PutHyperBlockHeaderList() starthid: [{}], hyperblockheaders.size: [{}], from_nodeid: [{}]",
            hyperblockheaders.begin()->GetID(), hyperblockheaders.size(), from_nodeid);
        g_console_logger->info("PutHyperBlockHeaderList() starthid: [{}], hyperblockheaders.size: [{}], from_nodeid: [{}]",
            hyperblockheaders.begin()->GetID(), hyperblockheaders.size(), from_nodeid);

        uint8 chainNum = 0;
        bool found = false;

        if (!m_chainInfoMap.empty()) {
            for (auto it = m_chainInfoMap.begin(); !found && it != m_chainInfoMap.end(); it++) {
                if (find(it->second.nodelist.begin(), it->second.nodelist.end(), from_nodeid) != it->second.nodelist.end()) {
                    chainNum = it->first;
                    found = true;
                    break;
                }
            }

            if (!found) {
                //HC: m_chainInfoMap里没有与from_nodeid一致的数据
                //HCE: There are no consistent data in the m_chainInfoMap with from_nodeid
                g_daily_logger->error("PutHyperBlockHeaderList failed! Can't find from_nodeid [{}] in m_chainInfoMap!", from_nodeid);
                g_console_logger->warn("PutHyperBlockHeaderList failed! Can't find from_nodeid [{}] in m_chainInfoMap!", from_nodeid);
                return;
            }

            if (!m_chainInfoMap[chainNum].checked) {
                //HC: 该链的HeaderHash没有完成MTRoot校验
                //HCE: The chain's HeaderHash did not complete the MTRoot checksum
                g_daily_logger->error("PutHyperBlockHeaderList failed! This chainInfo [{}] not checked!", chainNum);
                g_console_logger->warn("PutHyperBlockHeaderList failed! This chainInfo [{}] not checked!", chainNum);
                return;
            }
        }

        //using seconds = std::chrono::duration<double, ratio<1>>;
        //seconds timespan;
        //system_clock::time_point time1 = system_clock::now();

        uint64 gensisHID = 0;
        bool IsGensisBlock = false;

        auto iter = hyperblockheaders.begin();
        uint64 hid = iter->GetID();
        T_SHA256 hhash = iter->calculateHeaderHashSelf();

        if (pro_ver == ProtocolVer::NET::SAND_BOX && hid == m_gensisblockID + 1) {
            if (iter->GetPreHeaderHash() != m_gensisblockHeaderhash) {
                g_daily_logger->error("PutHyperBlockHeaderList failed! (NET::SAND_BOX) hid: [{}] PreHeaderhash not same!", hid);
                g_console_logger->error("PutHyperBlockHeaderList failed! (NET::SAND_BOX) hid: [{}] PreHeaderhash not same!", hid);
                return;
            }

            IsGensisBlock = true;
            gensisHID = hid;
        }

        if (pro_ver == ProtocolVer::NET::INFORMAL_NET && hid == m_gensisblockID) {
            if (hhash != m_gensisblockHeaderhash) {
                g_daily_logger->error("PutHyperBlockHeaderList failed! (NET::INFORMAL_NET) GensisBlock: [{}] Headerhash not same!", hid);
                g_console_logger->error("PutHyperBlockHeaderList failed! (NET::INFORMAL_NET) GensisBlock: [{}] Headerhash not same!", hid);
                return;
            }

            IsGensisBlock = true;
            gensisHID = hid;
        }

        if (m_chainInfoMap.empty() || hid > m_chainInfoMap[chainNum].sync_hash_hid) {
            //HCE: Process hot data
            if (!IsGensisBlock && !m_chainheaderhashSet.count(make_pair(hid - 1, iter->GetPreHeaderHash()))) {
                //HC: 收到的超块头PreHeaderHash与前一个超块头HeaderHash数据不一致
                //HCE: The received Hyperheader's PreHeaderHash is inconsistent with the previous Hyperheader HeaderHash data
                g_daily_logger->error("PutHyperBlockHeaderList 111 failed! hid [{}] PreHeaderhash not same!", hid - 1);
                g_console_logger->warn("PutHyperBlockHeaderList 111 failed! hid [{}] PreHeaderhash not same!", hid - 1);

                //HC: 前一个块头不存在，可能出现链切换情况，向来源节点要前MATURITY_SIZE个块头
                //HCE: The previous block header does not exist, and there may be a chain switch,
                //HCE: and the first MATURITY_SIZE block header is asked from the source node
                uint64 blockid = hid > MATURITY_SIZE ? hid - MATURITY_SIZE : m_gensisblockID;
                m_chainspacesyncheaderID[from_nodeid] = blockid;
                return;
            }

            map<uint64, T_SHA256> headerhash;

            if (!IsGensisBlock)
                headerhash[hid - 1] = iter->GetPreHeaderHash();

            for (; iter != hyperblockheaders.end(); iter++) {
                hid = iter->GetID();
                hhash = iter->calculateHeaderHashSelf();
                if (!IsGensisBlock && iter->GetPreHeaderHash() != headerhash[hid - 1]) {
                    //HC: 收到的超块头PreHeaderHash与前一个超块头HeaderHash数据不一致
                    //HCE: The received Hyperheader's PreHeaderHash is inconsistent with the previous Hyperheader HeaderHash data
                    g_daily_logger->error("PutHyperBlockHeaderList 222 failed! hid: [{}] PreHeaderhash not same!", hid);
                    g_console_logger->warn("PutHyperBlockHeaderList 222 failed! hid: [{}] PreHeaderhash not same!", hid);
                    return;
                }

                if (IsGensisBlock && hid == gensisHID) {
                    IsGensisBlock = false;
                }

                headerhash[hid] = hhash;
            }

            goto SAVEDATA;
        }

        {
            //HCE: Process cold data
            auto itr = m_chainInfoMap[chainNum].headerhash.find(hid);
            if (itr == m_chainInfoMap[chainNum].headerhash.end()) {
                //HC: hashmap里没有与hid一致的数据
                //HCE: There is no data in the hashmap that is consistent with HID
                g_daily_logger->error("PutHyperBlockHeaderList failed! Can't find hid [{}] in headerhashMap!", hid);
                g_console_logger->warn("PutHyperBlockHeaderList failed! Can't find hid [{}] in headerhashMap!", hid);
                return;
            }

            for (; iter != hyperblockheaders.end() && itr != m_chainInfoMap[chainNum].headerhash.end(); iter++, itr++) {
                hid = iter->GetID();
                if (hid == itr->first && iter->calculateHeaderHashSelf() != itr->second) {
                    //HC: 收到的超块头HeaderHash与Hash列表里的数据不一致
                    //HCE: The received hyperheader's HeaderHash does not match the data in the Hash list
                    g_daily_logger->error("PutHyperBlockHeaderList failed! hid: [{}] Headerhash not same!", hid);
                    g_console_logger->warn("PutHyperBlockHeaderList failed! hid: [{}] Headerhash not same!", hid);
                    return;
                }

                if (!IsGensisBlock && iter->GetPreHeaderHash() != m_chainInfoMap[chainNum].headerhash[hid - 1]) {
                    //HC: 收到的超块头PreHeaderHash与Hash列表里的数据不一致
                    //HCE: The received hyperheader's PreHeaderHash does not match the data in the Hash list
                    g_daily_logger->error("PutHyperBlockHeaderList failed! hid: [{}] PreHeaderhash not same!", hid);
                    g_console_logger->warn("PutHyperBlockHeaderList failed! hid: [{}] PreHeaderhash not same!", hid);
                    return;
                }

                if (IsGensisBlock && hid == gensisHID) {
                    IsGensisBlock = false;
                }
            }
        }

    SAVEDATA:
        bool isSingleHeader = false;
        //system_clock::time_point time3 = system_clock::now();
        PutHyperBlockHeader(hyperblockheaders, from_nodeid, isSingleHeader);
        //system_clock::time_point time4 = system_clock::now();
        //timespan = std::chrono::duration_cast<seconds>(time4 - time3);
        //g_basic_logger->info("PutHyperBlockHeader() spend [{}] second", timespan.count());

        if (isSingleHeader) {
            g_daily_logger->info("PutHyperBlockHeaderList isSingleHeader=[{}]", isSingleHeader);
            g_console_logger->info("PutHyperBlockHeaderList isSingleHeader=[{}]", isSingleHeader);

            if (m_chainInfoMap.empty() || hid > m_chainInfoMap[chainNum].sync_hash_hid) {
                //HC: 热数据，可能出现链切换情况，向来源节点要前MATURITY_SIZE个块头
                //HCE: Hot data, there may be chain switching, to the source node to ask for the first MATURITY_SIZE blocks
                uint64 blockid = hid > MATURITY_SIZE ? hid - MATURITY_SIZE : m_gensisblockID;
                m_chainspacesyncheaderID[from_nodeid] = blockid;
            }
            return;
        }

        CheckLocalHeaderReady();

        //system_clock::time_point time2 = system_clock::now();
        //timespan = std::chrono::duration_cast<seconds>(time2 - time1);
        //g_basic_logger->info("PutHyperBlockHeaderList() spend [{}] second", timespan.count());

        if (m_chainInfoMap.empty() || hid > m_chainInfoMap[chainNum].sync_hash_hid) {
            m_chainspacesyncheaderID[from_nodeid] = hid;
        }

        if (!m_chainInfoMap.empty() && m_chainInfoMap[chainNum].sync_header_hid < m_chainInfoMap[chainNum].sync_hash_hid) {
            //HCE: Update sync_header_hid
            m_chainInfoMap[chainNum].sync_header_hid = hid;

            _msghandler.registerTimer(2 * 1000, std::bind(&CHyperChainSpace::PullBlockHeader, this), true);
        }
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlockHeaderList, &hyperblockheaders, from_nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::PutHyperBlockHeader(T_HYPERBLOCKHEADER& hyperblockheader, string from_nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        int ret;
        uint64 hid = hyperblockheader.GetID();
        if (hid == UINT64_MAX)
            return;

        T_SHA256 headerhash = hyperblockheader.calculateHeaderHashSelf();
        T_SHA256 preheaderhash = hyperblockheader.GetPreHeaderHash();

        /*char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        char preHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(preHeaderHash, preheaderhash);
        g_console_logger->info("PutHyperBlockHeader(), hyper block: [{}] headerhash: [{}] preheaderhash: [{}] nodeid: [{}]",
            hid, HeaderHash, preHeaderHash, from_nodeid);*/

        T_SHA256 blockheaderhash;
        if (GetHyperBlockHeaderHash(hid, blockheaderhash) && headerhash == blockheaderhash) {
            //HC: 已经在最优链上
            //HCE: Already on the optimal chain
            return;
        }

        if (!m_chainheaderhashSet.count(make_pair(hid, headerhash))) {
            //HCE: save to header table
            ret = m_db->updateHeaderInfo(hid, headerhash, hyperblockheader);
            if (ret != 0) {
                g_daily_logger->error("PutHyperBlockHeader, updateHeaderInfo failed! hid: [{}]", hid);
                g_console_logger->warn("PutHyperBlockHeader, updateHeaderInfo failed! hid: [{}]", hid);
                return;
            }

            m_chainheaderhashSet.insert(make_pair(hid, headerhash));
        }

        bool isBetter;
        bool CheckFlag = false;
        //HCE: save header index
    RETRY:
        isBetter = SaveHeaderIndex(headerhash, preheaderhash, hyperblockheader, from_nodeid, CheckFlag);
        if (isBetter) {
            //HCE: better than local chain, need switch
            m_LatestBlockReady = false;
            SwitchLocalBestChain();
        }

        if (CheckFlag) {
            hid = hyperblockheader.GetID();

            //HCE: check m_SingleHeaderMap
            if (m_SingleHeaderMap.empty() || m_SingleHeaderMap.count(hid + 1) == 0)
                return;

            std::set<pair<T_SHA256, string>> headerhashSet;
            int nums = 0;

            for (multimap<uint64, T_SINGLEHEADER>::iterator mi = m_SingleHeaderMap.lower_bound(hid + 1);
                mi != m_SingleHeaderMap.upper_bound(hid + 1); ++mi) {
                if (mi->second.preheaderhash == headerhash) {
                    headerhashSet.insert(make_pair(mi->second.headerhash, mi->second.from_id));
                    nums++;
                }
            }

            if (nums == 0) {
                //HCE: not found
                return;
            }

            if (nums > 1) {
                //HC: 处理分叉数据
                //HCE: Handle forked data
                for (auto ir = headerhashSet.begin(); ir != headerhashSet.end(); ir++) {
                    //HCE: get header
                    T_HYPERBLOCKHEADER header;
                    ret = GetHeaderByHash(header, hid + 1, ir->first);
                    if (ret != 0) {
                        continue;
                    }

                    //HCE: delete from singleheader table
                    DeleteSingleHeader(hid + 1, ir->first);

                    //HCE: clear m_SingleHeaderMap
                    removeFromSingleHeaderMap(hid + 1, ir->first);

                    PutHyperBlockHeader(header, ir->second);
                }
                return;
            }

            //HCE: get header
            T_HYPERBLOCKHEADER header;
            ret = GetHeaderByHash(header, hid + 1, headerhashSet.begin()->first);
            if (ret != 0) {
                return;
            }

            //HCE: delete from singleheader table
            DeleteSingleHeader(hid + 1, headerhashSet.begin()->first);

            //HCE: clear m_SingleHeaderMap
            removeFromSingleHeaderMap(hid + 1, headerhashSet.begin()->first);

            headerhash = header.calculateHeaderHashSelf();
            preheaderhash = header.GetPreHeaderHash();
            hyperblockheader = std::move(header);
            from_nodeid = headerhashSet.begin()->second;
            CheckFlag = false;
            goto RETRY;
        }
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlockHeader, &hyperblockheader, from_nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::getHyperBlock(uint64 hid, T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_localHID.empty() || !m_localHID.count(hid))
            return false;

        if (m_LatestHyperBlock.GetID() == hid) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        //HCE: take it from db
        return CHyperchainDB::getHyperBlock(hyperblock, hid);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByID, hid, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

bool CHyperChainSpace::getHyperBlock(const T_SHA256& hhash, T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_LatestHyperBlock.GetHashSelf() == hhash) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        //HCE: take it from db
        return CHyperchainDB::getHyperBlock(hyperblock, hhash);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByHash, &hhash, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

bool CHyperChainSpace::getHyperBlockByPreHash(uint64 hid, T_SHA256& prehash, T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_BlockHashMap.find(hid) == m_BlockHashMap.end()) {
            g_daily_logger->error("getHyperBlockByPreHash failed! Can't find block [{}] in m_BlockHashMap", hid);
            g_console_logger->warn("getHyperBlockByPreHash failed! Can't find block [{}] in m_BlockHashMap", hid);
            return false;
        }

        if (m_BlockHashMap.find(hid - 1) != m_BlockHashMap.end() && m_BlockHashMap[hid - 1] != prehash) {
            g_daily_logger->error("getHyperBlockByPreHash failed! Prehash not same");
            g_console_logger->warn("getHyperBlockByPreHash failed! Prehash not same");
            return false;
        }

        if (m_LatestHyperBlock.GetPreHash() == prehash) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        //HCE: take it from db
        return CHyperchainDB::getHyperBlock(hyperblock, prehash);
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByPreHash, hid, &prehash, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

bool CHyperChainSpace::CheckHyperBlockHash(uint64 hid, const T_SHA256& hash, bool needdownload)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (hid > uiMaxHeaderID)
            return false;

        if (needdownload) {
            GetRemoteHyperBlockByID_UntilSuccess(hid, hid + 1, "");
        }

        if (m_BlockHashMap.find(hid) != m_BlockHashMap.end() && hash == m_BlockHashMap[hid])
            return true;

        if (m_HeaderHashMap.find(hid + 1) == m_HeaderHashMap.end())
            return false;

        T_SHA256& headerhash = m_HeaderHashMap[hid + 1];

        if (m_HeaderIndexMap.find(headerhash) == m_HeaderIndexMap.end())
            return false;

        if (hash == m_HeaderIndexMap[headerhash].prehash)
            return true;

        return false;
    }
    else {

        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::CheckHyperBlockHash, hid, &hash, needdownload);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

//HCE: Get Hyperblock hash in main chain
bool CHyperChainSpace::GetHyperBlockHash(uint64 hid, T_SHA256& hash)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (hid > uiMaxHeaderID)
            return false;

        if (m_BlockHashMap.find(hid) != m_BlockHashMap.end()) {
            hash = m_BlockHashMap[hid];
            return true;
        }

        if (m_HeaderHashMap.find(hid + 1) == m_HeaderHashMap.end())
            return false;

        T_SHA256& headerhash = m_HeaderHashMap[hid + 1];
        if (m_HeaderIndexMap.find(headerhash) == m_HeaderIndexMap.end())
            return false;

        hash = m_HeaderIndexMap[headerhash].prehash;
        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHash, hid, &hash);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

//HCE: Get a batch hash of Hyperblocks in main chain
bool CHyperChainSpace::GetHyperBlocksHashs(uint64 hid, uint32 num, vector<T_SHA256>& vechash, bool needdownload)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        for (uint64 i = hid; i < hid + num && i < uiMaxHeaderID; i++) {
            if (m_BlockHashMap.find(i) != m_BlockHashMap.end()) {
                vechash.push_back(m_BlockHashMap[i]);
                continue;
            }

            if (needdownload) {
                GetRemoteHyperBlockByID_UntilSuccess(i, i + 1, "");
            }

            if (m_HeaderHashMap.find(i + 1) == m_HeaderHashMap.end())
                break;

            T_SHA256& headerhash = m_HeaderHashMap[i + 1];
            if (m_HeaderIndexMap.find(headerhash) == m_HeaderIndexMap.end())
                break;
            vechash.push_back(m_HeaderIndexMap[headerhash].prehash);
        }
        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlocksHashs, hid, num, &vechash, needdownload);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

void CHyperChainSpace::SaveToLocalStorage(const T_HYPERBLOCK& tHyperBlock)
{
    DBmgr::Transaction t = m_db->beginTran();

    //HCE: If DB has already store this hyperblock , we should delete it at first
    if (m_db->isBlockExisted(tHyperBlock.GetID())) {
        m_db->deleteHyperblockAndLocalblock(tHyperBlock.GetID());
    }

    auto subItr = tHyperBlock.GetChildChains().begin();
    uint16 chainnum = 0;
    for (; subItr != tHyperBlock.GetChildChains().end(); subItr++) {
        chainnum++;
        auto ssubItr = (*subItr).begin();
        for (; ssubItr != (*subItr).end(); ssubItr++) {
            m_db->insertLocalblock(*ssubItr, tHyperBlock.GetID(), chainnum);
        }
    }
    m_db->insertHyperblock(tHyperBlock);
    t.set_trans_succ();
}

//HCE: return true mean hyper block is accepted and put into cache.
bool CHyperChainSpace::updateHyperBlockCache(T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        g_daily_logger->info("updateHyperBlockCache: {}", hyperblock.GetID());
        uint64_t currblockid = hyperblock.GetID();
        uint64_t blockcount = hyperblock.GetChildBlockCount();

        //HCE: Notice To Do:
        //HCE: Even if select another branch, we do nothing for my local blocks they are already in old chain.

        char HyperblockHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HyperblockHash, hyperblock.GetHashSelf());

        //HCE: if I have the hyper block and local is more well, refuse it.
        bool isBlockAlreadyExisted = false;
        if (!isAcceptHyperBlock(currblockid, hyperblock, isBlockAlreadyExisted)) {
            g_daily_logger->info("I have the hyper block or local is more well, refuse it: {} {} {}",
                currblockid, blockcount, HyperblockHash);
            return false;
        }

        //HCE: if not unlock, application layer maybe occur dead lock with hyper chain layer.
        //HCE: Application layer call RPC, this action hold lock CRITICAL_BLOCK(cs_main) and m_MuxHchainBlockList
        //HCE: Here calling ApplicationCheck will hold lock m_MuxHchainBlockList and cs_main, so deadlock occur.

        g_daily_logger->info("I accept the hyper block: {} {} {}",
            currblockid, blockcount, HyperblockHash);

        //g_tP2pManagerStatus->ApplicationAccept(currblockid - 1, hyperblock, uiMaxBlockNum <= currblockid);
        SaveToLocalStorage(hyperblock);

        //HCE: save HeaderHash and BlockHash
        T_SHA256 headerhash = hyperblock.calculateHeaderHashSelf();
        m_db->updateHashInfo(currblockid, headerhash, hyperblock.GetHashSelf());

        //HCE: update m_BlockHashMap
        m_BlockHashMap[currblockid] = hyperblock.GetHashSelf();

        if (!isBlockAlreadyExisted) {
            //HCE: update m_localHID and m_localHIDsection
            m_localHID.insert(currblockid);
            GenerateHIDSection(m_localHID, m_localHIDsection);
        }

        if (uiMaxBlockNum <= currblockid) {
            //HCE: update MaxBlockNum and previous hyper block
            uiMaxBlockNum = currblockid;
            m_LatestHyperBlock = std::move(hyperblock);

            //HCE: Notify subscribing module including consensus engine
            publishNewHyperBlock(currblockid - 1, m_LatestHyperBlock, true, false);

            if (m_localHeaderReady && currblockid >= uiMaxHeaderID) {
                m_LatestBlockReady = true;

                if (currblockid != 0) {
                    //HCE: send latest hyper block to neighbors
                    BoardcastHyperBlockTask task;
                    task.exec();
                }
            }
        }
        else {
            publishNewHyperBlock(currblockid - 1, hyperblock, false, false);
        }

        return true;
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::UpdateHyperBlockCache, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::publishNewHyperBlock(uint32_t hidFork, const T_HYPERBLOCK& hyperblock, bool isLatest, bool needSwitch)
{
    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    try {
        putStream(oa, hyperblock);
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }


    zmsg msg;
    MQMsgPush(&msg, hidFork, ssBuf.str(), isLatest, needSwitch);
    msg.send(*_hyperblock_pub);
}

//HCE: When block id is same, we choose the hyper block whose local blocks counts is more.
//HCE: When block id and local block counts both are same, we choose the hyper block whose hash is more less.
bool CHyperChainSpace::isMoreWellThanLocal(const T_HYPERBLOCK& localHyperBlock,
    uint64 blockid, uint64 blockcount, const T_SHA256& hhashself)
{
    assert(blockid == localHyperBlock.GetID());

    uint64 currentchildcount = localHyperBlock.GetChildBlockCount();
    if (blockcount > currentchildcount) {
        return true;
    }
    if (blockcount == currentchildcount) {
        T_SHA256 h = localHyperBlock.GetHashSelf();
        if (hhashself < h) {
            return true;
        }
    }
    return false;
}

bool CHyperChainSpace::isAcceptHyperBlock(uint64 blockid, const T_HYPERBLOCK& remoteHyperBlock, bool isAlreadyExisted)
{
    T_HYPERBLOCK localHyperBlock;

    bool Existed = getHyperBlock(blockid, localHyperBlock);
    if (!Existed) {
        isAlreadyExisted = false;
        return true;
    }

    isAlreadyExisted = true;

    T_SHA256 lblockhash = localHyperBlock.GetHashSelf();
    T_SHA256 rblockhash = remoteHyperBlock.GetHashSelf();
    if (lblockhash == rblockhash) {
        g_daily_logger->info("I have the hyper block: {}", blockid);
        return false;
    }

    g_daily_logger->info("hyper block {} has furcated, update local data", blockid);
    return true;
}

void getFromStream(boost::archive::binary_iarchive& ia, T_HYPERBLOCK& hyperblock, T_SHA256& hash)
{
    ia >> hash;
    ia >> hyperblock;
    uint32 count = hyperblock.GetChildChainsCount();
    for (uint32 i = 0; i < count; i++) {
        LIST_T_LOCALBLOCK childchain;
        uint32 blocknum;
        ia >> blocknum;
        for (uint32 j = 0; j < blocknum; j++) {
            T_LOCALBLOCK block;
            ia >> block;
            childchain.push_back(std::move(block));
        }
        hyperblock.AddChildChain(std::move(childchain));
    }
}


void putStream(boost::archive::binary_oarchive& oa, const T_HYPERBLOCK& hyperblock)
{
    oa << hyperblock.GetHashSelf();
    oa << hyperblock;

    const vector<LIST_T_LOCALBLOCK>& childchains = hyperblock.GetChildChains();

    assert(hyperblock.GetChildChainsCount() == childchains.size());
    size_t totalBlocks = 0;
    for (auto& cchain : childchains) {
        uint32 blocknum = cchain.size();
        oa << blocknum;
        for (auto iter = cchain.begin(); iter != cchain.end(); iter++) {
            oa << (*iter);
        }
        totalBlocks += blocknum;
    }
    assert(hyperblock.GetChildBlockCount() == totalBlocks);
}

void putStream(boost::archive::binary_oarchive& oa, const vector<T_HYPERBLOCKHEADER>& hyperblockheader)
{
    uint32 headernum = hyperblockheader.size();
    oa << headernum;
    for (auto iter = hyperblockheader.begin(); iter != hyperblockheader.end(); iter++) {
        oa << (*iter);
    }
}

void getFromStream(boost::archive::binary_iarchive& ia, uint64_t& hid, uint32& range, vector<T_SHA256>& headerhash)
{
    ia >> hid;
    ia >> range;

    uint32 hashnum = 0;
    ia >> hashnum;
    for (uint32 i = 0; i < hashnum; i++) {
        T_SHA256 hash;
        ia >> hash;
        headerhash.push_back(std::move(hash));
    }
}

void putStream(boost::archive::binary_oarchive& oa, uint64_t hid, uint32 range, const vector<T_SHA256>& headerhash)
{
    oa << hid;
    oa << range;

    uint32 hashnum = headerhash.size();
    oa << hashnum;
    for (auto iter = headerhash.begin(); iter != headerhash.end(); iter++) {
        oa << (*iter);
    }
}

void GetHeaderIDSection(uint64 headerHID, vector<uint16>& locationSection)
{
    uint64 startid = 0;

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        startid = INFORMALNET_GENESISBLOCKID - 1;
    }

    headerHID = headerHID - startid;

    if (!locationSection.empty()) {
        locationSection.clear();
    }

    for (uint16 i = 0; headerHID > 0; i++) {
        if (headerHID & 1)
            locationSection.insert(locationSection.begin(), i);

        headerHID = headerHID >> 1;
    }
}

void CHyperChainSpace::GenerateHeaderHashMTRootList(vector<uint16>& location, vector<T_SHA256>& hashMTRootlist, map<uint64, T_SHA256>& headerhashmap)
{
    T_SHA256 hash;
    uint64 startid = 0;
    uint64 endid = 0;

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET) {
        //HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
        startid = endid = m_gensisblockID - 1;
    }

    startid++;

    if (!hashMTRootlist.empty()) {
        hashMTRootlist.clear();
    }

    for (auto& i : location) {
        endid += (uint64)1 << i;

        hash = GenerateHeaderHashMTRoot(startid, endid, headerhashmap);
        hashMTRootlist.push_back(hash);

        startid = endid + 1;
    }
}

T_SHA256 CHyperChainSpace::GenerateHeaderHashMTRoot(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhashmap)
{
    vector<const T_SHA256*> v;
    for (auto it = headerhashmap.find(startid); it != headerhashmap.end(); it++) {
        if (it->first > endid)
            break;

        v.push_back(&(it->second));
    }

    return calculateMerkleTreeRoot(v);
}

uint64 BinarySearch(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhashmap1, map<uint64, T_SHA256>& headerhashmap2)
{
    if (startid == endid || endid == startid + 1)
        return startid;

    uint64 findid = (startid + endid) / 2;
    if (findid == startid || findid == endid)
        return findid;

    auto it1 = headerhashmap1.find(findid);
    auto it2 = headerhashmap2.find(findid);

    if (it1 == headerhashmap1.end() || it2 == headerhashmap2.end()) {
        return startid;
    }

    if (it1->second == it2->second) {
        startid = findid;
    }
    else {
        endid = findid;
    }

    return BinarySearch(startid, endid, headerhashmap1, headerhashmap2);
}

uint64 CHyperChainSpace::CheckDiffPos(uint64 startid, uint64 endid, map<uint64, T_SHA256>& headerhash, T_HEADERINFO& headerinfo)
{
    vector <uint16> hashMTRootSection;
    vector<T_SHA256> hashMTRootlist;
    vector<T_SHA256> localhashMTRootlist;

    uint64 headerid = endid < headerinfo.id ? endid : headerinfo.id;
    if (headerid == headerinfo.id) {
        hashMTRootSection = headerinfo.section;
        hashMTRootlist = headerinfo.hashMTRootList;
        GenerateHeaderHashMTRootList(hashMTRootSection, localhashMTRootlist, m_HeaderHashMap);
    }
    else {
        GetHeaderIDSection(headerid, hashMTRootSection);
        GenerateHeaderHashMTRootList(hashMTRootSection, hashMTRootlist, headerhash);
        GenerateHeaderHashMTRootList(hashMTRootSection, localhashMTRootlist, m_HeaderHashMap);
    }

    int i = 0;
    bool isSame = true;

    if (localhashMTRootlist.size() != hashMTRootlist.size()) {
        return startid;
    }

    for (; i < localhashMTRootlist.size(); i++) {
        if (localhashMTRootlist[i] != hashMTRootlist[i]) {
            isSame = false;
            break;
        }
    }

    if (isSame) {
        return headerid;
    }

    uint64 blockid = startid + 1;
    for (int j = 0; j < i; j++) {
        blockid += (uint64)1 << hashMTRootSection[j];
    }

    uint64 hid = blockid;
    for (; hid <= headerid; hid++) {
        if (m_HeaderHashMap.find(hid) != m_HeaderHashMap.end() &&
            headerhash.find(hid) != headerhash.end() &&
            m_HeaderHashMap[hid] != headerhash[hid]) {
            hid--;
            break;
        }
    }
    g_daily_logger->info("CheckDiffPos(), startid: [{}], endid: [{}], return hid: [{}]", blockid, headerid, hid);

    ////HC: 用二分法查找确定超块头Hash不一致的起始HID
    //uint64 hid = BinarySearch(blockid, headerid, m_HeaderHashMap, headerhash);
    //g_daily_logger->info("BinarySearch(), startid: [{}], endid: [{}], return hid: [{}]", blockid, headerid, hid);

    //while (m_HeaderHashMap.find(hid) != m_HeaderHashMap.end() &&
    //    headerhash.find(hid) != headerhash.end() &&
    //    m_HeaderHashMap[hid] != headerhash[hid]) {
    //    hid--;
    //}

    return hid;
}


std::string CHyperChainSpace::GetMQCostStatistics()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        //return m_chainactioncoststt.Statistics("HyperChainSpace MQ cost statistics: ");
        ostringstream oss;
        oss << m_chainactioncoststt.Statistics("HyperChainSpace MQ cost statistics: ");
        oss << endl;
        oss << _msghandler.getStatistics("HyperChainSpace Task cost statistics: ");
        return oss.str();
    }
    else {
        zmsg* rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::MQCostStatistics);

        string ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

