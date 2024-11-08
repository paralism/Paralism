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

#pragma once

#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "util/MutexObj.h"
#include "node/zmsg.h"
#include "node/mdp.h"
#include "p2pprotocol.h"
#include "node/ITask.hpp"


#include <thread>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
using namespace std;

class zmsg;
enum _enodestate
{
    IDLE = 0,
    LOCAL_BUDDY,
    GLOBAL_BUDDY
};

typedef struct _tBuddyInfo
{
    uint64 uiCurBuddyNo;
    uint16 usBlockNum;
    uint16 usChainNum;
    uint8 eBuddyState;

    uint64 GetCurBuddyNo()const;
    uint16 GetBlockNum()const;
    uint16 GetChainNum()const;
    uint8 GetBuddyState()const;

    void SetBlockNum(uint16 num);

}T_STRUCTBUDDYINFO, * T_PSTRUCTBUDDYINFO;

typedef struct _tOnChainHashInfo
{
    uint64 uiTime;
    string strHash;

    uint64 GetTime()const;
    string GetHash()const;

    void Set(uint64 t, string h);

}T_ONCHAINHASHINFO, * T_PONCHAINHASHINFO;

enum class CONSENSUS_PHASE :char {
    LOCALBUDDY_PHASE = 0,
    GLOBALBUDDY_PHASE,
    PERSISTENCE_CHAINDATA_PHASE,
    PREPARE_LOCALBUDDY_PHASE
};

class CycleQueue
{
public:
    CycleQueue()
    {
        head = queue.begin();
        tail = queue.begin();
    }

    bool push(TASKTYPE data)
    {
        *head = data;

        head++;

        if (head == queue.end())
        {
            head = queue.begin();
        }

        if (head == tail)
        {
            tail++;
            if (tail == queue.end())
                tail = queue.begin();
        }

        return true;
    }

    bool pop(TASKTYPE* data)
    {
        if (head == tail)
        {
            return false;
        }

        *data = *tail;

        tail++;
        if (tail == queue.end())
            tail = queue.begin();

        return true;
    }

private:
    array<TASKTYPE, 100> queue;
    array<TASKTYPE, 100>::iterator head;
    array<TASKTYPE, 100>::iterator tail;
};

typedef struct _tagCONSENSUSNOTIFYSTATE
{
    CONSENSUSNOTIFY notify_fns;
    bool unreging = false;           //whether application is unregistering

public:

    _tagCONSENSUSNOTIFYSTATE(const CONSENSUSNOTIFY& notify) : notify_fns(notify)
    { }

    _tagCONSENSUSNOTIFYSTATE(_tagCONSENSUSNOTIFYSTATE&& src) {
        notify_fns = src.notify_fns;
        unreging = src.unreging;
    }

} CONSENSUSNOTIFYSTATE;

using CONSENSUSNOTIFYSTATESP = std::shared_ptr<CONSENSUSNOTIFYSTATE>;

typedef struct _tp2pmanagerstatus
{
    std::thread::id threadid;
    bool bStartGlobalFlag;
    bool bGlobalChainChangeFlag;

    std::atomic<bool> bHaveOnChainReq;
    std::atomic<uint64> uiConsensusBlockNum;
    uint16 uiNodeState;
    T_LOCALBLOCK tPreLocalBlock;
    T_PEERADDRESS tLocalBuddyAddr;

    LIST_T_LOCALCONSENSUS listOnChainReq;

    LIST_T_LOCALCONSENSUS listLocalBuddyChainInfo;

    LIST_LIST_GLOBALBUDDYINFO listGlobalBuddyChainInfo;

    LIST_T_BUDDYINFO  listRecvLocalBuddyRsp;

    LIST_T_BUDDYINFOSTATE listCurBuddyRsp;

    LIST_T_BUDDYINFO  listRecvLocalBuddyReq;

    LIST_T_BUDDYINFOSTATE listCurBuddyReq;

    MAP_T_SEARCHONCHAIN mapSearchOnChain;

    T_STRUCTBUDDYINFO tBuddyInfo;

    T_SHA256 latestHyperBlockHash;
    uint64 latestHyperblockId = 0;
    uint64 latestHyperblockCTime = 0;

    bool bHyperBlockCreated;
    T_HYPERBLOCK tHyperBlock;

    map<CUInt128, T_BUDDYINFO> mapLocalBuddyInfo;           //HC: first:发送方nodeid, second:LOCAL阶段BLOCK数据不完整的buddy信息
                                                            //HCE: first: sent node id, second: buddy whose block data is uncomplete in local phase
    map<CUInt128, T_BUDDYINFO> mapGlobalBuddyInfo;          //HC: first:发送方nodeid, second:GLOBAL阶段BLOCK数据不完整的buddy信息
                                                            //HCE: first: sent node id, second: buddy whose block data is uncomplete in global phase
    map< T_SHA256, T_LOCALCONSENSUS > mapLocalConsensus;    //HC: first:子块hash, second:子块consensus
                                                            //HCE: first: block hash, second: block consensus

    //HCE: Clear all kinds of consensus status 
    //HCE: @returns void
    void ClearStatus();

    _tp2pmanagerstatus()
    {
        ClearStatus();
    }

    void SetConsensusTime(uint32 l, uint32 g, uint32 nxt)
    {
        _LOCALBUDDYTIME = l;
        _GLOBALBUDDYTIME = g;
        _NEXTBUDDYTIME = nxt;
    }

    void GetConsensusTime(uint32& l, uint32& g, uint32& nxt)
    {
        l = _LOCALBUDDYTIME;
        g = _GLOBALBUDDYTIME;
        nxt = _NEXTBUDDYTIME;
    }

    void SetGloblChainsChanged(bool changed) {
        bGlobalChainChangeFlag = changed;
    }

    bool GloblChainsChanged() {
        return bGlobalChainChangeFlag;
    }

    bool StartGlobalFlag()const;

    bool HaveOnChainReq()const;

    //HC: 返回当前共识子块头里存放的前一个超块Hash,这不完全等同于本节点最新超块的hash
    //HCE: Get pre hyper block hash in current consensus block which is not always equal to the latest pre hyper block hash of this node
    T_SHA256 GetConsensusPreHyperBlockHash()const;

    uint16 GetNodeState()const;

    uint64 GettTimeOfConsensus();

    //HCE: Get current consensus phase
    //HCE: @returns Current consensus phase
    CONSENSUS_PHASE GetCurrentConsensusPhase() const;

    T_PEERADDRESS GetLocalBuddyAddr()const;

    enum class SERVICE : short
    {
        GetListOnChainReqCount = 80,
        RequestOnChain,
        TrackLocalBlock,
    };

    //HCE: Reply message according to its service
    //HCE: @para t Service defined
    //HCE: @para msg Pointer to zmsg
    //HCE: @returns True if the message is processed.
    bool ReplyMsg(int t, zmsg* msg);

    //HCE: Get the size of listOnChainReq
    //HCE: @returns The size of listOnChainReq
    size_t GetListOnChainReqCount();

    //HCE: Push back a block to listOnChainReq(on chain request queue)
    //HCE: @para LocalConsensusInfo A local block
    //HCE: @returns void
    void RequestOnChain(const T_LOCALCONSENSUS& LocalConsensusInfo);

    void SetStartGlobalFlag(bool flag);

    void SetHaveOnChainReq(bool haveOnChainReq);

    void SetNodeState(uint16 state);

    T_STRUCTBUDDYINFO GetBuddyInfo()const;

    void SetBuddyInfo(T_STRUCTBUDDYINFO info);


    //HCE: Set lastest hyper block
    //HCE: @para hyperid The lastest hyper block ID
    //HCE: @para hhash Hash of the lastest hyper block
    //HCE: @para hyperctime Time of the lastest hyper block created
    //HCE: @returns void
    void SetLatestHyperBlock(uint64 hyperid, const T_SHA256& hhash, uint64 hyperctime);

    inline uint64 GetLatestHyperBlockId() const { return latestHyperblockId; };

    const T_SHA256& GetLatestHyperBlockHash() const { return latestHyperBlockHash; };

    //HCE: Get broadcast nodes
    //HCE: @para MulticastNodes the vector to store the broadcast nodes
    //HCE: @returns void
    void GetMulticastNodes(vector<CUInt128>& MulticastNodes);

    //HCE: Update on chain state of blocks in a hyper block
    //HCE: @para hyperblock Hyper block to update
    //HCE: @returns void
    void UpdateOnChainingState(const T_HYPERBLOCK& hyperblock);

    //HCE: let application layer check the payload data.
    //HCE: @para hyperblock Hyper block
    //HCE: @returns True if OK
    bool ApplicationCheck(T_HYPERBLOCK& hyperblock);

    //HCE: Let application layer handle their genesis block and accept block data.
    //HCE: @para hyperblock Hyper block
    //HCE: @para isLatest Bool value if it's latest
    //HCE: @returns True if OK
    bool ApplicationAccept(uint32_t hidFork, T_HYPERBLOCK& hyperblock, bool isLatest);

    //HCE: Update local block's hyper block info into the latest hyper block.
    //HCE: @para prehyperblockid Block's pre hyper block id 
    //HCE: @para preHyperBlockHash Block's pre hyper block hash
    //HCE: @returns void
    void UpdateLocalBuddyBlockToLatest(uint64 prehyperblockid, const T_SHA256& preHyperBlockHash);

    //HCE: init consensus environment
    //HCE: @returns void
    void CleanConsensusEnv();

    //HC:跟踪本地块上链状态
    //HCE: Trace the on chain state of local block 
    //HCE: @para localblock A local block
    //HCE: @returns void
    void TrackLocalBlock(const T_LOCALBLOCK& localblock);

    //HCE: Init on chain state of blocks in mapSearchOnChain whose hyperid = hid
    //HCE: @para hid Hid to init
    //HCE: @returns void
    void InitOnChainingState(uint64 hid);

    //HCE: Rehandle on chain state of blocks in mapSearchOnChain whose hyperid > hid
    //HCE: @para hid Hid to rehandle
    //HCE: @returns void
    void RehandleOnChainingState(uint64 hid);

    void SetAppCallback(const T_APPTYPE& app, const CONSENSUSNOTIFY& notify);

    //HCE: Remove call back App by App type
    //HCE: @para app App type 
    //HCE: @returns void
    void RemoveAppCallback(const T_APPTYPE& app);

    bool IsParaAppLoaded() {

        auto tmpmapcbfn = _mapcbfn;  //HC: reference count increase

        map<string, T_APPTYPE> mapApps;
        for (auto& appnoti : tmpmapcbfn) {
            if (appnoti.second->unreging) {
                continue;
            }
            if (appnoti.first.isParacoin()) {
                return true;
            }
        }
        return false;
    }

    bool IsAlethAppLoaded() {

        auto tmpmapcbfn = _mapcbfn;  //HC: reference count increase

        map<string, T_APPTYPE> mapApps;
        for (auto& appnoti : tmpmapcbfn) {
            if (appnoti.second->unreging) {
                continue;
            }
            if (appnoti.first.isEthereum()) {
                return true;
            }
        }
        return false;
    }


    map<string, T_APPTYPE> GetAppsInfo()
    {
        auto tmpmapcbfn = _mapcbfn;  //HC: reference count increase

        map<string, T_APPTYPE> mapApps;
        for (auto& appnoti : tmpmapcbfn) {
            if (appnoti.second->unreging) {
                continue;
            }
            mapApps[appnoti.first.appName()] = appnoti.first;
        }
        return mapApps;
    }


    template<cbindex I, typename... Args>
    bool AllAppCallback(Args&... args)
    {
        //HCE: copy _mapcbfn, avoid crash when exiting the program which will call RemoveAppCallback to unregister the application
        //HCE: RemoveAppCallback will erase the elements in _mapcbfn, so here traversing _mapcbfn maybe cause crash
        auto tmpmapcbfn = _mapcbfn;  //HC: reference count increase

        for (auto& appnoti : tmpmapcbfn) {
            if (appnoti.second->unreging) {
                continue;
            }
            auto fn = std::get<static_cast<size_t>(I)>(appnoti.second->notify_fns);
            if (fn) {
                fn(args...);
            }
        }
        return true;
    }

    template<cbindex I, typename... Args>
    CBRET AppCallback(const T_APPTYPE& app, Args&... args)
    {
        //HCE: If use lock, it will cause dead lock when calling RPC command addamounttoaddress
        //HCE: which hold mutex: cs_main then _muxmapcbfn
        if (_mapcbfn.count(app)) {

            if (_mapcbfn[app]->unreging) {
                return CBRET::UNREGISTERED;
            }

            auto spnotistate = _mapcbfn.at(app);
            auto fn = std::get<static_cast<size_t>(I)>(spnotistate->notify_fns);
            if (fn) {
                return fn(args...) ? (CBRET::REGISTERED_TRUE) : (CBRET::REGISTERED_FALSE);
            }
        }
        return CBRET::UNREGISTERED;
    }

private:

    //HCE: Insert block's address and payload in the hyper block to mapPayload
    //HCE: @para hyperblock Hyper block
    //HCE: @para mapPayload Map to store block's address and payload
    //HCE: @returns void
    void ToAppPayloads(const T_HYPERBLOCK& hyperblock, map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload);

private:

    unordered_map<T_APPTYPE, CONSENSUSNOTIFYSTATESP> _mapcbfn;
    uint32 _NEXTBUDDYTIME = NEXTBUDDYTIME;
    uint32 _LOCALBUDDYTIME = LOCALBUDDYTIME;
    uint32 _GLOBALBUDDYTIME = GLOBALBUDDYTIME;

}T_P2PMANAGERSTATUS, * T_PP2PMANAGERSTATUS;


//////////////////////////////////////////////////////////////////////////
