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
#include "utility/MutexObj.h"
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
    map<CUInt128, T_BUDDYINFO> mapGlobalBuddyInfo;          //HC: first:发送方nodeid, second:GLOBAL阶段BLOCK数据不完整的buddy信息
    map< T_SHA256, T_LOCALCONSENSUS > mapLocalConsensus;    //HC: first:子块hash, second:子块consensus

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
    T_SHA256 GetConsensusPreHyperBlockHash()const;

    uint16 GetNodeState()const;

    uint64 GettTimeOfConsensus();
    CONSENSUS_PHASE GetCurrentConsensusPhase() const;

    T_PEERADDRESS GetLocalBuddyAddr()const;

    enum class SERVICE : short
    {
        GetListOnChainReqCount = 80,
        RequestOnChain,
        TrackLocalBlock,
    };

    bool ReplyMsg(int t, zmsg* msg);


    size_t GetListOnChainReqCount();
    void RequestOnChain(const T_LOCALCONSENSUS& LocalConsensusInfo);

    void SetStartGlobalFlag(bool flag);

    void SetHaveOnChainReq(bool haveOnChainReq);

    void SetNodeState(uint16 state);

    T_STRUCTBUDDYINFO GetBuddyInfo()const;

    void SetBuddyInfo(T_STRUCTBUDDYINFO info);

    void SetLatestHyperBlock(uint64 hyperid, const T_SHA256& hhash, uint64 hyperctime);

    inline uint64 GetLatestHyperBlockId() const { return latestHyperblockId; };

    const T_SHA256& GetLatestHyperBlockHash() const { return latestHyperBlockHash; };

    void GetMulticastNodes(vector<CUInt128>& MulticastNodes);

    void UpdateOnChainingState(const T_HYPERBLOCK& hyperblock);

    bool ApplicationCheck(T_HYPERBLOCK& hyperblock);
    bool ApplicationAccept(uint32_t hidFork, T_HYPERBLOCK& hyperblock, bool isLatest);

    void UpdateLocalBuddyBlockToLatest(uint64 prehyperblockid, const T_SHA256& preHyperBlockHash);

    void CleanConsensusEnv();

    //HC:跟踪本地块上链状态
    void TrackLocalBlock(const T_LOCALBLOCK& localblock);
    void InitOnChainingState(uint64 hid);
    void RehandleOnChainingState(uint64 hid);

    void SetAppCallback(const T_APPTYPE& app, const CONSENSUSNOTIFY& notify);
    void RemoveAppCallback(const T_APPTYPE& app);

    template<cbindex I, typename... Args>
    bool AllAppCallback(Args&... args)
    {
        //HC: copy _mapcbfn, avoid crash when exiting the program which will call RemoveAppCallback to unregister the application
        //HC: RemoveAppCallback will erase the elements in _mapcbfn, so here traversing _mapcbfn maybe cause crash
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
        //HC: If use lock, it will cause dead lock when calling RPC command addamounttoaddress
        //HC: which hold mutex: cs_main then _muxmapcbfn
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

    void ToAppPayloads(const T_HYPERBLOCK& hyperblock, map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload);

private:

    unordered_map<T_APPTYPE, CONSENSUSNOTIFYSTATESP> _mapcbfn;
    uint32 _NEXTBUDDYTIME = NEXTBUDDYTIME;
    uint32 _LOCALBUDDYTIME = LOCALBUDDYTIME;
    uint32 _GLOBALBUDDYTIME = GLOBALBUDDYTIME;

}T_P2PMANAGERSTATUS, * T_PP2PMANAGERSTATUS;


//////////////////////////////////////////////////////////////////////////
