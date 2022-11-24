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
#include "newLog.h"
#include "buddyinfo.h"
#include "onchainhashtask.hpp"
#include "node/NodeManager.h"
#include "onchainconfirmtask.hpp"
#include "db/HyperchainDB.h"
#include "consensus_engine.h"
#include "consensus/globalbuddyhashtask.h"
#include "AppPlugins.h"

#include "headers/commonstruct.h"
#include "headers/lambda.h"
#include "headers/inter_public.h"

#include "../node/IAccessPoint.h"
#include "../node/UdpAccessPoint.hpp"
#include "../node/HCMQWrk.h"
#include "../node/HCMQClient.h"
#include "../HyperChain/HyperChainSpace.h"
#include "../vm/vm.h"

#include "../node/PingPongTask.h"
#include "../node/PingPongWithGenBlockHHashTask.hpp"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/bind.hpp>

#define MAX_BUF_LEN (1024 * 32)


void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type);
bool mergeChains(LIST_T_LOCALCONSENSUS &globallist, LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid);
bool checkAppType(const T_LOCALBLOCK& localblock, const T_LOCALBLOCK& buddyblock);

extern void getFromStream(boost::archive::binary_iarchive &ia, T_HYPERBLOCK& hyperblock, T_SHA256& hash);

//HC: local_dur: duration of local buddy phase
//HC: global_dur: duration of global buddy phase
//HC: persist_dur: duration of data persistence phase
bool ParseConsensusParas(const string& consen, uint32 &local_dur, uint32& global_dur, uint32& persist_dur)
{
    list<string> sections;
    stringTostringlist(consen, sections, ':');

    if (sections.size() != 3) {
        cerr << "Invalid consensus duration parameters\n";
        return false;
    }
    auto val_iter = sections.begin();
    local_dur = std::stoul(*val_iter);
    global_dur = std::stoul(*(++val_iter));
    persist_dur = std::stoul(*(++val_iter));

    if (local_dur < 8) {
        local_dur = 8;
    }

    if (global_dur < 10) {
        global_dur = 10;
    }

    if (persist_dur < 12) {
        persist_dur = 12;
    }

    cout << StringFormat("Consensus parameters(seconds): local buddy:%d global buddy:%d persistence:%d\n",
                         local_dur, global_dur,persist_dur);
    return true;
}

ConsensusEngine::ConsensusEngine() : _isstop(false),
                                     _is_able_to_consensus(false),
                                     _tP2pManagerStatus(new T_P2PMANAGERSTATUS())
{
    _onchaindatasize = 1000;
    if (mapHCArgs.count("-consensus")) {
        string consen = mapHCArgs.at("-consensus");
        uint32 local_dur;
        uint32 global_dur;
        uint32 persist_dur;
        if (ParseConsensusParas(consen, local_dur, global_dur, persist_dur)) {
            _tP2pManagerStatus->SetConsensusTime(local_dur,
                local_dur + global_dur,
                local_dur + global_dur + persist_dur);
        }
    }
}

ConsensusEngine::~ConsensusEngine()
{
    stopTest();
    stop();
    delete _tP2pManagerStatus;
}

void ConsensusEngine::StartMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&ConsensusEngine::DispatchService, this, std::placeholders::_1, std::placeholders::_2);

    _msghandler.registerWorker(CONSENSUS_SERVICE, fwrk);
    _msghandler.registerTaskWorker(CONSENSUS_T_SERVICE);

    _msghandler.registerTimer(5 * 1000, std::bind(&ConsensusEngine::DispatchConsensus, this), true);
    _msghandler.registerTimer(2 * 1000, std::bind(&ConsensusEngine::LocalBuddyReq, this));
    _msghandler.registerTimer(2 * 1000, std::bind(&ConsensusEngine::LocalBuddyRsp, this));

    auto createfunc = [&]() ->zmq::socket_t * {
        _hyperblock_updated = new zmq::socket_t(*g_inproc_context, ZMQ_SUB);
        _hyperblock_updated->connect(HYPERBLOCK_PUB_SERVICE);
        _hyperblock_updated->setsockopt(ZMQ_SUBSCRIBE, "", 0);
        return _hyperblock_updated;
    };

    std::function<void(void*, zmsg*)> fhblock =
        std::bind(&ConsensusEngine::HyperBlockUpdated, this, std::placeholders::_1, std::placeholders::_2);
    _msghandler.registerSocket(createfunc, fhblock);

//    _msghandler.registerTaskType<OnChainTask>(TASKTYPE::ON_CHAIN);
    _msghandler.registerTaskType<OnChainRspTask>(TASKTYPE::ON_CHAIN_RSP);
    _msghandler.registerTaskType<OnChainConfirmTask>(TASKTYPE::ON_CHAIN_CONFIRM);
    _msghandler.registerTaskType<OnChainConfirmRspTask>(TASKTYPE::ON_CHAIN_CONFIRM_RSP);
    _msghandler.registerTaskType<OnChainWaitTask>(TASKTYPE::ON_CHAIN_WAIT);
    _msghandler.registerTaskType<CopyBlockTask>(TASKTYPE::COPY_BLOCK);
    _msghandler.registerTaskType<OnChainRefuseTask>(TASKTYPE::ON_CHAIN_REFUSE);
    //    _msghandler.registerTaskType<GlobalBuddyStartTask>(TASKTYPE::GLOBAL_BUDDY_START_REQ);
//   _msghandler.registerTaskType<GlobalBuddyRspTask>(TASKTYPE::GLOBAL_BUDDY_RSP);
//   _msghandler.registerTaskType<GlobalBuddySendTask>(TASKTYPE::GLOBAL_BUDDY_SEND_REQ);

    //Opti-consensus
    _msghandler.registerTaskType<OnChainHashTask>(TASKTYPE::ON_CHAIN_HASH);
    _msghandler.registerTaskType<OnChainHashRspTask>(TASKTYPE::ON_CHAIN_HASH_RSP);
    _msghandler.registerTaskType<OnChainBlockTask>(TASKTYPE::ON_CHAIN_BLOCK);
    _msghandler.registerTaskType<GlobalBuddyHashStartTask>(TASKTYPE::GLOBAL_BUDDY_HASH_START_REQ);
    _msghandler.registerTaskType<GlobalBuddyHashRspTask>(TASKTYPE::GLOBAL_BUDDY_HASH_RSP);
    _msghandler.registerTaskType<GlobalBuddyHashRspForwardTask>(TASKTYPE::GLOBAL_BUDDY_HASH_RSP_FORWARD);
    _msghandler.registerTaskType<GlobalBuddyHashSendTask>(TASKTYPE::GLOBAL_BUDDY_HASH_SEND_REQ);
    _msghandler.registerTaskType<GlobalBuddyHashBlockTask>(TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK);
    _msghandler.registerTaskType<GlobalBuddyHashBlockRspTask>(TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK_RSP);
    _msghandler.registerTaskType<GlobalBuddyHashForwardTask>(TASKTYPE::GLOBAL_BUDDY_HASH_FORWARD);

    _msghandler.start();

    cout << "ConsensusEngine MQID: " << MQID() << endl;

    _tP2pManagerStatus->threadid = _msghandler.getID();
}

void ConsensusEngine::TestOnchain()
{
    std::function<void(int)> sleepfn = [this](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstoptest) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    };

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();
    string strNodeID = me->getNodeId<CUInt128>().ToHexString();

    bool bRandom = true;
    if (mapHCArgs.count("-onchaindata")) {
        int64 nCount = stoi(mapHCArgs["-onchaindata"]);
        //HC:限制模拟数据大小0~20M
        if (nCount > 0 && nCount <= 20000000) {
            _onchaindatasize = nCount;
            bRandom = false;
        }
    }

    while (!_isstoptest) {
        size_t s = _tP2pManagerStatus->GetListOnChainReqCount();
        if (s > 1) {
            sleepfn(30);
            continue;
        }
        string requestid;

        uint32 nOrder;
        string excp_desc;

        //HC:准备随机数据
        //HC:模拟数据大小为随机数200K-2M
        if (bRandom)
            _onchaindatasize = ((rand() % 80) + 20) * 10000;

        int8 randchar[1024 + 1] = { 0 };
        for (int i = 0; i < 1024; i++) {
            randchar[i] = 32 + (rand() % 90);
        }

        SubmitData msgData;
        msgData.payload = strNodeID + string(randchar, 1024) + string(_onchaindatasize, 32 + (rand() % 90));

        AddNewBlockEx(msgData, requestid, nOrder, excp_desc);
        cout << "Created a test block: " << requestid << endl;

        sleepfn(30);
    }
}


uint32 ConsensusEngine::AddChainEx(const T_APPTYPE& app, vector<PostingBlock>& postingchain)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        LIST_T_LOCALCONSENSUS listLocalConsensusInfo;

        size_t num = postingchain.size();
        for (size_t i = 0; i < num; i++) {
            T_LOCALCONSENSUS lconsensus;
            T_BLOCKSTATEADDR sa;
            sa.SetPeerAddr(T_PEERADDRESS(postingchain[i].nodeid));
            lconsensus.SetPeer(sa);

            T_LOCALBLOCK& tLocalBlock = lconsensus.GetLocalBlock();

            tLocalBlock.SetAppType(app);
            tLocalBlock.SetPayLoad(postingchain[i].payload);
            tLocalBlock.SetPreHyperBlock(_tP2pManagerStatus->GetLatestHyperBlockId(),
                _tP2pManagerStatus->GetLatestHyperBlockHash());

            if (tLocalBlock.isAppTxType()) {
                T_SHA256 h(postingchain[i].hashMTRoot);
                tLocalBlock.SetBlockBodyHash(h);
                tLocalBlock.SetBlockPayloadMTree(std::move(postingchain[i].vecMT));
            } else {
                tLocalBlock.BuildBlockBodyHash();
            }

            tLocalBlock.CalculateHashSelf();
            listLocalConsensusInfo.push_back(std::move(lconsensus));
        }

        //HC: 子链构建完成，合并到全局链容器中
        MergeToGlobalBuddyChains(listLocalConsensusInfo);
        return static_cast<uint32>(listLocalConsensusInfo.size());
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::AddChainEx, &app, &postingchain);

        uint32 nCount = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, nCount);
            delete rspmsg;
        }

        return nCount;
    }
}



bool ConsensusEngine::AddNewBlockEx(const SubmitData &data, string& requestid, uint32 &nOrder, string &excp_desc)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        T_LOCALBLOCK tLocalBlock;
        tLocalBlock.SetAppType(data.app);
        tLocalBlock.SetPayLoad(data.payload);

        tLocalBlock.SetAppType(data.app);
        if (!data.jsbytecode.empty()) {
            tLocalBlock.SetScript(data.jsbytecode);
        }

        tLocalBlock.SetPreHyperBlock(_tP2pManagerStatus->GetLatestHyperBlockId(),
            _tP2pManagerStatus->GetLatestHyperBlockHash());

        if (tLocalBlock.isAppTxType()) {
            T_SHA256 h(data.MTRootHash);
            tLocalBlock.SetBlockBodyHash(h);
        } else {
            tLocalBlock.BuildBlockBodyHash();
        }

        tLocalBlock.CalculateHashSelf();
        requestid = tLocalBlock.GetUUID(); //HC: base58

        _tP2pManagerStatus->TrackLocalBlock(tLocalBlock);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        HCNodeSH & me = nodemgr->myself();

        T_SHA256 h;
        GetSHA256(h.data(), data.payload.c_str(), data.payload.size());

        T_LOCALCONSENSUS LocalConsensusInfo(
            T_BLOCKSTATEADDR(T_PEERADDRESS(me->getNodeId<CUInt128>()), T_PEERADDRESS(me->getNodeId<CUInt128>())),
            tLocalBlock,
            0,
            (char*)h.data());

        Singleton<DBmgr>::instance()->InsertOnChainState(requestid, T_LOCALBLOCKADDRESS());
        //HC: 放入待上链链表排队，等待处理
        _tP2pManagerStatus->RequestOnChain(LocalConsensusInfo);
        nOrder = static_cast<uint32>(_tP2pManagerStatus->GetListOnChainReqCount());
        return true;
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::AddNewBlockEx, &data);

        bool ret = false;

        if (rspmsg) {
            MQMsgPop(rspmsg, ret, requestid, nOrder, excp_desc);
            delete rspmsg;
        }
        return ret;
    }
}

void ConsensusEngine::start()
{
    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
    T_HYPERBLOCK h;
    if (sp->GetMaxBlockID() == 0 || !sp->getHyperBlock(0, h)) {
        CreateGenesisBlock();
    }

    uint64 id;
    T_SHA256 hash;
    uint64 ctm;
    sp->GetLatestHyperBlockIDAndHash(id, hash, ctm);
    _tP2pManagerStatus->SetLatestHyperBlock(id, hash, ctm);

    _tP2pManagerStatus->tBuddyInfo.uiCurBuddyNo = sp->GetMaxBlockID() + 1;
    _tP2pManagerStatus->tBuddyInfo.eBuddyState = IDLE;

    StartMQHandler();

    _threads.emplace_back(&ConsensusEngine::CheckMyVersionThread, this);
}

void ConsensusEngine::stop()
{
    _isstop = true;

    _msghandler.stop();

    if (_hyperblock_updated) {
        delete _hyperblock_updated;
    }

    for (auto& t : _threads) {
        t.join();
    }
    _threads.clear();
}

bool ConsensusEngine::CheckConsensusCond()
{
    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
    _is_able_to_consensus = sp->IsLatestHyperBlockReady();

    return _is_able_to_consensus;
}

void ConsensusEngine::PrepareLocalBuddy()
{
    if (_tP2pManagerStatus->HaveOnChainReq()) {
        //HC: put the block into pending-on-chain-list
        ReOnChainFun();

        _tP2pManagerStatus->SetHaveOnChainReq(false);
    }
}

void ConsensusEngine::EmitConsensusSignal(int nDelaySecond)
{
    _msghandler.registerTimer(nDelaySecond * 1000, std::bind(&ConsensusEngine::DispatchConsensus, this), true);
}

void ConsensusEngine::DispatchService(void *wrk, zmsg *msg)
{
    HCMQWrk *realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();
    string u = msg->pop_front();

    int service_t = 0;
    memcpy(&service_t, u.c_str(), sizeof(service_t));

    switch ((SERVICE)service_t) {
        case SERVICE::GetOnChainState: {

            string requestId = msg->pop_front();
            size_t queuenum;

            ONCHAINSTATUS s = GetOnChainState(requestId, queuenum);

            MQMsgPush(msg, s, queuenum);
            break;
        }
        case SERVICE::AddNewBlockEx: {

            SubmitData *data;
            MQMsgPop(msg, data);

            string requestid;
            uint32 nOrder = 0;
            string excp_desc;

            bool ret = AddNewBlockEx(*data, requestid, nOrder, excp_desc);

            MQMsgPush(msg, ret, requestid, nOrder, excp_desc);
            break;
        }
        case SERVICE::AddChainEx: {

            T_APPTYPE *pApp;
            vector<PostingBlock> *pChain = nullptr;

            MQMsgPop(msg, pApp, pChain);

            uint32 ret = AddChainEx(*pApp, *pChain);

            MQMsgPush(msg, ret);
            break;
        }
        case SERVICE::GetStateOfCurrentConsensus: {

            uint64 nblockNo = 0;
            uint16 nblockNum = 0;
            uint16 nchainNum = 0;
            uint16 ret = GetStateOfCurrentConsensus(nblockNo, nblockNum, nchainNum);

            MQMsgPush(msg, ret, nblockNo, nblockNum, nchainNum);
            break;
        }
        case SERVICE::GetDetailsOfCurrentConsensus: {
            size_t reqblknum, rspblknum, reqchainnum, rspchainnum;
            size_t localchainBlocks, globalbuddychainnum;
            LIST_T_LOCALCONSENSUS *localbuddychaininfos = nullptr;

            MQMsgPop(msg, localbuddychaininfos);

            GetDetailsOfCurrentConsensus(reqblknum, rspblknum, reqchainnum, rspchainnum,
                localchainBlocks, localbuddychaininfos, globalbuddychainnum);
            MQMsgPush(msg, reqblknum, rspblknum, reqchainnum, rspchainnum, localchainBlocks, globalbuddychainnum);
            break;
        }
        case SERVICE::CheckSearchOnChainedPool: {

            LB_UUID requestId = msg->pop_front();

            T_LOCALBLOCKADDRESS *paddr = nullptr;
            MQMsgPop(msg, paddr);

            bool ret = CheckSearchOnChainedPool(requestId, *paddr);
            MQMsgPush(msg, ret);
            break;

        }
        case SERVICE::InitOnChainingState: {

            uint64_t blockid;
            MQMsgPop(msg, blockid);
            InitOnChainingState(blockid);
            break;
        }
        case SERVICE::RehandleOnChainingState: {

            uint64_t blockid;
            MQMsgPop(msg, blockid);
            RehandleOnChainingState(blockid);
            break;
        }
        case SERVICE::RegisterAppCallback: {

            T_APPTYPE *pApp = nullptr;
            CONSENSUSNOTIFY *cssnotify = nullptr;

            MQMsgPop(msg, pApp, cssnotify);
            RegisterAppCallback(*pApp, *cssnotify);
            break;
        }
        case SERVICE::UnregisterAppCallback: {

            T_APPTYPE *pApp = nullptr;
            MQMsgPop(msg, pApp);
            UnregisterAppCallback(*pApp);
            break;
        }

        default:
            _tP2pManagerStatus->ReplyMsg(service_t, msg);
            break;
    }
    realwrk->reply(reply_who, msg);
}

void ConsensusEngine::InitOnChainingState(uint64_t blockid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        _tP2pManagerStatus->InitOnChainingState(blockid);
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::InitOnChainingState, blockid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void ConsensusEngine::RehandleOnChainingState(uint64_t blockid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        _tP2pManagerStatus->RehandleOnChainingState(blockid);
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::RehandleOnChainingState, blockid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void ConsensusEngine::DispatchConsensus()
{
    static bool indexLobal = false;
    static bool indexGlobal = true;
    static bool bFirstTimes = true;
    static system_clock::time_point searchOnChainStatetimepoint = system_clock::now();
    static system_clock::time_point sendtimepoint = system_clock::now();
    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();

    if (_isstop) {
        return;
    }

    if (!_is_able_to_consensus && !CheckConsensusCond()) {
        EmitConsensusSignal(5);
        return;
    }

    switch (_tP2pManagerStatus->GetCurrentConsensusPhase()) {
        case CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE: {

            if (system_clock::now() > searchOnChainStatetimepoint) {
                SearchOnChainState();
                searchOnChainStatetimepoint = system_clock::now() + std::chrono::seconds(NEXTBUDDYTIME);
            }
            bFirstTimes = true;
            indexLobal = false;

            //HC: 处理上一个共识周期本地的上链数据，如果没有成功那么本周期准备重新上链
            T_HYPERBLOCK hyperblock;
            sp->GetLatestHyperBlock(hyperblock);
            UpdateMyBuddyBlock(hyperblock);

            _tP2pManagerStatus->CleanConsensusEnv();

            if (_is_able_to_consensus) {
                PrepareLocalBuddy();
            }
            EmitConsensusSignal(2);
            break;
        }
        case CONSENSUS_PHASE::LOCALBUDDY_PHASE: {
            if (!_is_able_to_consensus) {
                if (CheckConsensusCond()) {
                    PrepareLocalBuddy();
                }
                EmitConsensusSignal(2);
                break;
            }

            if (!indexLobal) {
                indexLobal = true;
                //HC: Notify application layer
                _tP2pManagerStatus->AllAppCallback<cbindex::PUTONCHAINIDX>();
            }

            size_t tempNum = _tP2pManagerStatus->listCurBuddyRsp.size();
            if (tempNum != 0) {
                EmitConsensusSignal(2);
                break;
            }

            indexGlobal = false;

            if (!_tP2pManagerStatus->HaveOnChainReq()) {
                //HC: 将要共识的块数据放到共识队列 listLocalBuddyChainInfo
                GetOnChainInfo();
            }

            size_t tempNum2 = _tP2pManagerStatus->listLocalBuddyChainInfo.size();
            if (tempNum2 == 0) {
                //HC: no data in consensus list,so notify the application layer to commit data.
                PrepareLocalBuddy();
                EmitConsensusSignal(2);
                break;
            }

            g_consensus_console_logger->trace("The Node enter LOCAL_BUDDY status, broadcast Local Consensus Request");
            _tP2pManagerStatus->tBuddyInfo.eBuddyState = LOCAL_BUDDY;

            SendLocalBuddyReq();
            EmitConsensusSignal(10);

            break;
        }
        case CONSENSUS_PHASE::GLOBALBUDDY_PHASE: {
            if (!indexGlobal) {
                indexGlobal = true;
                g_consensus_console_logger->trace("The Node enter GLOBAL_BUDDY status");

                //HC: Firstly only put local chain into global chain, then allow to merge chains from other nodes
                //HC: so the calling sequence is StartGlobalBuddy then SetStartGlobalFlag
                StartGlobalBuddy();

                _tP2pManagerStatus->SetStartGlobalFlag(true);
                _tP2pManagerStatus->tBuddyInfo.eBuddyState = GLOBAL_BUDDY;
            }
            else {
                //HC: Broadcast Global Consensus Request every 10 seconds                
                //if (system_clock::now() - sendtimepoint > std::chrono::seconds(10)) {
                    SendGlobalBuddyReq();
                //    sendtimepoint = system_clock::now();
                //}
            }
            TryCreateHyperBlock();
            EmitConsensusSignal(15);
            break;
        }
        case CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE: {
            _tP2pManagerStatus->SetStartGlobalFlag(false);
            indexGlobal = false;
            _is_able_to_consensus = false;
            _is_requested_latest_hyperblock = false;

            if (bFirstTimes) {
                TryCreateHyperBlock();
                if (_tP2pManagerStatus->bHyperBlockCreated) {
                    //HC: broadcast hyper block
                    string mynodeid = "myself";
                    vector<CUInt128> MulticastNodes;
                    _tP2pManagerStatus->GetMulticastNodes(MulticastNodes);

                    sp->PutHyperBlock(_tP2pManagerStatus->tHyperBlock, mynodeid, MulticastNodes);
                }

                bFirstTimes = false;
            }
            EmitConsensusSignal(5);
            break;
        }
    }
}

bool ConsensusEngine::IsMakeBuddy() {
    for (auto& buddystate : _tP2pManagerStatus->listCurBuddyReq) {
        if (buddystate.GetBuddyState() == IS_CONFIRM)
            return true;
    }

    for (auto& buddystate : _tP2pManagerStatus->listCurBuddyRsp) {
        if (buddystate.GetBuddyState() == SEND_CONFIRM)
            return true;
    }

    return false;    
}

void ConsensusEngine::LocalBuddyReq()
{
    while (!_isstop && !IsMakeBuddy()) {
        if (_tP2pManagerStatus->GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
            {
                _tP2pManagerStatus->listCurBuddyReq.clear();
                _tP2pManagerStatus->listRecvLocalBuddyReq.clear();
            }
            break;
        }

        if (_tP2pManagerStatus->listRecvLocalBuddyReq.size() == 0) {
            break;
        }

        if (_tP2pManagerStatus->listCurBuddyReq.size() > LIST_BUDDY_RSP_NUM) {
            break;
        } else {
            T_BUDDYINFO localInfo;
            localInfo = _tP2pManagerStatus->listRecvLocalBuddyReq.front();
            _tP2pManagerStatus->listRecvLocalBuddyReq.pop_front();
            _tP2pManagerStatus->tLocalBuddyAddr = localInfo.GetRequestAddress();

            OnChainRspTask task(localInfo.GetRequestAddress()._nodeid,
                std::move(localInfo.GetBuffer()),
                localInfo.GetBufferLength());
            task.exec();
        }
    }
}

void ConsensusEngine::LocalBuddyRsp()
{
    while (!_isstop && !IsMakeBuddy()) {
        if (_tP2pManagerStatus->GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
            _tP2pManagerStatus->listCurBuddyRsp.clear();
            _tP2pManagerStatus->listRecvLocalBuddyRsp.clear();
            break;
        }

        if (_tP2pManagerStatus->listRecvLocalBuddyRsp.size() == 0) {
            break;
        }

        if (_tP2pManagerStatus->listCurBuddyRsp.size() > LIST_BUDDY_RSP_NUM) {
            break;
        } else {
            T_BUDDYINFO localInfo;
            localInfo = _tP2pManagerStatus->listRecvLocalBuddyRsp.front();
            _tP2pManagerStatus->listRecvLocalBuddyRsp.pop_front();
            _tP2pManagerStatus->tLocalBuddyAddr = localInfo.GetRequestAddress();

            ProcessOnChainRspMsg(localInfo.GetRequestAddress()._nodeid,
                const_cast<char*>(localInfo.GetBuffer().c_str()), localInfo.GetBufferLength());
        }
    }
}

time_t convert_str_to_tm(const char * str_time)
{
    struct tm tt;
    memset(&tt, 0, sizeof(tt));
    tt.tm_year = atoi(str_time) - 1900;
    tt.tm_mon = atoi(str_time + 5) - 1;
    tt.tm_mday = atoi(str_time + 8);
    tt.tm_hour = atoi(str_time + 11);
    tt.tm_min = atoi(str_time + 14);
    tt.tm_sec = atoi(str_time + 17);
    return mktime(&tt);
}

const uint64 GENESISBLOCKID = UINT64_MAX;

T_LOCALBLOCK GetAppGenesisBlock(const string& appname, uint16 localid, time_t t, APPTYPE type)
{
    T_LOCALBLOCK localBlock;
    localBlock.SetID(localid);
    localBlock.SetCTime(t);
    localBlock.SetAppType(T_APPTYPE(type, 0, 0, 0));
    localBlock.SetChainNum(1);
    localBlock.SetPreHyperBlock(GENESISBLOCKID, T_SHA256(0));

    string payload;
    string blockmtroothash = g_appPlugin->GetGenesisBlock(appname, payload);
    if (payload.empty() || blockmtroothash.empty()) {
        throw runtime_error(string("cannot get genesis block of ") + appname);
    }

    localBlock.SetPayLoad(payload);

    T_SHA256 tBlockBodyHash(blockmtroothash);
    localBlock.SetBlockBodyHash(tBlockBodyHash);

    return localBlock;
}

void ConsensusEngine::CreateGenesisBlock()
{
    T_SHA512 h(1);
    ostringstream oss;
    oss << "HyperChain, 2020/1/6";

    time_t t = convert_str_to_tm("2020-01-06 10:30:00");

    //HC:To GenesisBlock,block id is 0,previous hyper block id is -1
    T_LOCALBLOCK tLocalBlock;
    tLocalBlock.SetID(1);
    tLocalBlock.SetCTime(t);
    tLocalBlock.SetChainNum(1);
    tLocalBlock.SetPreHyperBlock(GENESISBLOCKID, T_SHA256(0));
    tLocalBlock.SetPayLoad(oss.str());
    tLocalBlock.BuildBlockBodyHash();

    LIST_T_LOCALBLOCK ListLocalBlock;
    ListLocalBlock.push_back(tLocalBlock);

    try {
        //HC: add Paracoin genesis block
        T_LOCALBLOCK paracoinLocalBlock = GetAppGenesisBlock("paracoin", 2, t, APPTYPE::paracoin);
        ListLocalBlock.push_back(paracoinLocalBlock);

        //HC: not need add Ledger genesis block
        //T_LOCALBLOCK ledgerLocalBlock = GetAppGenesisBlock("ledger", 3, t, APPTYPE::ledger);
        //ListLocalBlock.push_back(ledgerLocalBlock);
    }
    catch (std::exception& e) {
        g_consensus_console_logger->anyway("CreateGenesisBlock Failed: {}", e.what());
        return;
    }

    //HC: build hyper block
    T_HYPERBLOCK tHyperBlock;
    tHyperBlock.SetID(0);
    tHyperBlock.SetCTime(t);
    tHyperBlock.SetPreHash(T_SHA256(0));
    tHyperBlock.SetPreHeaderHash(T_SHA256(0));

    tHyperBlock.AddChildChain(std::move(ListLocalBlock));
    tHyperBlock.Rebuild();

    //HC: here must modify
    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
    sp->SaveHyperblock(tHyperBlock);

    T_HYPERBLOCKHEADER header = tHyperBlock.GetHeader();
    sp->PutHyperBlockHeader(header, "myself");
    sp->updateHyperBlockCache(tHyperBlock);

    _tP2pManagerStatus->SetHaveOnChainReq(false);

}


void ConsensusEngine::ProcessOnChainRspMsg(const CUInt128 &peerid, char* pBuf, size_t uiBufLen)
{
    string sBuf(pBuf, uiBufLen);
    stringstream ssBuf(sBuf);
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

    T_P2PPROTOCOLONCHAINRSP P2pProtocolOnChainRspRecv;
    try {
        ia >> P2pProtocolOnChainRspRecv;
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    size_t nodeSize = 0;
    nodeSize = _tP2pManagerStatus->listLocalBuddyChainInfo.size();
    if (nodeSize == 0) {
        return;
    }

    if (nodeSize != ONE_LOCAL_BLOCK && P2pProtocolOnChainRspRecv.GetBlockCount() != ONE_LOCAL_BLOCK) {
        return;
    }

    string strHash(P2pProtocolOnChainRspRecv.GetHash(), DEF_STR_HASH256_LEN);
    //HC: 如果超块不匹配拒绝并退出处理
    uint64 hyperchainnum = P2pProtocolOnChainRspRecv.GetHyperBlockNum();
    if (!isHyperBlockMatched(hyperchainnum, P2pProtocolOnChainRspRecv.tHyperBlockHash, peerid)) {
        g_consensus_console_logger->info("Refuse buddy request for different hyper block from {}", peerid.ToHexString());
        SendRefuseReq(peerid, strHash, RECV_REQ);
        return;
    }

    //HC: Get size of blocks doing consensus again because MQ handle switches
    if (_tP2pManagerStatus->listLocalBuddyChainInfo.size() != ONE_LOCAL_BLOCK) {
        return;
    }

    //HC: 已经放入块集合中了吗？
    ITR_LIST_T_BUDDYINFOSTATE itr = _tP2pManagerStatus->listCurBuddyRsp.begin();
    for (; itr != _tP2pManagerStatus->listCurBuddyRsp.end(); itr++) {
        if (0 == strncmp((*itr).strBuddyHash, P2pProtocolOnChainRspRecv.GetHash(), DEF_STR_HASH256_LEN)) {
            return;
        }
    }

    T_BUDDYINFOSTATE buddyInfo;
    copyLocalBuddyList(buddyInfo.localList, _tP2pManagerStatus->listLocalBuddyChainInfo);

    bool index = false;
    bool isExistMyBlock = false;
    NodeManager *nodemanger = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemanger->myself();

    //HC: 这里取收到的所有块和已有的块合并
    auto firstelm = buddyInfo.localList.begin();
    for (uint64 i = 0; i < P2pProtocolOnChainRspRecv.GetBlockCount(); i++) {
        T_LOCALCONSENSUS  LocalBlockInfo;
        try {
            ia >> LocalBlockInfo;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        //HC:一个节点每个周期只能有一个块
        index = JudgExistAtLocalBuddy(buddyInfo.GetList(), LocalBlockInfo);
        
        /*
        isExistMyBlock = false;
        if (LocalBlockInfo.GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            isExistMyBlock = true;
        }

        if (isExistMyBlock && !index) {
            //HC: 出现2个本节点块,LocalBlockInfo此块是本节点的，但是已经不在buddy队列里
            g_consensus_console_logger->error("There are my two blocks in a consensus period,Skip...");
            //HC: Skip this buddy.
            return;
        }*/

        if (index)
            continue;

        T_LOCALBLOCK& block = LocalBlockInfo.GetLocalBlock();
        if (!checkAppType(firstelm->GetLocalBlock(), block)) {
            g_consensus_console_logger->info("Different application type,cannot make buddy");
            continue;
        }
        buddyInfo.LocalListPushBack(LocalBlockInfo);
        buddyInfo.LocalListSort();
    }

    if (!CheckPayload(buddyInfo.localList)) {
        return;
    }
    buddyInfo.Set(P2pProtocolOnChainRspRecv.GetHash(), RECV_ON_CHAIN_RSP, _tpeeraddress(peerid));

    //HC: listCurBuddyRsp中存储所有待共识的buddy组合
    _tP2pManagerStatus->listCurBuddyRsp.push_back(buddyInfo);

    SendConfirmReq(peerid, P2pProtocolOnChainRspRecv.uiHyperBlockNum,
            strHash, P2P_PROTOCOL_SUCCESS);
}

void ConsensusEngine::GetOnChainInfo()
{
    //HC:检查是否已有本地块
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();
    for (auto& blockinfo : _tP2pManagerStatus->listLocalBuddyChainInfo) {
        if (blockinfo.GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            _tP2pManagerStatus->SetHaveOnChainReq(true);
            return;
        }
    }    
    
    if (_tP2pManagerStatus->listOnChainReq.empty()) {
        _tP2pManagerStatus->tBuddyInfo.eBuddyState = IDLE;
        return;
    }

    T_LOCALCONSENSUS onChainInfo;
    onChainInfo = _tP2pManagerStatus->listOnChainReq.front();
    _tP2pManagerStatus->listOnChainReq.pop_front();

    string requestid = onChainInfo.GetLocalBlock().GetUUID();
    Singleton<DBmgr>::instance()->RecordOnchain1Time(requestid);

    _tP2pManagerStatus->listLocalBuddyChainInfo.emplace_back(std::move(onChainInfo));

    g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo phase:{} push a block:{}",
        (uint8)_tP2pManagerStatus->GetCurrentConsensusPhase(),
        onChainInfo.GetLocalBlock().GetPayLoadPreview());

    _tP2pManagerStatus->listLocalBuddyChainInfo.sort(CmpareOnChain());

    int i = 0;
    for (auto &b : _tP2pManagerStatus->listLocalBuddyChainInfo) {
        g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo:{} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
    }

    _tP2pManagerStatus->tBuddyInfo.usBlockNum = static_cast<uint16>(_tP2pManagerStatus->listLocalBuddyChainInfo.size());

    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
    _tP2pManagerStatus->tBuddyInfo.uiCurBuddyNo = sp->GetMaxBlockID() + 1;
    _tP2pManagerStatus->tBuddyInfo.eBuddyState = LOCAL_BUDDY;
    _tP2pManagerStatus->uiNodeState = CONFIRMING;

    _tP2pManagerStatus->SetHaveOnChainReq(true);

    return;
}

void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type)
{
    OnChainConfirmTask task(peerid, hyperblocknum, hash, type);
    task.exec();
}

void ConsensusEngine::SendLocalBuddyReq()
{
    OnChainHashTask task;
    task.exec();
}

void copyLocalBuddyList(LIST_T_LOCALCONSENSUS &endList, const LIST_T_LOCALCONSENSUS &fromList)
{
    auto itrList = fromList.cbegin();
    for (; itrList != fromList.cend(); itrList++) {
        T_LOCALCONSENSUS tempBlock;
        tempBlock.SetLoaclConsensus((*itrList).GetPeer(), (*itrList).GetLocalBlock());
        endList.push_back(tempBlock);
    }
}

void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type)
{
    OnChainRefuseTask task(peerid, hash, type);
    task.exec();
}

void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock)
{
    CopyBlockTask task(localBlock);
    task.exec();
}

bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo)
{
    for (auto& blockinfo : localList) {
        if (blockinfo.GetPeer().GetPeerAddr() == localBlockInfo.GetPeer().GetPeerAddr())
            return true;
    }
    return false;
    /*
    ITR_LIST_T_LOCALCONSENSUS itrList = localList.begin();
    for (; itrList != localList.end(); itrList++) {
        if (((*itrList).GetPeer().GetPeerAddr() == localBlockInfo.GetPeer().GetPeerAddr())
            && ((*itrList).GetPeer().GetPeerAddrOut() == localBlockInfo.GetPeer().GetPeerAddrOut())) {
            string h1 = (*itrList).GetLocalBlock().GetUUID();
            string h2 = localBlockInfo.GetLocalBlock().GetUUID();
            if (h1 == h2) {
                return true;
            }
        }
    }
    return false;
    */
}

bool ConsensusEngine::MergeToGlobalBuddyChains(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo)
{
    if (listLocalBuddyChainInfo.begin()->GetLocalBlock().GetPreHHash() !=
        _tP2pManagerStatus->GetLatestHyperBlockHash()) {
        return false;
    }

    if (listLocalBuddyChainInfo.size() < LEAST_START_GLOBAL_BUDDY_NUM)
        return false;

    //HC:获取子链类型
    T_LOCALBLOCK& block = listLocalBuddyChainInfo.begin()->GetLocalBlock();
    auto AppType = block.GetAppType();

    //HC:获取listGlobalBuddyChainInfo Hash-ChainItr  map 
    map<T_SHA256, ITR_LIST_LIST_GLOBALBUDDYINFO> mapChain_Hash;   //Hash-ChainItr map
    auto itr = _tP2pManagerStatus->listGlobalBuddyChainInfo.begin();
    for (; itr != _tP2pManagerStatus->listGlobalBuddyChainInfo.end(); itr++) {
        if (AppType == itr->begin()->GetLocalBlock().GetAppType()) {
            for (auto& localinfo : (*itr)) {
                mapChain_Hash[localinfo.GetLocalBlock().GetHashSelf()] = itr;
            }
        }
    }

    //HC:找出listLocalBuddyChainInfo中block所在子链
    vector<ITR_LIST_LIST_GLOBALBUDDYINFO> vectChainItr;                  //HC:包含在listGlobalBuddyChainInfo中的block所在子链索引号
    LIST_T_LOCALCONSENSUS listNewChain;     //HC:不包含在listGlobalBuddyChainInfo中的block
    int nSameChainCount = 0;                //HC:包含在listGlobalBuddyChainInfo中的block个数
    for (auto& localblock : listLocalBuddyChainInfo) {
        T_SHA256 hash = localblock.GetLocalBlock().GetHashSelf();
        if (mapChain_Hash.count(hash) > 0) {
            nSameChainCount++;
            auto& itrtmp = mapChain_Hash[hash];
            bool bfind = false;
            for (int i = 0; i < vectChainItr.size(); i++) {
                if (vectChainItr[i] == itrtmp) {
                    bfind = true;
                    break;
                }
            }
            if (!bfind)
                vectChainItr.push_back(itrtmp);
        }
        else {
            listNewChain.push_back(localblock);
        }
    }

    if (block.isAppTxType()) {
        //HC:APP类型的子链：
        //HC:如果是被包含/重复的子链，直接返回false而不是作为新子链插入listGlobalBuddyChainInfo
        
        //HC:被包含/重复的子链
        if (vectChainItr.size() == 1) {
            if (listNewChain.size() == 0)
                return false;
            else {
                //HC:删除被包含的子链
                itr = vectChainItr[0];
                if (nSameChainCount == itr->size()) {
                    _tP2pManagerStatus->listGlobalBuddyChainInfo.erase(itr);
                }
            }
        }
        
        //HC:新子链
        _tP2pManagerStatus->listGlobalBuddyChainInfo.push_back(listLocalBuddyChainInfo);
        _tP2pManagerStatus->tBuddyInfo.usChainNum = static_cast<uint16>(_tP2pManagerStatus->listGlobalBuddyChainInfo.size());
        _tP2pManagerStatus->listGlobalBuddyChainInfo.sort(CmpareGlobalBuddy());
        _tP2pManagerStatus->bGlobalChainChangeFlag = true;

        return true;

    } else {
        //HC:非APP类型
        //HC:新子链
        if (vectChainItr.size() == 0) {
            _tP2pManagerStatus->listGlobalBuddyChainInfo.push_back(listLocalBuddyChainInfo);
            _tP2pManagerStatus->tBuddyInfo.usChainNum = static_cast<uint16>(_tP2pManagerStatus->listGlobalBuddyChainInfo.size());
            _tP2pManagerStatus->listGlobalBuddyChainInfo.sort(CmpareGlobalBuddy());
            _tP2pManagerStatus->bGlobalChainChangeFlag = true;

            return true;
        }

        //HC:listLocalBuddyChainInfo与超过2条子链有交集: (a,b) (c,d) <-- (a,b,c,d)
        if (vectChainItr.size() > 1) {
            g_consensus_console_logger->warn("Over two chains have same blocks with this chain! ");
            return false;
        }
        
        //HC:vectChainItr.size() == 1 
        //HC:error：1个block存在于2个子链中: (a,b) <--(a,c)
        if (nSameChainCount == 1) {
            g_consensus_console_logger->critical("Two chains have one same block! ");
            return false;
        }

        //HC:被包含/重复的子链: (a,b,c) <-- (a,b)/(a,b,c)
        if (listNewChain.size() == 0)
            return false;

        //HC:listNewChain.size() > 0
        //HC:将包含的子链与listNewChain合并形成新子链: (a,b) <-- (a,b,c) = (a,b,c)
        itr = vectChainItr[0];
        for (auto& blockinfo : listNewChain) {
            itr->push_back(blockinfo);
        }

        _tP2pManagerStatus->tBuddyInfo.usChainNum = static_cast<uint16>(_tP2pManagerStatus->listGlobalBuddyChainInfo.size());
        _tP2pManagerStatus->listGlobalBuddyChainInfo.sort(CmpareGlobalBuddy());
        _tP2pManagerStatus->bGlobalChainChangeFlag = true;

        return true;
    }
};

bool mergeChains(LIST_T_LOCALCONSENSUS &globallist, LIST_T_LOCALCONSENSUS &locallist)
{
    bool chainchanged = false;
    for (auto &localblock : locallist) {
        auto r = std::find_if(globallist.begin(), globallist.end(), [&](const T_LOCALCONSENSUS &globalblock) {
            if ((localblock.GetLocalBlock().GetUUID()
                == globalblock.GetLocalBlock().GetUUID())) {
                return true;
            }
            return false;
            });

        if (r == globallist.end()) {
            globallist.emplace_back(localblock);
            chainchanged = true;
        }
    }
    return chainchanged;
}

//HC: on chain try again
void ConsensusEngine::ReOnChainFun()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    T_LOCALCONSENSUS localInfo;
    ITR_LIST_T_LOCALCONSENSUS itrList = _tP2pManagerStatus->listLocalBuddyChainInfo.begin();
    for (; itrList != _tP2pManagerStatus->listLocalBuddyChainInfo.end(); itrList++) {
        if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            T_LOCALCONSENSUS& localInfo = (*itrList);

            g_consensus_console_logger->info("***ReOnChainFun***: phase:{} block:{}",
                (uint8)_tP2pManagerStatus->GetCurrentConsensusPhase(),
                localInfo.GetLocalBlock().GetPayLoadPreview());

            localInfo.uiRetryTime += 1;
            _tP2pManagerStatus->listOnChainReq.emplace_front(std::move(localInfo));
            _tP2pManagerStatus->listLocalBuddyChainInfo.clear();

            break;
        }
    }
}

bool CurBuddyBlockInTheHyperBlock(const T_HYPERBLOCK &blockInfos, T_LOCALCONSENSUS *buddyblock)
{
    bool index = false;
    auto itr = blockInfos.GetChildChains().begin();
    for (; itr != blockInfos.GetChildChains().end(); ++itr) {
        auto subItr = itr->begin();
        for (; subItr != itr->end(); subItr++) {
            //HC: don't use block hash which is variable
            if (buddyblock->GetLocalBlockUUID() == subItr->GetUUID()) {
                index = true;
                break;
            }
        }

        if (index) {
            break;
        }
    }
    return index;
}

//HC: 块数据是否上链成功，如果不成功下个共识周期继续上链
//HC: 如果上链成功，清空上链数据链表
//HC: TO DO: 这里不完善需要改进，未考虑分叉情况,一旦分叉上链的结果可能完全不同。
void ConsensusEngine::UpdateMyBuddyBlock(const T_HYPERBLOCK &h)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    //HC: Is my local block in hyperblock?
    T_LOCALCONSENSUS *localInfo = nullptr;
    if (_tP2pManagerStatus->listLocalBuddyChainInfo.size() == 0 && _tP2pManagerStatus->listOnChainReq.size() == 0) {
        return;
    }
    auto itrList = _tP2pManagerStatus->listLocalBuddyChainInfo.begin();
    for (; itrList != _tP2pManagerStatus->listLocalBuddyChainInfo.end(); itrList++) {
        if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            localInfo = &(*itrList);
            break;
        }
    }
    if (!localInfo) {
        return;
    }
    bool isIncluded = false;
    isIncluded = CurBuddyBlockInTheHyperBlock(h, localInfo);
    g_consensus_console_logger->info("updateMyBuddyBlock: current buddy block included in hyperblock? {}", isIncluded);
    if (!isIncluded) {
        ReOnChainFun();
    } else {
        //HC: All block in hyper chain,so clear local buddy chain.
        _tP2pManagerStatus->listLocalBuddyChainInfo.clear();
    }
}

void ConsensusEngine::HyperBlockUpdated(void *sock, zmsg *msg)
{
    uint32_t hidFork;
    string sHyperBlockBuf;
    bool needSwitch;
    bool isLatest;

    MQMsgPop(msg, hidFork, sHyperBlockBuf, isLatest, needSwitch);

    stringstream ssBuf(sHyperBlockBuf);
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

    T_SHA256 hash;
    T_HYPERBLOCK  h;
    try {
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        getFromStream(ia, h, hash);
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }
    catch (runtime_error& e) {
        g_consensus_console_logger->warn("{}", e.what());
        return;
    }
    catch (std::exception& e) {
        g_consensus_console_logger->warn("{}", e.what());
        return;
    }
    catch (...) {
        g_consensus_console_logger->error("unknown exception occurs");
        return;
    }

    if (isLatest) {
        _tP2pManagerStatus->SetLatestHyperBlock(h.GetID(), h.GetHashSelf(), h.GetCTime());
    }
    AsyncHyperBlockUpdated(h);

    if (needSwitch) {
        _tP2pManagerStatus->RehandleOnChainingState(h.GetID());
    } else {
        _tP2pManagerStatus->InitOnChainingState(h.GetID());
    }
    _tP2pManagerStatus->UpdateOnChainingState(h);
    _tP2pManagerStatus->ApplicationAccept(hidFork, h, isLatest);
}

void ConsensusEngine::AsyncHyperBlockUpdated(const T_HYPERBLOCK &h)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    //HC: Is my local block in Hyperblock?
    T_LOCALCONSENSUS *localInfo = nullptr;
    if (_tP2pManagerStatus->listLocalBuddyChainInfo.size() == 0 && _tP2pManagerStatus->listOnChainReq.size() == 0) {
        return;
    }
    auto itrList = _tP2pManagerStatus->listLocalBuddyChainInfo.begin();
    for (; itrList != _tP2pManagerStatus->listLocalBuddyChainInfo.end(); itrList++) {
        if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            localInfo = &(*itrList);
            break;
        }
    }

    bool isIncluded = false;
    if (localInfo) {
        isIncluded = CurBuddyBlockInTheHyperBlock(h, localInfo);
        g_consensus_console_logger->info("AsyncHyperBlockUpdated: current buddy block included in hyperblock : {}", isIncluded);
        if (isIncluded) {
            //HC: Local block is in Hyperblock,so clear local buddy chain.
            _tP2pManagerStatus->listLocalBuddyChainInfo.clear();
            return;
        }
    }

    T_SHA256 preHyperBlockHash;
    uint64 prehyperblockid = 0;
    uint64 ctm;

    CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
    sp->GetLatestHyperBlockIDAndHash(prehyperblockid, preHyperBlockHash, ctm);

    _tP2pManagerStatus->UpdateLocalBuddyBlockToLatest(prehyperblockid, preHyperBlockHash);

    //HC: 检查待共识上链队列中的本地块是否已经上链
    itrList = _tP2pManagerStatus->listOnChainReq.begin();
    for (; itrList != _tP2pManagerStatus->listOnChainReq.end(); itrList++) {
        isIncluded = CurBuddyBlockInTheHyperBlock(h, &(*itrList));
        if (isIncluded) {
            _tP2pManagerStatus->listOnChainReq.erase(itrList);
            g_consensus_console_logger->info("AsyncHyperBlockUpdated: listOnChainReq's buddy block included in hyperblock");
            break;
        }
    }
}


void ConsensusEngine::StartGlobalBuddy()
{
    //HC:记录onchain2time
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();
   
    //HC: Insert chain of application layer to do global consensus
    _tP2pManagerStatus->AllAppCallback<cbindex::PUTGLOBALCHAINIDX>();

    for (auto& buddyinfo : _tP2pManagerStatus->listLocalBuddyChainInfo) {
        if (buddyinfo.GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            string requestid = buddyinfo.GetLocalBlock().GetUUID();
            Singleton<DBmgr>::instance()->RecordOnchain2Time(requestid);
        }
    }

    //HC: Broadcast my local chain to neighbor nodes
    //GlobalBuddyStartTask task;
    //optimise consensus
    GlobalBuddyHashStartTask task;
    task.exec();
}

void ConsensusEngine::SendGlobalBuddyReq()
{
    GlobalBuddyHashSendTask task;
    task.exec();
}

uint ConsensusEngine::GetStateOfCurrentConsensus(uint64 &blockNo, uint16 &blockNum, uint16 &chainNum)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        blockNo = _tP2pManagerStatus->GetBuddyInfo().GetCurBuddyNo();
        blockNum = _tP2pManagerStatus->GetBuddyInfo().GetBlockNum();
        chainNum = _tP2pManagerStatus->GetBuddyInfo().GetChainNum();

        return _tP2pManagerStatus->GetBuddyInfo().GetBuddyState();
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::GetStateOfCurrentConsensus);

        uint ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret, blockNo, blockNum, chainNum);
            delete rspmsg;
        }
        return ret;
    }
}

void ConsensusEngine::GetDetailsOfCurrentConsensus(size_t &reqblknum,
    size_t &rspblknum,
    size_t &reqchainnum,
    size_t &rspchainnum,
    size_t &localchainBlocks,
    LIST_T_LOCALCONSENSUS *localbuddychaininfos,
    size_t &globalbuddychainnum)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        reqblknum = _tP2pManagerStatus->listRecvLocalBuddyReq.size();
        rspblknum = _tP2pManagerStatus->listRecvLocalBuddyRsp.size();
        reqchainnum = _tP2pManagerStatus->listCurBuddyReq.size();
        rspchainnum = _tP2pManagerStatus->listCurBuddyRsp.size();
        localchainBlocks = _tP2pManagerStatus->listLocalBuddyChainInfo.size();
        if (localbuddychaininfos)
            *localbuddychaininfos = _tP2pManagerStatus->listLocalBuddyChainInfo;
        globalbuddychainnum = _tP2pManagerStatus->listGlobalBuddyChainInfo.size();
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::GetDetailsOfCurrentConsensus, localbuddychaininfos);

        if (rspmsg) {
            MQMsgPop(rspmsg,
                reqblknum,
                rspblknum,
                reqchainnum,
                rspchainnum,
                localchainBlocks,
                globalbuddychainnum);
            delete rspmsg;
        }
    }
}

ONCHAINSTATUS ConsensusEngine::GetOnChainState(const LB_UUID& requestId, size_t &queuenum)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        LIST_T_LOCALCONSENSUS::iterator itrOnChain = _tP2pManagerStatus->listOnChainReq.begin();
        queuenum = 0;
        for (; itrOnChain != _tP2pManagerStatus->listOnChainReq.end(); itrOnChain++) {
            queuenum++;
            if (0 == requestId.compare((*itrOnChain).GetLocalBlockUUID().c_str())) {
                return ONCHAINSTATUS::queueing;
            }
        }

        LIST_T_LOCALCONSENSUS::iterator itrOnChaining = _tP2pManagerStatus->listLocalBuddyChainInfo.begin();
        for (; itrOnChaining != _tP2pManagerStatus->listLocalBuddyChainInfo.end(); itrOnChaining++) {
            if (0 == requestId.compare((*itrOnChaining).GetLocalBlockUUID().c_str())) {
                CONSENSUS_PHASE phase = _tP2pManagerStatus->GetCurrentConsensusPhase();
                if ((phase == CONSENSUS_PHASE::GLOBALBUDDY_PHASE || phase == CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE)
                    && _tP2pManagerStatus->listLocalBuddyChainInfo.size() > 1) {
                    return ONCHAINSTATUS::onchaining2;
                }
                return ONCHAINSTATUS::onchaining1;
            }
        }
        return ONCHAINSTATUS::unknown;
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::GetOnChainState, requestId);

        ONCHAINSTATUS s = ONCHAINSTATUS::unknown;

        if (rspmsg) {
            MQMsgPop(rspmsg, s, queuenum);
            delete rspmsg;
        }
        return s;
    }
}

bool ConsensusEngine::CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (_tP2pManagerStatus->mapSearchOnChain.count(requestId) > 0) {
            addr = _tP2pManagerStatus->mapSearchOnChain.at(requestId).addr;
            return true;
        }
        return false;
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::CheckSearchOnChainedPool, requestId, &addr);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

extern bool CheckMyVersion(string& newversion);
void ConsensusEngine::CheckMyVersionThread()
{
    std::function<void(int)> sleepfn = [this](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstop) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    };

    time_t nextChecktime = 0;
    while (!_isstop) {
        string strNewVersion;
        time_t now = time(nullptr);
        if (nextChecktime < now) {
            if (CheckMyVersion(strNewVersion)) {
                nextChecktime = now + 24 * 60 * 60;
            }
        }
        if (!strNewVersion.empty() && strNewVersion > VERSION_STRING) {
            g_consensus_console_logger->anyway("Found new version: {}, current version: {}, Please update", strNewVersion, VERSION_STRING);
        }
        sleepfn(10 * 60);
    }
}

void ConsensusEngine::SearchOnChainState()
{
    ITR_MAP_T_SEARCHONCHAIN itr = _tP2pManagerStatus->mapSearchOnChain.begin();
    for (; itr != _tP2pManagerStatus->mapSearchOnChain.end();) {
        size_t queuenum;
        ONCHAINSTATUS status = GetOnChainState((*itr).first, queuenum);
        uint64 timeNow = (uint64)time(nullptr);
        if (timeNow - (*itr).second.uiTime > MATURITY_TIME &&
            status == ONCHAINSTATUS::unknown) {
            //记录成熟时间
            string requestid = (*itr).first;
            T_LOCALBLOCKADDRESS addr;
            if (Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestid, addr)) {
                if (addr.isValid())
                    Singleton<DBmgr>::instance()->RecordMatureTime(requestid);
            }

            //HC: 已经成熟且未在进行共识，删除
            itr = _tP2pManagerStatus->mapSearchOnChain.erase(itr);
        } else {
            itr++;
        }
    }
}

void ConsensusEngine::RegisterAppCallback(const T_APPTYPE &app, const CONSENSUSNOTIFY &notify)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        _tP2pManagerStatus->SetAppCallback(app, notify);
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::RegisterAppCallback, &app, &notify);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void ConsensusEngine::UnregisterAppCallback(const T_APPTYPE &app)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        _tP2pManagerStatus->RemoveAppCallback(app);
    } else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)SERVICE::UnregisterAppCallback, &app);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void ConsensusEngine::PutIntoConsensusList(T_BUDDYINFOSTATE &buddyinfostate)
{
    bool index = false;
    list <T_LOCALCONSENSUS> listLocalBlock;        //非本地链中的BLOCK
    //HC: put child blocks into consensus list: listLocalBuddyChainInfo
    ITR_LIST_T_LOCALCONSENSUS itrSub = buddyinfostate.localList.begin();
    for (; itrSub != buddyinfostate.localList.end(); itrSub++) {
        index = JudgExistAtLocalBuddy(_tP2pManagerStatus->listLocalBuddyChainInfo, (*itrSub));
        if (index)
            continue;

        g_consensus_console_logger->info("PutIntoConsensusList: push block into listLocalBuddyChainInfo: {}",
            (*itrSub).GetLocalBlock().GetPayLoadPreview());
        _tP2pManagerStatus->listLocalBuddyChainInfo.push_back((*itrSub));
        _tP2pManagerStatus->listLocalBuddyChainInfo.sort(CmpareOnChain());
        _tP2pManagerStatus->tBuddyInfo.usBlockNum = static_cast<uint16>(_tP2pManagerStatus->listLocalBuddyChainInfo.size());

        listLocalBlock.push_back((*itrSub));
    }

    //只有加入的BLOCK=1，并且本地已经是子链才发送
    if (listLocalBlock.size() == 1 && _tP2pManagerStatus->listLocalBuddyChainInfo.size() > 2) {
        SendCopyLocalBlock(listLocalBlock.front());
    }

    //在最后设置
    buddyinfostate.uibuddyState = CONSENSUS_CONFIRMED;
}

bool ConsensusEngine::MakeBuddy(const string & confirmhash)
{
    bool ismakebuddy = false;
    ITR_LIST_T_BUDDYINFOSTATE itrRsp = _tP2pManagerStatus->listCurBuddyRsp.begin();
    for (; itrRsp != _tP2pManagerStatus->listCurBuddyRsp.end();) {
        if (0 == strncmp((*itrRsp).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN)) {
            (*itrRsp).uibuddyState = CONSENSUS_CONFIRMED;
        } else if ((*itrRsp).GetBuddyState() != CONSENSUS_CONFIRMED) {
            SendRefuseReq((*itrRsp).GetPeerAddrOut()._nodeid,
                string((*itrRsp).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);
            itrRsp = _tP2pManagerStatus->listCurBuddyRsp.erase(itrRsp);
            continue;
        }
        ++itrRsp;
    }

    auto itrReq = _tP2pManagerStatus->listCurBuddyReq.begin();
    for (; itrReq != _tP2pManagerStatus->listCurBuddyReq.end();) {
        if (0 != strncmp((*itrReq).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN)) {
            if ((*itrReq).GetBuddyState() != CONSENSUS_CONFIRMED && (*itrReq).GetBuddyState() != IS_CONFIRM) {
                SendRefuseReq((*itrReq).GetPeerAddrOut()._nodeid,
                    string((*itrReq).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);

                itrReq = _tP2pManagerStatus->listCurBuddyReq.erase(itrReq);
                continue;
            }
        }
        ++itrReq;
    }

    itrReq = _tP2pManagerStatus->listCurBuddyReq.begin();
    for (; itrReq != _tP2pManagerStatus->listCurBuddyReq.end();) {
        if (0 == strncmp((*itrReq).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN)){
            if ((*itrReq).uibuddyState != CONSENSUS_CONFIRMED) {
                PutIntoConsensusList(*itrReq);
                int i = 0;
                for (auto& b : _tP2pManagerStatus->listLocalBuddyChainInfo) {
                    g_consensus_console_logger->info("makeBuddy: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
                }
            }
            ismakebuddy = true;
            break;
        }
        ++itrReq;
    }

    g_consensus_console_logger->info("makeBuddy: listCurBuddyReq size: {} listCurBuddyRsp size: {}, makebuddy:{}",
        _tP2pManagerStatus->listCurBuddyReq.size(),
        _tP2pManagerStatus->listCurBuddyRsp.size(), ismakebuddy);

    if (ismakebuddy) {
        _tP2pManagerStatus->listRecvLocalBuddyRsp.clear();
        _tP2pManagerStatus->listRecvLocalBuddyReq.clear();
    }
    return ismakebuddy;
}

bool  ConsensusEngine::IsConfirming(string &currBuddyHash)
{
    for (auto &buddy : _tP2pManagerStatus->listCurBuddyRsp) {
        if (buddy.GetBuddyState() == SEND_CONFIRM) {
            currBuddyHash = string(buddy.GetBuddyHash(), DEF_STR_HASH256_LEN);
            return true;
        }
    }
    return false;
}

void ConsensusEngine::TryCreateHyperBlock()
{
    if (_tP2pManagerStatus->listGlobalBuddyChainInfo.size() != 0) {
        if (_tP2pManagerStatus->GloblChainsChanged() && IsEndNode()) {
            if (CreateHyperBlock(_tP2pManagerStatus->tHyperBlock)) {
                _tP2pManagerStatus->bHyperBlockCreated = true;
                _tP2pManagerStatus->SetGloblChainsChanged(false);
            }
            else {
                _tP2pManagerStatus->bHyperBlockCreated = false;
            }
        }
    }
}

bool ConsensusEngine::CreateHyperBlock(T_HYPERBLOCK &tHyperBlock)
{
    CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();

    T_HYPERBLOCK preHyperBlock;
    sp->GetLatestHyperBlock(preHyperBlock);

    const T_SHA256& hhash = preHyperBlock.GetHashSelf();

    LIST_LIST_GLOBALBUDDYINFO &listlistGL = _tP2pManagerStatus->listGlobalBuddyChainInfo;
    auto globalconsensusList = listlistGL.begin();

    //Check every chain if hash of previous hyper block is right
    for (; globalconsensusList != listlistGL.end();) {
        auto globalconsensus = globalconsensusList->begin();
        T_LOCALBLOCK& localblock = globalconsensus->GetLocalBlock();
        if (localblock.GetPreHHash() != hhash) {
            //HC: remove the chain
            listlistGL.erase(globalconsensusList++);
            continue;
        }
        ++globalconsensusList;
    }

    if (listlistGL.size() == 0) {
        return false;
    }

    tHyperBlock = T_HYPERBLOCK();
    tHyperBlock.SetID(preHyperBlock.GetID() + 1);
    tHyperBlock.SetPreHash(preHyperBlock.GetHashSelf());
    tHyperBlock.SetCTime(_tP2pManagerStatus->GettTimeOfConsensus());
    tHyperBlock.SetPreHeaderHash(preHyperBlock.calculateHeaderHashSelf());

    uint16 blockNum = 0;
    LIST_T_LOCALBLOCK listLocalBlockInfo;
    list<LIST_T_LOCALBLOCK> listPayLoad;

    g_consensus_console_logger->anyway("Creating/Recreating Hyperblock: {}", tHyperBlock.header.uiID);

    //HC: Not allow two or above ledger/paracoin chains in a hyper block.
    map<T_APPTYPE, char> mapLedgerApp;
    multimap<T_APPTYPE, list<LIST_T_LOCALCONSENSUS>::iterator> appmap;
    auto& globalChain = _tP2pManagerStatus->listGlobalBuddyChainInfo;
    for (auto chain = globalChain.begin(); chain != globalChain.end(); ++chain) {
        T_LOCALBLOCK& block = (*chain).begin()->GetLocalBlock();
        if (block.isAppTxType()) {
            mapLedgerApp[block.GetAppType()] = 0;
            appmap.insert(std::pair<T_APPTYPE, list<LIST_T_LOCALCONSENSUS>::iterator>(block.GetAppType(), chain));
        }
    }

    //HC: let application layer select the best one
    T_SHA256 prevhhash = preHyperBlock.GetHashSelf();
    uint32_t prevhid = preHyperBlock.GetID();
    for (auto app : mapLedgerApp) {
        if (appmap.count(app.first) > 1) {
            for (auto mi = appmap.lower_bound(app.first); mi != appmap.upper_bound(app.first); ) {
                vector<T_PAYLOADADDR> vecPayload;
                for (auto& localconsensus : *mi->second) {
                    vecPayload.emplace_back(T_LOCALBLOCKADDRESS(), localconsensus.GetLocalBlock().GetPayLoad());
                }
                CBRET ret = _tP2pManagerStatus->AppCallback<cbindex::CHECKCHAINIDX>(
                    app.first, vecPayload, prevhid, prevhhash);
                if (ret == CBRET::REGISTERED_FALSE) {
                    globalChain.erase(mi->second);
                    appmap.erase(mi++);
                } else {
                    mi++;
                }
            }
        }
    }

    for (auto app : mapLedgerApp) {
        if (appmap.count(app.first) > 1) {
            auto currMax = appmap.lower_bound(app.first);
            auto mi = currMax;
            mi++;
            for (; mi != appmap.upper_bound(app.first); ++mi) {
                if (mi->second->size() < currMax->second->size()) {
                    globalChain.erase(mi->second);
                } else if (mi->second->size() == currMax->second->size()) {
                    //HC: compare hash, choose the chain whose first block's hash value is less
                    auto hash = mi->second->begin()->GetLocalBlock().GetHashSelf();
                    auto hashcurrMax = currMax->second->begin()->GetLocalBlock().GetHashSelf();
                    if (hash > hashcurrMax) {
                        globalChain.erase(mi->second);
                    } else {
                        globalChain.erase(currMax->second);
                        currMax = mi;
                    }
                } else {
                    globalChain.erase(currMax->second);
                    currMax = mi;
                }
            }
            g_consensus_console_logger->anyway("Removed {} {} chains",
                appmap.count(app.first) - 1, app.first.isLedger() ? "ledger" : "paracoin");
        }
    }

    //HC: sort every child chain
    uint32_t chainnum = 0;
    auto itr = globalChain.begin();
    for (; itr != globalChain.end(); ++itr) {
        chainnum++;
        blockNum = 0;
        T_APPTYPE app;
        auto subItr = (*itr).begin();
        for (; subItr != (*itr).end(); ++subItr) {

            T_SHA256 hhash = subItr->GetLocalBlock().GetPreHHash();
            if (preHyperBlock.GetHashSelf() != hhash) {
                g_consensus_console_logger->warn("Invalid prehyperblock hash, {} payload:{}, skip the whole chain containing the block...",
                    tHyperBlock.GetID(),
                    subItr->tLocalBlock.GetPayLoadPreview());
                listLocalBlockInfo.clear();
                break;
            }
            blockNum += 1;
            g_consensus_console_logger->info("\t {}:{} {} payload:{}", chainnum, blockNum,
                subItr->tLocalBlock.GetAppType().tohexstring(),
                subItr->tLocalBlock.GetPayLoadPreview());

            listLocalBlockInfo.emplace_back((*subItr).tLocalBlock);
            app = subItr->tLocalBlock.GetAppType();
        }

        if (!app.isParacoin() && !app.isLedger() && !app.isEthereum()) {
            listLocalBlockInfo.sort(CmpareOnChainLocal());
        }
        tHyperBlock.AddChildChain(std::move(listLocalBlockInfo));
        listLocalBlockInfo.clear();
    }

    tHyperBlock.Rebuild();

    ostringstream osschildchain;
    auto& chains = tHyperBlock.GetChildChains();
    int nChainID = 1;

    size_t nChainNum = chains.size();
    if (nChainNum <= 0) {
        return false;
    }

    for (size_t num = 0; num < nChainNum; ++num) {
        auto firstblock = chains[num].begin();
        osschildchain << StringFormat("[Chain %d: child blocks %d, type: %s]\n", nChainID++, chains[num].size(),
            firstblock->GetAppType().tohexstring());
        if (num != nChainNum - 1) {
            osschildchain << "\t\t";
        }
    }

    g_consensus_console_logger->anyway("HyperBlock {} created: \n\tChild Chains: {} \tTotal child blocks: {} \n\tHash: {}", tHyperBlock.GetID(),
        osschildchain.str(),
        tHyperBlock.GetChildBlockCount(),
        tHyperBlock.GetHashSelf().toHexString());
    return true;
}

//HC: 计算本节点是否是共识链上最后一个节点如果是则负责创建超块
bool ConsensusEngine::IsEndNode()
{
    bool isEndNodeBuddyChain = false;

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    do {
        if (_tP2pManagerStatus->listLocalBuddyChainInfo.size() <= 1) {
            break;
        }
        LIST_T_LOCALCONSENSUS::iterator itr = _tP2pManagerStatus->listLocalBuddyChainInfo.end();
        itr--;

        if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            isEndNodeBuddyChain = true;
        }
    } while (false);

    //HC: search every chain
    if (!isEndNodeBuddyChain) {
        for (auto& childchain : _tP2pManagerStatus->listGlobalBuddyChainInfo) {
            auto childblock = childchain.end();
            childblock--;
            if ((*childblock).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
                isEndNodeBuddyChain = true;
                break;
            }
        }
    }
    return isEndNodeBuddyChain;
}

bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid)
{
    T_SHA256 preHyperBlockHash;
    uint64 localhyperblockid = 0;
    uint64 ctm;

    CHyperChainSpace *sp = Singleton<CHyperChainSpace, string>::getInstance();
    sp->GetLatestHyperBlockIDAndHash(localhyperblockid, preHyperBlockHash, ctm);

    bool isMatched = true;
    bool isNeedUpdateHyperBlock = false;
    if (localhyperblockid != hyperblockid) {
        g_consensus_console_logger->info("Refuse: local previous HyperBlockID:{}, recv buddy HyperBlockID:{}",
            localhyperblockid, hyperblockid);

        isMatched = false;
        if (localhyperblockid < hyperblockid) {
            isNeedUpdateHyperBlock = true;
        }
    } else if (hash != preHyperBlockHash) {
        g_consensus_console_logger->info("Refuse: local previous HyperBlock Hash:{}, recv hash:{}",
            preHyperBlockHash.toHexString(), hash.toHexString());

        isMatched = false;
        if (hash < preHyperBlockHash) {
            isNeedUpdateHyperBlock = true;
        }
    }

    if (isNeedUpdateHyperBlock) {
        //HC: give me your hyper block
        g_consensus_console_logger->info("Hello friend, give me your HyperBlock:{}", hyperblockid);
        sp->GetRemoteHyperBlockByID(hyperblockid, peerid.ToHexString());
    }
    return isMatched;
}


bool checkAppType(const T_LOCALBLOCK& localblock, const T_LOCALBLOCK& buddyblock)
{
    T_APPTYPE localapptype = localblock.GetAppType();
    if (localblock.isAppTxType() || buddyblock.isAppTxType()) {
        if (localblock.GetAppType() != buddyblock.GetAppType()) {
            return false;
        }
    }
    return true;
}

bool ConsensusEngine::CheckPayload(LIST_T_LOCALCONSENSUS& localList)
{
    //HC:notify application layer to validate the payload data
    auto itrblock = localList.begin();

    uint16 i = 0;
    map<boost::any, T_LOCALBLOCKADDRESS> outpt;
    boost::any hashPrev;

    for (; itrblock != localList.end();) {

        T_LOCALBLOCK& block = itrblock->GetLocalBlock();
        T_LOCALBLOCKADDRESS addr;
        addr.set(block.GetHID(), 1, i + 1);
        T_PAYLOADADDR payloadaddr(addr, block.GetPayLoad());

        CBRET ret = _tP2pManagerStatus->AppCallback<cbindex::VALIDATEFNIDX>(block.GetAppType(), payloadaddr, outpt, hashPrev);
        if (ret == CBRET::REGISTERED_FALSE) {
            g_consensus_console_logger->warn("checkPayload() : invalid buddy data,removed");
            localList.erase(itrblock++);
            continue;
        }

        if (block.GetAppType().isSmartContractWithResult()) {
            qjs::VM vm;
            string result, strlog;
            string excp_desc;
            if (vm.execute(block.GetScript(), result, excp_desc)) {
                if (result != block.GetPayLoad()) {
                    strlog = "payload != script executed result";
                    g_consensus_console_logger->warn("checkPayload() : invalid SmartContract data,removed for {}", strlog.c_str());
                    localList.erase(itrblock++);
                    continue;
                }
            } else {
                strlog = StringFormat("execute error, %s", excp_desc);
                g_consensus_console_logger->warn("checkPayload() : cannot check correctly SmartContract data, {}", strlog.c_str());
            }
        }

        i++;
        itrblock++;
    }

    //HC: At least 2 blocks for buddy
    if (localList.size() < 2) {
        return false;
    }
    return true;
}
