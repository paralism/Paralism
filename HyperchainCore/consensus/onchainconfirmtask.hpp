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


#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "../consensus/consensus_engine.h"
#include "buddyinfo.h"
#include "headers/lambda.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include <iostream>
using namespace std;

extern void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);

extern void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock);


class OnChainConfirmRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM_RSP> {
public:
    using ITask::ITask;

    OnChainConfirmRspTask(const CUInt128 &peerid, uint64 uiHyperBlockNum, const string & hash) :
        _peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum), _hash(hash) {}

    ~OnChainConfirmRspTask() {};

    void exec() override
    {
        g_consensus_console_logger->info("Send OnChainConfirmRspTask to {}\n", _peerid.ToHexString().c_str());

        //HCE: Run to here, buddy is formed
        T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRsp = nullptr;

        int ipP2pProtocolOnChainConfirmRspLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRMRSP);

        DataBuffer<OnChainConfirmRspTask> msgbuf(ipP2pProtocolOnChainConfirmRspLen);
        pP2pProtocolOnChainConfirmRsp = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRMRSP>(msgbuf.payload());
        pP2pProtocolOnChainConfirmRsp->uiHyperBlockNum = _uiHyperBlockNum;
        pP2pProtocolOnChainConfirmRsp->SetInitHash(0);
        pP2pProtocolOnChainConfirmRsp->SetP2pprotocolonchainconfirmrsp(
            T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM_RSP, CCommonStruct::gettimeofday_update()), P2P_PROTOCOL_SUCCESS),
            const_cast<char*>(_hash.c_str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        nodemgr->sendTo(_peerid, msgbuf);

    }

    void execRespond() override
    {
        g_consensus_console_logger->info("Received OnChainConfirmRspTask from {}", _sentnodeid.ToHexString());
        T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRspRecv = (T_PP2PPROTOCOLONCHAINCONFIRMRSP)(_payload);

        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        auto itrReq = pConsensusStatus->listCurBuddyReq.begin();
        for (; itrReq != pConsensusStatus->listCurBuddyReq.end();) {
            if (0 == strncmp((*itrReq).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->strHash, DEF_STR_HASH256_LEN)) {
                itrReq->uibuddyState = CONSENSUS_CONFIRMED;
            }
            else if (itrReq->GetBuddyState() != CONSENSUS_CONFIRMED && itrReq->GetBuddyState() != IS_CONFIRM) {
                SendRefuseReq((*itrReq).GetPeerAddrOut()._nodeid,
                    string((*itrReq).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);
                itrReq = pConsensusStatus->listCurBuddyReq.erase(itrReq);
                continue;
            }
            ++itrReq;
        }

        auto itrRsp = pConsensusStatus->listCurBuddyRsp.begin();
        for (; itrRsp != pConsensusStatus->listCurBuddyRsp.end();) {
            if (0 != strncmp((*itrRsp).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->GetHash(), DEF_STR_HASH256_LEN)) {
                if ((*itrRsp).GetBuddyState() != CONSENSUS_CONFIRMED) {
                    SendRefuseReq((*itrRsp).GetPeerAddrOut()._nodeid,
                        string((*itrRsp).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);

                    itrRsp = pConsensusStatus->listCurBuddyRsp.erase(itrRsp);
                    continue;
                }
            }
            ++itrRsp;
        }

        itrRsp = pConsensusStatus->listCurBuddyRsp.begin();
        for (; itrRsp != pConsensusStatus->listCurBuddyRsp.end();) {
            if (0 == strncmp((*itrRsp).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->GetHash(), DEF_STR_HASH256_LEN) &&
                (*itrRsp).GetBuddyState() == SEND_CONFIRM) {
                pEng->PutIntoConsensusList(*itrRsp);
                int i = 0;
                for (auto& b : pConsensusStatus->listLocalBuddyChainInfo) {
                    g_consensus_console_logger->info("OnChainConfirmRspTask: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
                }
                break;
            }
            ++itrRsp;
        }

        g_consensus_console_logger->info("OnChainConfirmRspTask: listCurBuddyReq size: {} listCurBuddyRsp size: {}",
            pConsensusStatus->listCurBuddyReq.size(),
            pConsensusStatus->listCurBuddyRsp.size());

        pConsensusStatus->listRecvLocalBuddyRsp.clear();

        pConsensusStatus->listRecvLocalBuddyReq.clear();
    }

private:
    CUInt128 _peerid;
    uint64_t _uiHyperBlockNum;
    string _hash;
};

class OnChainConfirmTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM> {
public:
    using ITask::ITask;

    OnChainConfirmTask(const CUInt128 &peerid, uint64 uiHyperBlockNum, string hash, uint8 state) :
        _peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum), _hash(hash), _state(state) {}

    ~OnChainConfirmTask() {};
    void exec() override
    {
        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        if (pEng->IsMakeBuddy()) {
            g_consensus_console_logger->info("OnChainConfirmTask: the node is making buddy!");
            return;
        }

        bool isFind = false;
        for (auto &chain : pConsensusStatus->listCurBuddyRsp) {
            if (0 == strncmp(chain.GetBuddyHash(), _hash.c_str(), DEF_STR_HASH256_LEN)) {
                chain.SetBuddyState(SEND_CONFIRM);
                g_consensus_console_logger->info("OnChainConfirmTask: set buddy state SEND_CONFIRM");
                isFind = true;
                break;
            }
        }
        if (!isFind) {
            return;
        }

        char logmsg[128] = { 0 };
        snprintf(logmsg, 128, "Send OnChainConfirmTask to peer:%s\n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirm = nullptr;

        int ipP2pProtocolOnChainConfirmLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRM);

        DataBuffer<OnChainConfirmTask> msgbuf(ipP2pProtocolOnChainConfirmLen);
        pP2pProtocolOnChainConfirm = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRM>(msgbuf.payload());
        pP2pProtocolOnChainConfirm->SetInitHash(0);
        pP2pProtocolOnChainConfirm->uiHyperBlockNum = _uiHyperBlockNum;
        pP2pProtocolOnChainConfirm->SetP2pprotocolonchainconfirm(
            T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM, CCommonStruct::gettimeofday_update()), _state),
            const_cast<char*> (_hash.c_str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);

    }

    void execRespond() override
    {
        T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirmRecv = (T_PP2PPROTOCOLONCHAINCONFIRM)(_payload);

        g_consensus_console_logger->info("Received confirm from {}", _sentnodeid.ToHexString());
        string confirmbuddyhash = string(pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN);

        string currBuddyHash;
        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        bool isconfirming = pEng->IsConfirming(currBuddyHash);

        auto itr = pConsensusStatus->listCurBuddyReq.begin();
        for (; itr != pConsensusStatus->listCurBuddyReq.end(); itr++) {
            if (0 == strncmp(itr->strBuddyHash,
                pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN)) {
                break;
            }
        }

        //HC: listCurBuddyReq中找到该BUUDY
        if (itr != pConsensusStatus->listCurBuddyReq.end()) {
            if (!isconfirming || currBuddyHash == confirmbuddyhash) {
                itr->SetBuddyState(IS_CONFIRM);

                //HC: 我没和任何节点在进行buddy确认，所以可以结成buddy
                //HC: 或者我正和一个节点在进行buddy确认，但是正好就是同一个节点，所以可以结成buddy
                //HCE: I have never make buddy with any nodes, so I can make buddy with the node.
                //HCE: or I am making buddy with a node, but it's just the same node, so I can make buddy with this node
                g_consensus_console_logger->info("confirm from {}: will makebuddy, isconfirming:{}", _sentnodeid.ToHexString(), isconfirming);

                if (pEng->MakeBuddy(confirmbuddyhash)) {
                    //HC: 结BUDDY成功
                    //HCE: success to make buddy
                    SendConfirmRsp(confirmbuddyhash, pP2pProtocolOnChainConfirmRecv->uiHyperBlockNum);
                    return;
                }

                //HC: 结BUDDY失败，删除该BUDDY
                //HCE: failed to make buddy, delete this buddy
                if (currBuddyHash == confirmbuddyhash) {
                    auto itrRsp = pConsensusStatus->listCurBuddyRsp.begin();
                    for (; itrRsp != pConsensusStatus->listCurBuddyRsp.end(); itrRsp++) {
                        if (itrRsp->GetBuddyState() == SEND_CONFIRM) {
                            pConsensusStatus->listCurBuddyRsp.erase(itrRsp++);
                            break;
                        }
                    }
                }
            }
        }

        //HC: 没找到，或者结BUDDY失败
        //HCE: don't find the buddy, or failed to make buddy
        g_consensus_console_logger->info("Confirm refused: make buddy failed, buddy hash from {} ",
            _sentnodeid.ToHexString().c_str());
        SendRefuseReq(_sentnodeid, confirmbuddyhash, RECV_RSP);

    }

    void SendConfirmRsp(string hash, uint64_t uiHyperBlockNum)
    {
        OnChainConfirmRspTask tsk(_sentnodeid, uiHyperBlockNum, hash);
        tsk.exec();

    }
    void SendWaitRsp(string hash)
    {
        OnChainWaitTask tsk(_sentnodeid, hash);
        tsk.exec();
    }

private:
    CUInt128 _peerid;
    uint64_t _uiHyperBlockNum;
    string _hash;
    int _state;
};

//HCE: Copy local block to peer
class CopyBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::COPY_BLOCK> {
public:
    using ITask::ITask;

    CopyBlockTask(const T_LOCALCONSENSUS &localBlock) : _localBlock(localBlock) {}

    ~CopyBlockTask() {};

    void exec() override
    {
        g_consensus_console_logger->info("Send CopyBlockLocalTask: {}",
            _localBlock.GetLocalBlock().GetPayLoadPreview());

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        size_t nodeSize = pConsensusStatus->listLocalBuddyChainInfo.size();
        string strUUID = _localBlock.GetLocalBlock().GetUUID();

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        HCNodeSH me = nodemgr->myself();

        uint16 num = 0;
        list<CUInt128> listNodeID;      //HC: 要发送的节点
                                        //HCE: list of the nodes to send
        ITR_LIST_T_LOCALCONSENSUS itr = pConsensusStatus->listLocalBuddyChainInfo.begin();
        for (; itr != pConsensusStatus->listLocalBuddyChainInfo.end(); itr++) {
            if ((*itr).tLocalBlock.GetUUID() == strUUID) {
                continue;
            }
            num++;

            if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
                continue;
            }
            listNodeID.push_back(itr->GetPeer().GetPeerAddr()._nodeid);
        }

        //HC: 没有要发送的节点
        //HCE: no nodes to send
        if (listNodeID.empty())
            return;

        T_P2PPROTOCOLCOPYBLOCKREQ P2pProtocolCopyBlockReq;
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        try {
            P2pProtocolCopyBlockReq.SetType(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_COPY_BLOCK_REQ, CCommonStruct::gettimeofday_update()));
            P2pProtocolCopyBlockReq.uiBuddyNum = num;

            oa << P2pProtocolCopyBlockReq;

            T_LOCALCONSENSUS localconsensus;
            localconsensus.SetLocalBlock(_localBlock.GetLocalBlock());
            localconsensus.SetPeer(_localBlock.GetPeer());

            oa << localconsensus;

            //HC: 增加共识周期校验
            //HCE: add verify to consensus circle 
            oa << ConsensusEngine::GetConsensusCircle();

            //HC: 必须重新遍历序列化，两段序列化的数据不能拼接
            //HCE: must be serialized.Two serialized data cannot be put together
            for (auto& b : pConsensusStatus->listLocalBuddyChainInfo) {
                if ((b.GetLocalBlock().GetUUID() == strUUID)) {
                    continue;
                }
                string uuid = b.GetLocalBlock().GetUUID();
                uint32 uuidSize = static_cast<uint32>(uuid.size());
                oa << uuidSize;
                oa << boost::serialization::make_binary_object(uuid.data(), uuidSize);
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<CopyBlockTask> msgbuf(std::move(ssBuf.str()));

        for (auto& sendnodeid : listNodeID) {
            g_consensus_console_logger->info("Send {} blocks hash and CopyBlockLocalTask to {}",
                P2pProtocolCopyBlockReq.uiBuddyNum,
                sendnodeid.ToHexString());
            nodemgr->sendTo(sendnodeid, msgbuf);
        }
    }

    void execRespond() override
    {
        g_consensus_console_logger->trace("Received CopyBlockTask");

        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

        T_P2PPROTOCOLCOPYBLOCKREQ P2pProtocolCopyBlockReqRecv;
        T_LOCALCONSENSUS  LocalBlockTemp;
        int64 nCircle;
        try {
            ia >> P2pProtocolCopyBlockReqRecv;
            ia >> LocalBlockTemp;
            ia >> nCircle;
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        if (nCircle != ConsensusEngine::GetConsensusCircle()) {
            g_console_logger->error("Skip Consensus circle!", __FUNCTION__);
            return;
        }

        ITR_LIST_T_LOCALCONSENSUS itrList = pConsensusStatus->listLocalBuddyChainInfo.begin();
        for (; itrList != pConsensusStatus->listLocalBuddyChainInfo.end(); itrList++) {
            if ((*itrList).GetPeer().GetPeerAddr() == LocalBlockTemp.GetPeer().GetPeerAddr()) {
                return;
            }
        }

        uint16 num = 0;
        string uuidRecv;
        for (uint16 i = 0; i < P2pProtocolCopyBlockReqRecv.uiBuddyNum; i++) {
            try {
                uint32 uuidSize = 0;
                ia >> uuidSize;
                uuidRecv.resize(uuidSize);
                ia >> boost::serialization::make_binary_object(const_cast<char*>(uuidRecv.data()), uuidSize);
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
                return;
            }

            for (auto &b : pConsensusStatus->listLocalBuddyChainInfo) {
                if (uuidRecv == b.GetLocalBlock().GetUUID()) {
                    num++;
                    break;
                }
            }
        }
        g_consensus_console_logger->info("CopyBlockTask: recv {} copy block data,{} block is same.",
            P2pProtocolCopyBlockReqRecv.uiBuddyNum, num);
        //HCE: At lease the same block number is 2.
        if (num < 2) {
            g_consensus_console_logger->warn("CopyBlockTask: cannot accept the copy data,maybe I have entered next phase.");
            return;
        }
        g_consensus_console_logger->trace("CopyBlockTask: push block into listLocalBuddyChainInfo,payload:{}",
            LocalBlockTemp.GetLocalBlock().GetPayLoadPreview());
        pConsensusStatus->listLocalBuddyChainInfo.push_back(LocalBlockTemp);
        pConsensusStatus->listLocalBuddyChainInfo.sort(CmpareOnChain());
        pConsensusStatus->tBuddyInfo.usBlockNum = static_cast<uint16>(pConsensusStatus->listLocalBuddyChainInfo.size());
    }

private:
    T_LOCALCONSENSUS _localBlock;
};
