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

#include <iostream>
using namespace std;

#include "headers/lambda.h"
#include "../crypto/sha2.h"
#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../db/dbmgr.h"
#include "../node/NodeManager.h"
#include "consensus_engine.h"
#include "buddyinfo.h"
#include "../HyperChain/HyperChainSpace.h"

#include <boost/any.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
extern void copyLocalBuddyList(LIST_T_LOCALCONSENSUS& endList, const LIST_T_LOCALCONSENSUS& fromList);
extern void SendConfirmReq(const CUInt128& peerid, uint64 hyperblocknum, const string& hash, uint8 type);
extern bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256& hash, const CUInt128& peerid);
extern bool checkAppType(const T_LOCALBLOCK& localblock, const T_LOCALBLOCK& buddyblock);

//HCE: Resolve the local buddy info
//HCE: @para nodeid Node ID
//HCE: @para pProtocolHeader Pointer to T_P2PPROTOCOLONCHAINREQ
//HCE: @para plistTotalHash Pointer to list of hash of the local buddy
//HCE: @para plistLackHash Pointer to list of hash whose coresponding block data is lack.
//HCE: @returns True if success
bool ResolveLocalBuddyInfo(const CUInt128& nodeid, T_P2PPROTOCOLONCHAINREQ* pProtocolHeader, list<T_SHA256>* plistTotalHash, list<T_SHA256>* plistLackHash) {
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    T_P2PPROTOCOLONCHAINREQ protocolHeader;
    auto buddyItr = pConsensusStatus->mapLocalBuddyInfo.find(nodeid);
    if (buddyItr != pConsensusStatus->mapLocalBuddyInfo.end()) {
        stringstream mapbuf(buddyItr->second.GetBuffer());
        boost::archive::binary_iarchive mapss(mapbuf, boost::archive::archive_flags::no_header);
        try {
            mapss >> protocolHeader;
            *pProtocolHeader = protocolHeader;

            int64 nBlocknum = protocolHeader.GetBlockCount();
            T_SHA256 BlockHash;
            for (int i = 0; i < nBlocknum; i++) {
                mapss >> BlockHash;
                plistTotalHash->emplace_back(BlockHash);

                auto r = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                if (r == pConsensusStatus->mapLocalConsensus.end())
                    plistLackHash->emplace_back(BlockHash);
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("ResolveLocalProtocolHeader:{} {}", __FUNCTION__, e.what());
            return false;
        }
        return true;
    }
    return false;
}

//HC:插入到listRecvLocalBuddyReq队列中
//HCE: Insert local buddy into listRecvLocalBuddyReq
//HCE: @para nodeid Node ID
//HCE: @para ProtocolHeader T_P2PPROTOCOLONCHAINREQ data
//HCE: @para listTotalHash list of hash of the local buddy
//HCE: @returns True if success
bool InsertIntoListRecv(const CUInt128& nodeid, T_P2PPROTOCOLONCHAINREQ& ProtocolHeader, list<T_SHA256>& listTotalHash)
{
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    stringstream outBuf;
    boost::archive::binary_oarchive oa(outBuf, boost::archive::archive_flags::no_header);
    try {
        oa << ProtocolHeader;
        for (auto& hash : listTotalHash) {
            auto r = pConsensusStatus->mapLocalConsensus.find(hash);
            if (r != pConsensusStatus->mapLocalConsensus.end())
                oa << r->second;
            else {
                g_consensus_console_logger->warn("Warning! InsertIntoListRecv: sleep over 2 circle");
                return false;
            }
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return false;
    }

    T_BUDDYINFO localBuddyInfo;
    T_PEERADDRESS peerAddrOut(nodeid);
    localBuddyInfo.Set(RECV_REQ, outBuf.str().size(), outBuf.str().c_str(), peerAddrOut);


    bool index = false;
    LIST_T_BUDDYINFO::iterator itr = pConsensusStatus->listRecvLocalBuddyReq.begin();
    for (; itr != pConsensusStatus->listRecvLocalBuddyReq.end(); itr++) {
        stringstream ssTemp(itr->GetBuffer());
        boost::archive::binary_iarchive iaTemp(ssTemp, boost::archive::archive_flags::no_header);
        T_P2PPROTOCOLONCHAINREQ currReq;
        try {
            iaTemp >> currReq;
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return false;
        }
        if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
            if (ProtocolHeader.tType.GetTimeStamp() <= currReq.tType.GetTimeStamp()) {
                index = true;
            }
            else {
                //HC:删除老数据
                //HCE: delete old data
                itr = pConsensusStatus->listRecvLocalBuddyReq.erase(itr);
            }
            break;
        }
    }

    if (!index) {
        //HC: 插入到listRecvLocalBuddyReq中
        //HCE: insert the local buddy into listRecvLocalBuddyReq
        pConsensusStatus->listRecvLocalBuddyReq.emplace_back(localBuddyInfo);
        return true;
    }

    return false;

}

class OnChainBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_BLOCK> {
public:
    using ITask::ITask;

    OnChainBlockTask(CUInt128 peerid,const list< T_LOCALCONSENSUS >& listconsensus) :
        _peerid(peerid),_listconsensus(listconsensus) {};
    ~OnChainBlockTask() {};
    void exec() override
    {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            int32 nBlockNum = _listconsensus.size();
            oa << nBlockNum;
            for (auto& r : _listconsensus)
                oa << r;
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<OnChainBlockTask> msgbuf(std::move(ssBuf.str()));

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        //HC:接收块数据信息，并插入到mapLocalConsensus中
        //HCE: receive block data and insert it into mapLocalConsensus
        stringstream ssBuf(string(_payload, _payloadlen));
        boost::archive::binary_iarchive ss(ssBuf, boost::archive::archive_flags::no_header);
        try {
            int32 nBlocknum;
            T_LOCALCONSENSUS consensusinfo;
            ss >> nBlocknum;
            for (int i = 0; i < nBlocknum; i++) {
                ss >> consensusinfo;
                T_SHA256 BlockHash = consensusinfo.GetLocalBlock().GetHashSelf();
                auto finditr = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                if( finditr == pConsensusStatus->mapLocalConsensus.end() )
                    pConsensusStatus->mapLocalConsensus[BlockHash] = consensusinfo;
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        //HC:插入到listRecvLocalBuddyReq队列中
        //HCE: insert into listRecvLocalBuddyReq
        list< T_SHA256> listTotalHash;
        list< T_SHA256> listLackHash;
        T_P2PPROTOCOLONCHAINREQ protocolHeader;
        if (ResolveLocalBuddyInfo(_sentnodeid, &protocolHeader, &listTotalHash, &listLackHash)) {
            if (listLackHash.size() == 0) {
                //HC:不缺少块数据，插入到listRecvLocalBuddyReq中
                //HCE: be not lack of block data,and insert the buddy into listRecvLocalBuddyReq
                if (InsertIntoListRecv(_sentnodeid, protocolHeader, listTotalHash))
                    pConsensusStatus->mapLocalBuddyInfo.erase(_sentnodeid);
            }
        }
    }
private:
    list< T_LOCALCONSENSUS > _listconsensus;
    CUInt128 _peerid;
};

class OnChainHashRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_HASH_RSP> {
public:
    using ITask::ITask;

    OnChainHashRspTask(CUInt128 peerid, const list< T_SHA256>& blockhashlist) :
        _peerid(peerid),_blockhashlist(blockhashlist){};

    ~OnChainHashRspTask() {};
    void exec() override
    {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            uint64 nHashNum = _blockhashlist.size();
            oa << nHashNum;
            for (auto& r: _blockhashlist)
                oa << r;
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }
        
        DataBuffer<OnChainHashRspTask> msgbuf(std::move(ssBuf.str()));

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        list< T_LOCALCONSENSUS > ListConsensus;
        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        //HC:根据块HASH值，找到块数据
        stringstream ssBuf(string(_payload,_payloadlen));
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        try {
            uint64 nBlocknum;
            T_SHA256 BlockHash;
            ia >> nBlocknum;
            for (int i = 0; i < nBlocknum; i++) {
                ia >> BlockHash;
                auto r = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                if (r != pConsensusStatus->mapLocalConsensus.end())
                    ListConsensus.emplace_back(r->second);
                else {
                    g_consensus_console_logger->warn("Warning: OnChainHashRspTask execRespond: sleep over 2 circle!");
                    return;
                }
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        //HC:将块数据信息回复对方
        //HCE: send the block data back to requester
        OnChainBlockTask task(_sentnodeid,ListConsensus);
        task.exec();
    }
private:
    CUInt128 _peerid;
    list< T_SHA256> _blockhashlist;

};

class OnChainHashTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_HASH> {
public:
    using ITask::ITask;

    ~OnChainHashTask() {};
    void exec() override
    {
        //HCE: Update local block's hyper block information
        //HCE: Notice: MuxlistLocalBuddyChainInfo m_MuxHchainBlockList dead lock
        T_SHA256 preHyperBlockHash;
        uint64 prehyperblockid = 0;
        uint64 ctm;

        CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->GetLatestHyperBlockIDAndHash(prehyperblockid, preHyperBlockHash, ctm);

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        size_t blockNum = pConsensusStatus->listLocalBuddyChainInfo.size();
        if (blockNum < ONE_LOCAL_BLOCK) {
            return;
        }

        pConsensusStatus->UpdateLocalBuddyBlockToLatest(prehyperblockid, preHyperBlockHash);

        T_SHA256 tPreHyperBlockHash;
        uint64 hyperblockid = 0;

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        HCNodeSH me = nodemgr->myself();

        bool bhave = false;
        for (auto& localblock : pConsensusStatus->listLocalBuddyChainInfo) {
            if (localblock.GetPeer().GetPeerAddr().GetNodeid() == me->getNodeId<CUInt128>()) {
                tPreHyperBlockHash = localblock.GetLocalBlock().GetPreHHash();
                hyperblockid = localblock.GetLocalBlock().GetPreHID();
                bhave = true;
                break;
            }
        }

        if (!bhave) {
            return;
        }

        //HCE: put previous hyper block hash and id into protocol head
        T_P2PPROTOCOLONCHAINREQ P2pProtocolOnChainReq;
        P2pProtocolOnChainReq.SetP2pprotocolonchainreq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_REQ, CCommonStruct::gettimeofday_update()),
            hyperblockid, tPreHyperBlockHash, blockNum);

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        uint64 i = blockNum;
        try {
            oa << P2pProtocolOnChainReq;
            for (auto& localblock : pConsensusStatus->listLocalBuddyChainInfo) {
                T_LOCALCONSENSUS blockinfos;
                blockinfos.SetLoaclConsensus(localblock.GetPeer(), localblock.GetLocalBlock());
                T_SHA256 BlockHash = blockinfos.GetLocalBlock().GetHashSelf();
                //HC:将子块信息插入到mapLocalConsensus中
                //HCE: insert block data into mapLocalConsensus
                auto finditr = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                if (finditr == pConsensusStatus->mapLocalConsensus.end())
                    pConsensusStatus->mapLocalConsensus[BlockHash] = blockinfos;

                oa << BlockHash;
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        g_consensus_console_logger->info("Broadcast OnChainHashTask...block number:{} prehyperblockid:{}", i,
            prehyperblockid);

        DataBuffer<OnChainHashTask> msgbuf(std::move(ssBuf.str()));

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), string("ALL"));

        g_consensus_console_logger->info("Broadcast OnChainTask...block number:{} prehyperblockid:{}", i,
            P2pProtocolOnChainReq.GetHyperBlockID());
        nodemgr->sendToAllNodes(msgbuf);

    }

    void execRespond() override
    {
        //HCE:If there is a onchain request, continue; otherwise return;
        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        HCNodeSH me = nodemgr->myself();

        //HC:检查结成BUDDY的条件，有则继续
        //HCE: Check the condition to make buddy,continue if ok
        int nLocalChainSize = pConsensusStatus->listLocalBuddyChainInfo.size();
        if (nLocalChainSize > 0) {
            T_PEERADDRESS peerAddrOut(_sentnodeid);
            T_BUDDYINFO buddyinfo;
            buddyinfo.Set(RECV_REQ, _payloadlen, _payload, peerAddrOut);
            pConsensusStatus->mapLocalBuddyInfo[_sentnodeid] = buddyinfo;

            list< T_SHA256> listTotalHash;
            list< T_SHA256> listLackHash;
            T_P2PPROTOCOLONCHAINREQ protocolHeader;
            if (ResolveLocalBuddyInfo(_sentnodeid, &protocolHeader, &listTotalHash, &listLackHash)) {
                //HC:每一次只增加一个block
                //HCE: Add one block each time
                if ((nLocalChainSize == ONE_LOCAL_BLOCK) || (listTotalHash.size() == ONE_LOCAL_BLOCK)) {
                    if (listLackHash.size() > 0) {
                        //HC:缺少块数据，将缺少的块HASH发送给对方
                        //HCE: be lack of block data,send the hash of the block to the requester
                        OnChainHashRspTask task(_sentnodeid, listLackHash);
                        task.exec();
                    }
                    else {
                        //HC:不缺少块数据，插入到listRecvLocalBuddyReq中
                        //HCE: be not lack of block data,insert the buddy into listRecvLocalBuddyReq
                        InsertIntoListRecv(_sentnodeid, protocolHeader, listTotalHash);
                    }
                }
            }
        }
    }
};


class OnChainRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_RSP> {
public:
    using ITask::ITask;
    OnChainRspTask(const CUInt128& peerid, string&& pBuf, size_t uiBufLen) :
        _peerid(peerid), _pBuf(std::forward<string>(pBuf)), _uiBufLen(uiBufLen) {}
    ~OnChainRspTask() {};

    void exec() override
    {
        g_consensus_console_logger->trace("enter OnChainRspTask: {}", _peerid.ToHexString());

        //HCE: Set buddy block hyper block information to latest.
        //HCE: Notice: MuxlistLocalBuddyChainInfo m_MuxHchainBlockList dead lock
        T_SHA256 preHyperBlockHash;
        uint64 prehyperblockid = 0;
        uint64 ctm;
        CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->GetLatestHyperBlockIDAndHash(prehyperblockid, preHyperBlockHash, ctm);

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        //HCE: Have I local blocks to consensus?
        size_t consensusblks = pConsensusStatus->listLocalBuddyChainInfo.size();
        if (consensusblks == 0) {
            g_consensus_console_logger->trace("OnChainRspTask: my consensus block size is 0 ");
            return;
        }

        stringstream ssBufIn(_pBuf);
        boost::archive::binary_iarchive ia(ssBufIn, boost::archive::archive_flags::no_header);

        T_P2PPROTOCOLONCHAINREQ P2pProtocolOnChainReqRecv;
        try {
            ia >> P2pProtocolOnChainReqRecv;
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        if (!isHyperBlockMatched(P2pProtocolOnChainReqRecv.GetHyperBlockID(), P2pProtocolOnChainReqRecv.tHyperBlockHash, _peerid)) {
            g_consensus_console_logger->warn("OnChainRspTask: PreHyperBlock isn't matched. recv:{} local:{} from: {}",
                P2pProtocolOnChainReqRecv.GetHyperBlockID(),
                sp->GetMaxBlockID(), _peerid.ToHexString());
            return;
        }

        bool index = false;

        //HCE: Get size of blocks doing consensus again because MQ handle switches
        consensusblks = pConsensusStatus->listLocalBuddyChainInfo.size();
        if (consensusblks == 0) {
            g_consensus_console_logger->trace("OnChainRspTask: my consensus block size is 0 ");
            return;
        }

        if (consensusblks != ONE_LOCAL_BLOCK && P2pProtocolOnChainReqRecv.GetBlockCount() != ONE_LOCAL_BLOCK) {
            g_consensus_console_logger->trace("OnChainRspTask: cannot make buddy, my consensus block size:{}, recv block: {}",
                consensusblks, P2pProtocolOnChainReqRecv.GetBlockCount());
            return;
        }

        //HCE: Set buddy block hyper block information to latest.
        pConsensusStatus->UpdateLocalBuddyBlockToLatest(prehyperblockid, preHyperBlockHash);

        T_BUDDYINFOSTATE buddyInfo;
        copyLocalBuddyList(buddyInfo.localList, pConsensusStatus->listLocalBuddyChainInfo);

        auto firstelm = buddyInfo.localList.begin();
        //HC: 组合形成备选链
        //HCE: compined to waiting buddy
        for (uint64 i = 0; i < P2pProtocolOnChainReqRecv.GetBlockCount(); i++) {
            T_LOCALCONSENSUS  LocalBlockInfo;
            try {
                ia >> LocalBlockInfo;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
                return;
            }

            T_LOCALBLOCK& block = LocalBlockInfo.GetLocalBlock();
            if (!checkAppType(firstelm->GetLocalBlock(), block)) {
                g_consensus_console_logger->info("Different application type,cannot make buddy");
                return;
            }

            index = JudgExistAtLocalBuddy(buddyInfo.localList, LocalBlockInfo);
            if (index)
                continue;
            //HC: 加入本地待上链数据块，形成备选链
            //HCE: add the local block and compined to the backup buddy
            buddyInfo.localList.push_back(LocalBlockInfo);
            //HC: 排序组合成链
            //HCE: sort
            buddyInfo.localList.sort(CmpareOnChain());
        }

        if (!pEng->CheckPayload(buddyInfo.localList)) {
            return;
        }

        stringstream ssList;
        boost::archive::binary_oarchive oaList(ssList, boost::archive::archive_flags::no_header);

        try {
            ITR_LIST_T_LOCALCONSENSUS itrTemp = buddyInfo.localList.begin();
            for (; itrTemp != buddyInfo.localList.end(); itrTemp++) {
                oaList << (*itrTemp);
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        buddyInfo.SetPeerAddrOut(T_PEERADDRESS(_peerid));
        //HC: 设置备选链状态
        //HCE: set the backup buddy state to SEND_ON_CHAIN_RSP
        buddyInfo.SetBuddyState(SEND_ON_CHAIN_RSP);


        T_SHA256 tempHash(0);
        GetSHA256(tempHash.data(), ssList.str().data(), ssList.str().size());

        int8 strLocalHashTemp[DEF_STR_HASH256_LEN + 1] = { 0 };
        CCommonStruct::Hash256ToStr(strLocalHashTemp, tempHash);

        buddyInfo.SetBuddyHashInit(0);
        buddyInfo.SetBuddyHash(strLocalHashTemp);

        ITR_LIST_T_BUDDYINFOSTATE itrReq = pConsensusStatus->listCurBuddyReq.begin();
        for (; itrReq != pConsensusStatus->listCurBuddyReq.end(); itrReq++) {
            if (0 == memcmp((*itrReq).GetBuddyHash(), buddyInfo.GetBuddyHash(), DEF_STR_HASH256_LEN)) {
                return;
            }
        }
        //HC: 将备选链放入备选链集合中
        //HCE: put the backup buddy into listCurBuddyReq
        pConsensusStatus->listCurBuddyReq.push_back(buddyInfo);

        size_t blockNum = buddyInfo.localList.size();

        T_SHA256 tPreHyperBlockHash;
        uint64 hyperblockid = 0;

        sp->GetLatestHyperBlockIDAndHash(hyperblockid, tPreHyperBlockHash, ctm);

        T_P2PPROTOCOLONCHAINRSP P2pProtocolOnChainRsp;
        P2pProtocolOnChainRsp.SetP2pprotocolonchainrsp(T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_RSP, CCommonStruct::gettimeofday_update()), P2P_PROTOCOL_SUCCESS),
            hyperblockid, blockNum, strLocalHashTemp);
        P2pProtocolOnChainRsp.tHyperBlockHash = tPreHyperBlockHash;

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            oa << P2pProtocolOnChainRsp;

            ITR_LIST_T_LOCALCONSENSUS itrTemp = buddyInfo.localList.begin();
            for (; itrTemp != buddyInfo.localList.end(); itrTemp++) {
                oa << (*itrTemp);
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<OnChainRspTask> msgbuf(std::move(ssBuf.str()));

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        g_consensus_console_logger->info("Send out OnChainRspTask");
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        g_consensus_console_logger->info("Received OnChainRspTask");
        T_BUDDYINFO localBuddyInfo;

        T_PEERADDRESS peerAddrOut(_sentnodeid);
        localBuddyInfo.Set(RECV_RSP, _payloadlen, _payload, peerAddrOut);

        bool index = false;

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        LIST_T_BUDDYINFO::iterator itr = pConsensusStatus->listRecvLocalBuddyRsp.begin();
        for (; itr != pConsensusStatus->listRecvLocalBuddyRsp.end(); itr++) {
            if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
                index = true;
                break;
            }
        }
        if (!index) {
            pConsensusStatus->listRecvLocalBuddyRsp.push_back(localBuddyInfo);
        }
    }

private:
    CUInt128 _peerid;
    string _pBuf;
    size_t _uiBufLen;
};

class OnChainRefuseTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_REFUSE> {
public:
    using ITask::ITask;

    OnChainRefuseTask(const CUInt128& peerid, const string& hash, uint8 type) : _peerid(peerid), _hash(hash), _type(type) {}

    ~OnChainRefuseTask() {};

    void exec() override
    {
        char logmsg[128] = { 0 };

        snprintf(logmsg, 128, "Refuse peer:%s chain respond\n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = nullptr;
        int ipP2pProtocolRefuseReqLen = sizeof(T_P2PPROTOCOLREFUSEREQ);

        DataBuffer<OnChainRefuseTask> msgbuf(ipP2pProtocolRefuseReqLen);
        pP2pProtocolRefuseReq = reinterpret_cast<T_PP2PPROTOCOLREFUSEREQ>(msgbuf.payload());

        pP2pProtocolRefuseReq->SetP2pprotocolrefusereq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_REFUSE_REQ, CCommonStruct::gettimeofday_update()), (char*)_hash.c_str(), _type);

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = (T_PP2PPROTOCOLREFUSEREQ)(_payload);

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        if (pP2pProtocolRefuseReq->GetSubType() == RECV_RSP) {
            bool isfound = false;
            auto itr = pConsensusStatus->listCurBuddyRsp.begin();
            for (; itr != pConsensusStatus->listCurBuddyRsp.end();) {
                if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
                    itr = pConsensusStatus->listCurBuddyRsp.erase(itr);
                    isfound = true;
                }
                else {
                    itr++;
                }
            }

            if (!isfound) {
                return;
            }
            g_consensus_console_logger->info("Confirm refused from: {}: select another buddy to confirm: listCurBuddyRsp size:{}",
                _sentnodeid.ToHexString(), pConsensusStatus->listCurBuddyRsp.size());

            if (pConsensusStatus->listCurBuddyRsp.size() > 0) {
                auto itr = pConsensusStatus->listCurBuddyRsp.begin();
                for (auto& b : itr->GetList()) {
                    g_consensus_console_logger->info("Confirm selected: {}", b.GetLocalBlock().GetPayLoadPreview());
                }

                LIST_T_LOCALCONSENSUS& c = itr->GetLocalConsensus();
                T_LOCALBLOCK& tLocalBlock = c.begin()->GetLocalBlock();

                SendConfirmReq(itr->GetPeerAddrOut()._nodeid, tLocalBlock.GetID(),
                    itr->GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
            }
        }
        else if (pP2pProtocolRefuseReq->GetSubType() == RECV_REQ)
        {
            auto itr = pConsensusStatus->listCurBuddyReq.begin();
            for (; itr != pConsensusStatus->listCurBuddyReq.end();) {
                if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
                    itr = pConsensusStatus->listCurBuddyReq.erase(itr);
                }
                else {
                    itr++;
                }
            }
        }
    }

private:
    CUInt128 _peerid;
    string _hash;
    int _type;
};

class OnChainWaitTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_WAIT> {
public:
    using ITask::ITask;

    OnChainWaitTask(const CUInt128& peerid, const string& hash) : _peerid(peerid), _hash(hash) {}

    ~OnChainWaitTask() {};

    void exec() override
    {
        char logmsg[128] = { 0 };

        snprintf(logmsg, 128, "I am waiting for confirm respond,inform peer to wait: %s \n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        DataBuffer<OnChainWaitTask> msgbuf(DEF_STR_HASH256_LEN);
        memcpy(msgbuf.payload(), _hash.c_str(), DEF_STR_HASH256_LEN);

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        const char* pHash = _payload;

        ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

        for (auto& buddy : pConsensusStatus->listCurBuddyRsp) {
            if (0 == strncmp(buddy.strBuddyHash, pHash, DEF_STR_HASH256_LEN) && buddy.GetBuddyState() == SEND_CONFIRM) {

                g_consensus_console_logger->info("Confirm wait from {}: select another buddy to confirm : listCurBuddyRsp size:{}",
                    _sentnodeid.ToHexString(), pConsensusStatus->listCurBuddyRsp.size());

                buddy.SetBuddyState(RECV_ON_CHAIN_RSP);
                for (auto& buddyCon : pConsensusStatus->listCurBuddyRsp) {
                    if (&buddyCon != &buddy) {
                        LIST_T_LOCALCONSENSUS& c = buddyCon.GetLocalConsensus();
                        T_LOCALBLOCK& tLocalBlock = c.begin()->GetLocalBlock();
                        SendConfirmReq(buddyCon.GetPeerAddrOut()._nodeid, tLocalBlock.GetID(),
                            buddyCon.GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
                        break;
                    }
                }

                //HCE: Todo:
                //HCE: if listCurBuddyRsp.size()==1, how to do?
                break;
            }
        }
    }

private:
    CUInt128 _peerid;
    string _hash;
};



