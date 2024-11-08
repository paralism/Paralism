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

#include "../newLog.h"
#include "globalbuddyhashtask.h"
#include "../node/Singleton.h"
#include "../db/dbmgr.h"
#include "consensus_engine.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"
#include "../HyperChain/HyperChainSpace.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

//HCE: Merge local block chain into global buddy chain
//HCE: @para mapTotalHash Map of hash list
//HCE: @returns True if success
bool MergeToGlobalConsensus(map<int32, list<T_SHA256>>& mapTotalHash) {
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    bool bchange = false;
    list<T_LOCALCONSENSUS>listLocalConsensus;
    for (auto& hashlist : mapTotalHash) {
        for (auto& hash : hashlist.second) {
            auto itr = pConsensusStatus->mapLocalConsensus.find(hash);
            if (itr != pConsensusStatus->mapLocalConsensus.end()) {
                listLocalConsensus.emplace_back(itr->second);
            }
            else {
                g_consensus_console_logger->warn("Warning: MergeToGlobalConsensus:sleep over 2 circle!");
                return false;
            }
        }
        if (pEng->MergeToGlobalBuddyChains(listLocalConsensus)) {
            bchange = true;
        }
        listLocalConsensus.clear();
    }
    return bchange;
}

//HCE: Resolve T_P2PPROTOCOLGLOBALBUDDYHEADER header
//HCE: @para pProtocolHeader Pointer to T_P2PPROTOCOLGLOBALBUDDYHEADER data
//HCE: @returns True if success
bool ResolveProtocolHeader(const CUInt128& nodeid, T_P2PPROTOCOLGLOBALBUDDYHEADER* pProtocolHeader) {
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    T_P2PPROTOCOLGLOBALBUDDYHEADER protocolHeader;
    auto buddyItr = pConsensusStatus->mapGlobalBuddyInfo.find(nodeid);
    if (buddyItr != pConsensusStatus->mapGlobalBuddyInfo.end()) {
        stringstream mapbuf(buddyItr->second.GetBuffer());
        boost::archive::binary_iarchive mapss(mapbuf, boost::archive::archive_flags::no_header);
        try {
            mapss >> protocolHeader;
            *pProtocolHeader = protocolHeader;
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("ResolveProtocolHeader:{} {}", __FUNCTION__, e.what());
            return false;
        }
        return true;
    }
    return false;
}

//HCE: Resolve T_P2PPROTOCOLGLOBALBUDDYHEADER data
//HCE: @para pProtocolHeader Pointer to T_P2PPROTOCOLGLOBALBUDDYHEADER data
//HCE: @para pmapTotalHash Pointer to map of hash list
//HCE: @para pLackHashList Pointer to list of hash
//HCE: @returns True if success
bool ResolveGlobalBuddy(const CUInt128& nodeid, T_P2PPROTOCOLGLOBALBUDDYHEADER* pProtocolHeader, map<int32, list<T_SHA256>>* pmapTotalHash, list<T_SHA256>* pLackHashList) {
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    auto buddyItr = pConsensusStatus->mapGlobalBuddyInfo.find(nodeid);
    T_P2PPROTOCOLGLOBALBUDDYHEADER protocolHeader;
    if (buddyItr != pConsensusStatus->mapGlobalBuddyInfo.end()) {
        stringstream mapbuf(buddyItr->second.GetBuffer());
        boost::archive::binary_iarchive mapss(mapbuf, boost::archive::archive_flags::no_header);
        try {
            mapss >> protocolHeader;
            *pProtocolHeader = protocolHeader;

            int64 chaincount = pProtocolHeader->GetChainCount();
            int64 blockcount;
            T_SHA256 BlockHash;
            list<T_SHA256> listChainHash;
            for (int i = 0; i < chaincount; i++) {
                mapss >> blockcount;
                for (int j = 0; j < blockcount; j++) {
                    mapss >> BlockHash;
                    listChainHash.emplace_back(BlockHash);

                    //HC:根据BLOCKHASH检查缺少的BLOCK数据
                    //HCE: Check the lack block from BlockHash
                    auto r = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                    if (r == pConsensusStatus->mapLocalConsensus.end()) {
                        pLackHashList->emplace_back(BlockHash);
                    }
                }
                (*pmapTotalHash)[i] = listChainHash;
                listChainHash.clear();
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("ResolveGlobalBuddy:{} {}", __FUNCTION__, e.what());
            return false;
        }
        return true;
    }
    return false;
}

//HCE: Response to receive listGlobalBuddyChainInfo message 
//HCE: @para sendnode Sendnode ID
//HCE: @para _buf Buffer of message data
//HCE: @para _buflenth Size of message data
//HCE: @returns void
void GlobalSendRsp(const CUInt128 sendnode, const char* _buf, uint64 _buflenth) {
    //HC:接收到listGlobalBuddyChainInfo（仅包含块HASH值）信息后的处理
    //HCE: Response to receive listGlobalBuddyChainInfo message 
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    stringstream ssBuf(string(_buf, _buflenth));
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
    T_P2PPROTOCOLGLOBALBUDDYHEADER globalBuddyHeader;
    try {
        ia >> globalBuddyHeader;
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("globalBuddyHeader: {} {}", __FUNCTION__, e.what());
        return;
    }

    //HC:检查hyperblockhash
    //HCE: Check hyper block hash
    T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    if (globalBuddyHeader.uiHyperBlockHash != hyperblockhash) {
        g_consensus_console_logger->info(StringFormat("GlobalBuddyReq is refused for different hyper block hash: (%d)%s %s",
            globalBuddyHeader.GetBlockCount(),
            globalBuddyHeader.uiHyperBlockHash.toHexString(),
            hyperblockhash.toHexString()));

        return;
    };

    //HC: 检查是否是最新buddy信息
    //HCE: Check if it is the lastest buddy
    CUInt128 nodeid = globalBuddyHeader.GetPeerAddr().GetNodeid();
    T_P2PPROTOCOLGLOBALBUDDYHEADER mapBuddyHeader;
    if (ResolveProtocolHeader(nodeid, &mapBuddyHeader))
    {
        if (mapBuddyHeader.tType.GetTimeStamp() >= globalBuddyHeader.tType.GetTimeStamp()) {
            //HC: old buddy信息，不处理
            //HCE: old buddy, return
            return;
        }
    }

    //HC: 用当前buddy信息替换
    //HCE: replace with current buddy 
    T_PEERADDRESS peerAddrOut(nodeid);
    T_BUDDYINFO buddyinfo;
    buddyinfo.Set(RECV_REQ, _buflenth, _buf, peerAddrOut);
    pConsensusStatus->mapGlobalBuddyInfo[nodeid] = buddyinfo;

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    //HC: 仅每一个子链上的最后一个节点进行合并处理
    //HCE: only the end node in each solo chain handles the message
    bool isEndNodeBuddyChain = pEng->IsEndNode();
    if (isEndNodeBuddyChain) {
        T_P2PPROTOCOLGLOBALBUDDYHEADER protocolheader;
        list<T_SHA256> listLackHash;
        map<int32, list<T_SHA256>> mapTotalHash;

        if (ResolveGlobalBuddy(nodeid, &protocolheader, &mapTotalHash, &listLackHash)) {
            CUInt128 memode = me->getNodeId<CUInt128>();
            if (listLackHash.size() > 0) {
                //HC:缺少BLOCK数据，向发送方请求
                //HC:如果在邻居节点中，直接发送，否则发送到发送方转发
                //HCE: be lack of block data and send request to send node
                //HCE: If the node is in active KBuckets, send request directly;otherwise send request to send node
                if (nodemgr->IsNodeInKBuckets(nodeid)) {
                    GlobalBuddyHashBlockTask task(memode, nodeid, nodeid, listLackHash);
                    task.exec();
                }
                else {
                    GlobalBuddyHashBlockTask task(memode, sendnode, nodeid, listLackHash);
                    task.exec();
                }
               
            }
            else {
                //HC:不缺少BLOCK数据，则将合并后的listGlobalBuddyChaininfo发送给对方
                //HCE: never lack of block data,then send merged listGlobalBuddyChaininfo to send node
                if (MergeToGlobalConsensus(mapTotalHash)) {
                    //HC: 合并后有变化
                    //HCE: There are some changes after merge
                    GlobalBuddyHashRspTask task(memode, sendnode, nodeid);
                    task.exec();
                }
                //HC:删除已经发送的buddyinfo
                //HCE: delete buddy already sent
                pConsensusStatus->mapGlobalBuddyInfo.erase(nodeid);
            }
        }
    }
    else {
        //HC:不是最后一个节点，将数据传给共识队列listLocalBuddyChainInfo的最后一个节点
        //HCE: forward chain data to last node in chain
        if (pConsensusStatus->listLocalBuddyChainInfo.size() < 2) {
            return;
        }

        //HC:仅listLocalBuddyChainInfo上的节点转发，减少转发数据
        //HC:listLocalBuddyChainInfo上的最后一个节点
        //HCE: only the node in listLocalBuddyChainInfo forwards the message in order to reduce the forward data
        //HCE: the end node in listLocalBuddyChainInfo
        auto endItr = pConsensusStatus->listLocalBuddyChainInfo.end();
        endItr--;

        //HC:检查是否向自己发送
        //HCE: Check if send to itself
        if (endItr->GetPeer().GetPeerAddr().GetNodeid() != globalBuddyHeader.GetPeerAddr().GetNodeid()) {
            //HC: 不用发给自己
            //HCE: don't need to send to itself
            GlobalBuddyHashForwardTask task(endItr->GetPeer().GetPeerAddr().GetNodeid(), _buf, _buflenth);
            task.exec();
        }
    }
};

//HCE: Response to response to receive listGlobalBuddyChainInfo message 
//HCE: @para _buf Buffer of message data
//HCE: @para _buflenth Size of message data
//HCE: @returns void
void GlobalBuddyHashRspRsp(const char* buf, int64 buflen){
    //HC: 将接收到的listGlobalBuddyChainInfo信息按照子链合并到本节点listGlobalBuddyChainInfo中
    //HCE: Merge the received listGlobalBuddyChainInfo to listGlobalBuddyChainInfo in this node according to solo chain
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    CUInt128 fromnode, destnode;
    T_P2PPROTOCOLGLOBALBUDDYHEADER globalBuddyHeader;
    map<int, LIST_T_LOCALCONSENSUS> mapListConsensus;
    stringstream ssBuf(string(buf, buflen));
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
    try {
        ia >> fromnode;
        ia >> destnode;
        ia >> globalBuddyHeader;
        for (int blocknum = 0; blocknum < globalBuddyHeader.GetBlockCount(); blocknum++) {
            T_GLOBALCONSENSUS globalinfo;
            T_LOCALCONSENSUS localInfo;
            ia >> globalinfo;
            localInfo.SetLoaclConsensus(globalinfo.GetPeer(), globalinfo.GetLocalBlock());
            int nChainnum = globalinfo.GetChainNo();
            auto r = mapListConsensus.find(nChainnum);
            if (r == mapListConsensus.end()) {
                LIST_T_LOCALCONSENSUS listConsensus;
                listConsensus.emplace_back(localInfo);
                mapListConsensus[nChainnum] = listConsensus;
            }
            else {
                r->second.emplace_back(localInfo);
            }
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();

    //HC:自己是转发节点
    //HCE: me is forward node
    if (destnode != me->getNodeId<CUInt128>()) {
        GlobalBuddyHashRspForwardTask task(destnode, buf, buflen);
        task.exec();
        return;
    }

    T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    //HC:hyperblockhash检查，如果不同则返回
    //HCE: check hyper block hash, return if it's different
    if (globalBuddyHeader.uiHyperBlockHash != hyperblockhash) {
        g_consensus_console_logger->info(StringFormat("GlobalBuddyRsp is refused for different hyper block hash: (%d)%s %s",
            globalBuddyHeader.GetBlockCount(),
            globalBuddyHeader.uiHyperBlockHash.toHexString(),
            hyperblockhash.toHexString()));

        return;
    }

    //HC:将每条子链合并到本节点listGlobalBuddyChainInfo中
    //HCE: merge every solo chain into listGlobalBuddyChainInfo of this node
    for (auto& r : mapListConsensus)
        pEng->MergeToGlobalBuddyChains(r.second);
}

void GlobalBuddyHashRspForwardTask::exec() {
    //HCE: send to requester
    DataBuffer<GlobalBuddyHashRspForwardTask> msgbuf(_buf.c_str());

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _destnode.ToHexString());

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();
    if (_destnode != me->getNodeId<CUInt128>()) {
        nodemgr->sendTo(_destnode, msgbuf);
    }
};

void GlobalBuddyHashRspForwardTask::execRespond() {
    GlobalBuddyHashRspRsp(_payload, _payloadlen);
};

void GlobalBuddyHashRspTask::exec() {
    //HC:将合并后的listGlobalBuddyChainInfo信息发送给对方
    //HCE: send the merged listGlobalBuddyChainInfo to send node
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    uint64 blockNum = 0;
    auto itrGlobal = pConsensusStatus->listGlobalBuddyChainInfo.begin();
    for (; itrGlobal != pConsensusStatus->listGlobalBuddyChainInfo.end(); itrGlobal++) {
        blockNum += itrGlobal->size();
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();

    uint64 tempNum = pConsensusStatus->listGlobalBuddyChainInfo.size();

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    P2pProtocolGlobalBuddyHeader.SetBlockCount(blockNum);
    P2pProtocolGlobalBuddyHeader.SetPeerAddr(T_PEERADDRESS(me->getNodeId<CUInt128>()));
    P2pProtocolGlobalBuddyHeader.SetChainCount(tempNum);

    stringstream ssBuf;
    try {
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << _fromnode;
        oa << _destnode;
        oa << P2pProtocolGlobalBuddyHeader;

        uint64 chainNum = 0;
        itrGlobal = pConsensusStatus->listGlobalBuddyChainInfo.begin();
        for (; itrGlobal != pConsensusStatus->listGlobalBuddyChainInfo.end(); itrGlobal++) {
            chainNum++;
            auto subItr = itrGlobal->begin();
            for (; subItr != itrGlobal->end(); subItr++) {
                T_GLOBALCONSENSUS PeerInfos;
                PeerInfos.SetLocalBlock((*subItr).GetLocalBlock());
                PeerInfos.SetPeer((*subItr).GetPeer());
                PeerInfos.SetChainNo(chainNum);
                oa << PeerInfos;
            }
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    //HCE: send to requester
    DataBuffer<GlobalBuddyHashRspTask> msgbuf(move(ssBuf.str()));

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _tonode.ToHexString());

    if (_tonode != me->getNodeId<CUInt128>()) {
        nodemgr->sendTo(_tonode, msgbuf);
    }
};

void GlobalBuddyHashRspTask::execRespond() {
    GlobalBuddyHashRspRsp(_payload, _payloadlen);
};

void GlobalBuddyHashBlockRspTask::exec() {
    //HC:将子块数据发送给对方
    //HCE: send block data to requester
    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    try {
        oa << _fromnode;
        oa << _destnode;
        uint64 blockCount = _listconsensus.size();
        oa << blockCount;
        for (auto& r : _listconsensus)
            oa << r;
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    DataBuffer<GlobalBuddyHashBlockRspTask> msgbuf(std::move(ssBuf.str()));

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _tonode.ToHexString());

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->sendTo(_tonode, msgbuf);
};

void GlobalBuddyHashBlockRspTask::execRespond() {
    //HC:接收子块数据，搜索子块数据完整的子链，并将该子链合并到listGlobalBuddyChainInfo,
    //HC:并将合并后的listGlobalBuddyChainInfo发送给对方
    //HCE: receive solo chain data,search completed solo chain and merge it into listGlobalBuddyChainInfo
    //HCE: send the merged listGlobalBuddyChainInfo to requester
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    CUInt128 fromnode,destnode;
    uint64 blockCount;
    list<T_LOCALCONSENSUS> listConsensus;
    stringstream ssBuf(string(_payload, _payloadlen));
    boost::archive::binary_iarchive ss(ssBuf, boost::archive::archive_flags::no_header);
    try {
        ss >> fromnode;
        ss >> destnode;
        T_LOCALCONSENSUS consensusinfo;
        ss >> blockCount;
        for (int i = 0; i < blockCount; i++) {
            ss >> consensusinfo;
            listConsensus.push_back(consensusinfo);
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    T_SHA256 BlockHash;
    for (auto& blockinfo : listConsensus) {
        BlockHash = blockinfo.GetLocalBlock().GetHashSelf();
        auto r = pConsensusStatus->mapLocalConsensus.find(BlockHash);
        if (r == pConsensusStatus->mapLocalConsensus.end())
            pConsensusStatus->mapLocalConsensus[BlockHash] = blockinfo;
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();
    CUInt128 menode = me->getNodeId<CUInt128>();
    if (destnode != menode) {
        GlobalBuddyHashBlockRspTask task(fromnode, destnode, destnode, listConsensus);
        task.exec();
        return;
    }

    T_P2PPROTOCOLGLOBALBUDDYHEADER protocolheader;
    list<T_SHA256> listLackHash;
    map<int32, list<T_SHA256>> mapTotalHash;

    if (ResolveGlobalBuddy(fromnode, &protocolheader, &mapTotalHash, &listLackHash)) {
        if (listLackHash.size() == 0) {
            //HC:不缺少BLOCK数据，则将合并后的listGlobalBuddyChaininfo发送给对方
            //HCE: be not lack of block data,then send merged listGlobalBuddyChaininfo to requester
            if (MergeToGlobalConsensus(mapTotalHash)) {
                //HC:合并后有变化
                //HCE: there are some changes after merged
                GlobalBuddyHashRspTask task(destnode, _sentnodeid, fromnode);
                task.exec();
            }
            //HC:删除已经发送的buddyinfo
            //HCE: delete buddy already sent
            pConsensusStatus->mapGlobalBuddyInfo.erase(fromnode);
        }
    }
};

void GlobalBuddyHashBlockTask::exec() {
    //HC:发送数据缺少的子块HASH
    //HCE: send hash of uncompleted block to requester
    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    try {
        oa << _fromnode;
        oa << _destnode;

        uint64 hashCount = _blockhashlist.size();
        oa << hashCount;
        for (auto& r : _blockhashlist)
            oa << r;

    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    DataBuffer<GlobalBuddyHashBlockTask> msgbuf(std::move(ssBuf.str()));

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), _tonode.ToHexString());

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->sendTo(_tonode, msgbuf);
};

void GlobalBuddyHashBlockTask::execRespond() {
    //HC:根据子块HASH准备子块数据，并返回给对方
    //HCE: prepare block data according to the block hash, and send back to requester
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    CUInt128 fromnode, destnode;
    uint64 hashCount;
    T_SHA256 BlockHash;

    list<T_SHA256> listhash;
    stringstream ssBuf(string(_payload, _payloadlen));
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
    try {
        ia >> fromnode;
        ia >> destnode;
        ia >> hashCount;
        for (int i = 0; i < hashCount; i++) {
            ia >> BlockHash;
            listhash.push_back(BlockHash);
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();
    CUInt128 menode = me->getNodeId<CUInt128>();

    bool bLackBlock = false;
    list< T_LOCALCONSENSUS > ListConsensus;
    for (auto& blockhash : listhash) {
        auto r = pConsensusStatus->mapLocalConsensus.find(blockhash);
        if (r != pConsensusStatus->mapLocalConsensus.end())
            ListConsensus.emplace_back(r->second);
        else {
            bLackBlock = true;
            break;
        }
    }

    if (!bLackBlock)
    {
        if (nodemgr->IsNodeInKBuckets(fromnode)) {
            GlobalBuddyHashBlockRspTask task(menode, fromnode, fromnode, ListConsensus);
            task.exec();
        }
        else {
            GlobalBuddyHashBlockRspTask task(menode, _sentnodeid, fromnode, ListConsensus);
            task.exec();
        }
    }
    else {
        if (destnode != menode) {
            GlobalBuddyHashBlockTask task(fromnode, destnode, destnode, listhash);
            task.exec();
        }
        else {
            g_consensus_console_logger->warn("{} Can't find blockinfo from blockhash}", __FUNCTION__);
        }
    }
};

void GlobalBuddyHashForwardTask::exec() {
    //HC:将广播数据传送给子链的最后一个节点
    //HCE: forward the broadcast message to the end node in each solo chain
    DataBuffer<GlobalBuddyHashForwardTask> datamsgbuf(std::move(_buf));

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(datamsgbuf.tostring().size(), string(__FUNCTION__), _peerid.ToHexString());

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->sendTo(_peerid, datamsgbuf);
};

void GlobalBuddyHashForwardTask::execRespond() {
    //HC:对数据进行处理
    //HCE: process the data
    GlobalSendRsp(_sentnodeid, _payload, _payloadlen);
};

void GlobalBuddyHashStartTask::exec() {
    //HC:广播listLocalBuddyChainInfo信息，其中的块数据优化为块HASH值
    //HCE: broadcast listLocalBuddyChainInfo, and the block data in it is optimized to the hash of the block data
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    pConsensusStatus->listRecvLocalBuddyReq.clear();

    T_SHA256 preHyperblockHash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    uint64 blockNum = pConsensusStatus->listLocalBuddyChainInfo.size();
    if (blockNum <= 1) {
        //HCE: No any buddy block need to handle
        return;
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();

    pEng->MergeToGlobalBuddyChains(pConsensusStatus->listLocalBuddyChainInfo);
    pConsensusStatus->tBuddyInfo.usChainNum = pConsensusStatus->listGlobalBuddyChainInfo.size();

    auto itr = pConsensusStatus->listLocalBuddyChainInfo.end();
    //HC: Take out the tail local block in the local chain.
    itr--;
    if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
        //HC: The tail local block is created by me.

        T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyReq;
        P2pProtocolGlobalBuddyReq.tType = T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GLOBAL_BUDDY_REQ, CCommonStruct::gettimeofday_update());

        P2pProtocolGlobalBuddyReq.uiHyperBlockHash = preHyperblockHash;
        P2pProtocolGlobalBuddyReq.SetP2pprotocolglobalconsensusreq(T_PEERADDRESS(me->getNodeId<CUInt128>()), blockNum, 1);

        stringstream ssBuf;
        try {
            boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
            oa << P2pProtocolGlobalBuddyReq;
            oa << blockNum;

            for (auto& localblock : pConsensusStatus->listLocalBuddyChainInfo) {
                T_LOCALCONSENSUS blockinfos;
                blockinfos.SetLoaclConsensus(localblock.GetPeer(), localblock.GetLocalBlock());
                T_SHA256 BlockHash = blockinfos.GetLocalBlock().GetHashSelf();
                //HC:将子块信息插入到mapLocalConsensus中
                //HCE: Insert block data into mapLocalConsensus
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

        DataBuffer<GlobalBuddyHashStartTask> msgbuf(move(ssBuf.str()));

        DBmgr* pDb = Singleton<DBmgr>::getInstance();
        pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), string("ALL"));

        nodemgr->sendToAllNodes(msgbuf);
    }
};

void GlobalBuddyHashStartTask::execRespond() {
    //HC:对广播数据进行处理
    //HCE: process the broadcast data
    GlobalSendRsp(_sentnodeid, _payload, _payloadlen);
};

void GlobalBuddyHashSendTask::exec() {
    //HC:广播listGlobalBuddyChainInfo信息，其中的块数据优化为块HASH值
    //HCE: broadcast listGlobalBuddyChainInfo, and the block data in it is optimized to the hash of the block data
    ConsensusEngine* pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    if (!pEng->IsEndNode()) {
        return;
    }

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = nodemgr->myself();

    T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    uint64 blockCount = 0;
    auto itr = pConsensusStatus->listGlobalBuddyChainInfo.begin();

    for (; itr != pConsensusStatus->listGlobalBuddyChainInfo.end(); itr++) {
        blockCount += itr->size();
    }

    if (blockCount == 0) {
        return;
    }

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.tType = T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GLOBAL_BUDDY_REQ, CCommonStruct::gettimeofday_update());
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = hyperblockhash;
    uint64 chainCount = pConsensusStatus->listGlobalBuddyChainInfo.size();
    P2pProtocolGlobalBuddyHeader.SetP2pprotocolglobalconsensusreq(T_PEERADDRESS(me->getNodeId<CUInt128>()),
        blockCount, chainCount);

    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    try {
        oa << P2pProtocolGlobalBuddyHeader;

        for (auto& itrlist : pConsensusStatus->listGlobalBuddyChainInfo) {
            uint64 listcount = itrlist.size();
            oa << listcount;
            for (auto& localblock : itrlist) {
                T_LOCALCONSENSUS blockinfos;
                blockinfos.SetLoaclConsensus(localblock.GetPeer(), localblock.GetLocalBlock());
                T_SHA256 BlockHash = blockinfos.GetLocalBlock().GetHashSelf();
                //HC:将子块信息插入到mapLocalConsensus中
                //HCE: Insert block data into mapLocalConsensus
                auto finditr = pConsensusStatus->mapLocalConsensus.find(BlockHash);
                if (finditr == pConsensusStatus->mapLocalConsensus.end())
                    pConsensusStatus->mapLocalConsensus[BlockHash] = blockinfos;

                oa << BlockHash;
            }
        }
    }
    catch (boost::archive::archive_exception& e) {
        g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
        return;
    }

    g_consensus_console_logger->info("Boardcast my Hyperblock chain to do Global Consensus: {}",
        P2pProtocolGlobalBuddyHeader.uiHyperBlockHash.toHexString());

    //HC:广播块HASH值的listGlobalBuddyChainInfo信息
    DataBuffer<GlobalBuddyHashSendTask> msgbuf(move(ssBuf.str()));

    DBmgr* pDb = Singleton<DBmgr>::getInstance();
    pDb->RecordMsgInfo(msgbuf.tostring().size(), string(__FUNCTION__), string("ALL"));

    nodemgr->sendToAllNodes(msgbuf);
};

void GlobalBuddyHashSendTask::execRespond() {
    //HC:对广播数据进行处理
    //HCE: process the broadcast data
    GlobalSendRsp(_sentnodeid, _payload, _payloadlen);
};
