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
#pragma once
#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"
#include "consensus/buddyinfo.h"
#include "headers/inter_public.h"
#include "headers/lambda.h"
#include "consensus/consensus_engine.h"
#include "../crypto/sha2.h"

#include <openssl/evp.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


#include <iostream>
using namespace std;

extern void putStream(boost::archive::binary_oarchive& oa, const T_HYPERBLOCK& hyperblock);
extern void getFromStream(boost::archive::binary_iarchive &ia, T_HYPERBLOCK& hyperblock, T_SHA256& hash);

class NoHyperBlockRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::NO_HYPERBLOCK_RSP> {
public:
    using ITask::ITask;
    NoHyperBlockRspTask() {};
    ~NoHyperBlockRspTask() {};

    void exec() override {};

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        uint64_t hid = stoull(msgbuf);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->NoHyperBlock(hid, _sentnodeid.ToHexString());
    }
};

class BoardcastHyperBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BOARDCAST_HYPER_BLOCK> {
public:
    using ITask::ITask;
    BoardcastHyperBlockTask() {};
    ~BoardcastHyperBlockTask() {};

    void exec() override
    {
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        vector<CUInt128> sendNodes;
        sp->GetMulticastNodes(sendNodes);
        if (sendNodes.empty())
            return;

        stringstream ssBuf;
        T_HYPERBLOCK hyperblock;

        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            sp->GetLatestHyperBlock(hyperblock);
            putStream(oa, hyperblock);
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        std::set<CUInt128> nodes;
        for (auto & elm : sendNodes) {
            nodes.insert(elm);
        }

        //HC: don't use sendToNodes, here should use async send
        vector<CUInt128>::iterator iter = sendNodes.begin();
        for (; iter != sendNodes.end(); iter++) {
            g_consensus_console_logger->info("Broadcast Latest HyperBlock [{}] to neighbors [{}]", hyperblock.GetID(), (*iter).ToHexString());
            nodemgr->sendTo(*iter, msgbuf);
        }
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);

        T_SHA256 hash;
        T_HYPERBLOCK hyperblock;
        try {
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            getFromStream(ia, hyperblock, hash);

            ostringstream oss;
            hyperblock.calculateHashSelf();
            g_consensus_console_logger->debug("Received hyper block: {}", hyperblock.GetID());
            if (hash != hyperblock.GetHashSelf()) {
                oss << "Received invalid hyper block: " << hyperblock.GetID() << " for hash error";
                throw std::runtime_error(oss.str());
            }
            if (!hyperblock.verify()) {
                oss << "Received invalid hyper block: " << hyperblock.GetID() << " for verification failed";
                throw std::runtime_error(oss.str());
            }
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

        string nodeid = _sentnodeid.ToHexString();
        vector<CUInt128> multicastnodes;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->PutHyperBlock(hyperblock, nodeid, multicastnodes);
    }
};

class GetHyperBlockByNoReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ> {
public:
    using ITask::ITask;
    GetHyperBlockByNoReqTask(uint64 blockNum, const string &nodeid, uint32_t ncount = 1) :
        m_blockNum(blockNum), m_nodeid(nodeid), m_ncount(ncount)
    { }

    ~GetHyperBlockByNoReqTask() {};

    void exec() override
    {
        if (m_blockNum == UINT64_MAX)
            return;

        DataBuffer<GetHyperBlockByNoReqTask> msgbuf(sizeof(T_P2PPROTOCOLGETHYPERBLOCKBYNOREQ));
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ tGetHyperBlockByNoReq = reinterpret_cast<T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ>(msgbuf.payload());
        tGetHyperBlockByNoReq->SetP2pprotocolgethyperblockbynoreq(
            T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GET_HYPERBLOCK_BY_NO_REQ, CCommonStruct::gettimeofday_update()), m_blockNum, m_ncount);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ pP2pProtocolGetHyperBlockByNoReq = (T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ)(_payload);
        m_ncount = pP2pProtocolGetHyperBlockByNoReq->nBlockCount;
        uint64 reqblockNum = pP2pProtocolGetHyperBlockByNoReq->GetBlockNum();

        if (reqblockNum == UINT64_MAX) {
            g_daily_logger->info("GetHyperBlockByNoReqTask, ignore invalid hyperblock id: [-1]");
            return;
        }

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        T_HYPERBLOCK hyperBlock;
        for (uint64 i = 0; i < m_ncount; ++i) {
            if (!sp->getHyperBlock(reqblockNum + i, hyperBlock)) {
                //HCE: I haven't the hyper block.
                DataBuffer<NoHyperBlockRspTask> msgbuf(std::move(to_string(reqblockNum + i)));
                nodemgr->sendTo(_sentnodeid, msgbuf);
                g_daily_logger->info("GetHyperBlockByNoReqTask, I haven't hyperblock: [{}], sentnodeid: [{}]", reqblockNum + i, _sentnodeid.ToHexString());
                continue;
            }

            //HCE: prepare to send the hyper block to the request node
            stringstream ssBuf;
            boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
            try {
                putStream(oa, hyperBlock);
            }
            catch (boost::archive::archive_exception& e) {
                g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
                continue;
            }

            DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

            //HCE: send to the request node
            g_consensus_console_logger->debug("Send Hyperblock {}", hyperBlock.GetID());
            nodemgr->sendTo(_sentnodeid, msgbuf);
        }
    }

private:
    uint64_t m_blockNum;
    uint32_t m_ncount;
    string m_nodeid;

};

class GetHyperBlockByPreHashReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_PREHASH_REQ> {
public:
    using ITask::ITask;
    GetHyperBlockByPreHashReqTask(uint64 blockNum, T_SHA256 prehash, string nodeid)
    {
        m_blockNum = blockNum;
        m_prehash = prehash;
        m_nodeid = nodeid;
    }

    ~GetHyperBlockByPreHashReqTask() {};

    void exec() override
    {
        string datamsg = to_string(m_blockNum) + ":" + m_prehash.toHexString();
        DataBuffer<GetHyperBlockByPreHashReqTask> msgbuf(std::move(datamsg));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string msgbuffer(_payload, _payloadlen);
        string::size_type ns = msgbuffer.find(":");
        if ((ns == string::npos) || (ns == 0)) {
            //HCE: Data format error.
            return;
        }

        uint64_t blockNum = stoull(msgbuffer.substr(0, ns));
        T_SHA256 PreHash = CCommonStruct::StrToHash256(msgbuffer.substr(ns + 1, msgbuffer.length() - 1));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        T_HYPERBLOCK hyperBlock;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        if (!sp->getHyperBlockByPreHash(blockNum, PreHash, hyperBlock)) {
            //HCE: I haven't the hyper block.
            DataBuffer<NoHyperBlockRspTask> msgbuf(std::move(to_string(blockNum)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetHyperBlockByPreHashReqTask, I haven't hyper block: [{}], sentnodeid: [{}]", blockNum, _sentnodeid.ToHexString());
            return;
        }

        //HCE: prepare to send the hyper block to the request node
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        try {
            putStream(oa, hyperBlock);
        }
        catch (boost::archive::archive_exception& e) {
            g_consensus_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        //HCE: send to the request node
        nodemgr->sendTo(_sentnodeid, msgbuf);
    }

private:
    uint64_t m_blockNum;
    T_SHA256 m_prehash;
    string m_nodeid;
};



