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

#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"

extern void putStream(boost::archive::binary_oarchive &oa, uint64_t hid, uint32 range, const vector<T_SHA256>& headerhash);
extern void getFromStream(boost::archive::binary_iarchive &ia, uint64_t& hid, uint32& range, vector<T_SHA256>& headerhash);

class NoHeaderHashRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::NO_HEADERHASH_RSP> {
public:
    using ITask::ITask;
    NoHeaderHashRspTask() {};
    ~NoHeaderHashRspTask() {};

    void exec() override {};

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        uint64_t hid = stoull(msgbuf);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->NoHyperBlockHeaderHash(hid, _sentnodeid.ToHexString());
    }
};

class GetHeaderHashRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASH_RSP> {
public:
    using ITask::ITask;
    GetHeaderHashRspTask() {};
    GetHeaderHashRspTask(CUInt128 nodeid, uint64_t hid, uint32 range) : ITask(), m_startHid(hid), m_range(range) { _sentnodeid = nodeid; }
    ~GetHeaderHashRspTask() {};

    void exec() override
    {
        vector<T_SHA256> HeaderHashList;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        if (!sp->GetHyperBlockHeaderHash(m_startHid, m_range, HeaderHashList)) {
            //HC: I haven't the header hash.
            DataBuffer<NoHeaderHashRspTask> msgbuf(std::move(to_string(m_startHid)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetHeaderHashRspTask, I haven't header hash: [{}], sentnodeid: [{}]", m_startHid, _sentnodeid.ToHexString());
            return;
        }

        //HC: prepare to send the hyper block header to the request node
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            putStream(oa, m_startHid, m_range, HeaderHashList);
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<GetHeaderHashRspTask> datamsg(std::move(ssBuf.str()));

        nodemgr->sendTo(_sentnodeid, datamsg);
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);

        uint64_t hid;
        uint32 range;
        vector<T_SHA256> HeaderHashList;
        try {
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            getFromStream(ia, hid, range, HeaderHashList);
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->PutHyperBlockHeaderHash(hid, range, HeaderHashList, _sentnodeid.ToHexString());
    }

    uint64_t m_startHid;
    uint32_t m_range;
};

class GetHeaderHashReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASH_REQ> {
public:
    using ITask::ITask;
    GetHeaderHashReqTask(uint64 startHid, uint32 range, string nodeid) : m_startHid(startHid), m_range(range), m_nodeid(nodeid) {};
    ~GetHeaderHashReqTask() {};

    void exec() override
    {
        string datamsg = to_string(m_startHid) + ":" + to_string(m_range);
        DataBuffer<GetHeaderHashReqTask> msgbuf(std::move(datamsg));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        string::size_type ns = msgbuf.find(":");
        if ((ns == string::npos) || (ns == 0)) {
            //HC: Data format error.
            return;
        }

        uint64_t hid = stoull(msgbuf.substr(0, ns));
        uint32_t range = stoul(msgbuf.substr(ns + 1, msgbuf.length() - 1));

        GetHeaderHashRspTask tsk(_sentnodeid, hid, range);
        tsk.exec();
    }

    uint64_t m_startHid;
    uint32_t m_range;
    string m_nodeid;
};



class NoHeaderHashMTRootRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::NO_HEADERHASHMTROOT_RSP> {
public:
    using ITask::ITask;
    NoHeaderHashMTRootRspTask() {};
    ~NoHeaderHashMTRootRspTask() {};

    void exec() override {};

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        uint64_t hid = stoull(msgbuf);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->NoHeaderHashMTRoot(hid, _sentnodeid.ToHexString());
    }
};

class GetHeaderHashMTRootRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASHMTROOT_RSP> {
public:
    using ITask::ITask;
    GetHeaderHashMTRootRspTask() {};
    GetHeaderHashMTRootRspTask(CUInt128 nodeid, uint64_t hid) : ITask(), m_hid(hid) { _sentnodeid = nodeid; }
    ~GetHeaderHashMTRootRspTask() {};

    void exec() override
    {
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        string msgbuf;
        if (!sp->GetHeaderHashMTRootData(m_hid, msgbuf)) {
            //HC: I haven't the headerhashMTRoot.
            DataBuffer<NoHeaderHashMTRootRspTask> msgbuf(std::move(to_string(m_hid)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetHeaderHashMTRootRspTask, I haven't headerhashMTRoot: [{}], sentnodeid: [{}]", m_hid, _sentnodeid.ToHexString());
            return;
        }

        DataBuffer<GetHeaderHashMTRootRspTask> datamsg(std::move(msgbuf));
        nodemgr->sendTo(_sentnodeid, datamsg);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->AnalyzeHeaderHashMTRootData(msgbuf, _sentnodeid.ToHexString());
    }

    uint64_t m_hid;
};

class GetHeaderHashMTRootReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASHMTROOT_REQ> {
public:
    using ITask::ITask;
    GetHeaderHashMTRootReqTask(uint64 hid, string nodeid) : m_hid(hid), m_nodeid(nodeid) {};
    ~GetHeaderHashMTRootReqTask() {};

    void exec() override
    {
        DataBuffer<GetHeaderHashMTRootReqTask> msgbuf(std::move(to_string(m_hid)));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);

        uint64_t hid = stoull(msgbuf);
        GetHeaderHashMTRootRspTask tsk(_sentnodeid, hid);
        tsk.exec();
    }

    uint64_t m_hid;
    string m_nodeid;
};
