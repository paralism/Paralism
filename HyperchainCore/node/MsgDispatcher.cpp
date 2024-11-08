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
#include "newLog.h"
#include "ITask.hpp"

#include <boost/thread/tss.hpp>

#include <thread>
#include <functional>

#include "Singleton.h"
#include "NodeManager.h"
#include "MsgDispatcher.h"

//HCE: TODO: how to delete to avoid memory leak?
boost::thread_specific_ptr<zmq::socket_t> msgtransfer;

MsgDispatcher::MsgDispatcher()
{
    m_context = g_inproc_context;
    m_verbose = 0;

    auto fcreate = [&]() -> zmq::socket_t* {
        m_dispatch_inner = new zmq::socket_t(*g_inproc_context, ZMQ_ROUTER);
        m_dispatch_endpoint_i = "inproc://dispatch_inner";
        m_dispatch_inner->bind(m_dispatch_endpoint_i.c_str());
        return m_dispatch_inner;
    };

    std::function<void(void*, zmsg*)> f =
        std::bind(&MsgDispatcher::msg_received, this, std::placeholders::_1, std::placeholders::_2);
    m_msghandler.registerSocket(fcreate, f);

    auto fcreatereg = [&]() -> zmq::socket_t* {
        m_app_reg_inner = new zmq::socket_t(*g_inproc_context, ZMQ_ROUTER);
        m_app_reg_endpoint_i = "inproc://reg_inner";
        m_app_reg_inner->bind(m_app_reg_endpoint_i.c_str());
        return m_app_reg_inner;
    };

    std::function<void(void*, zmsg*)> freg =
        std::bind(&MsgDispatcher::reg_received, this, std::placeholders::_1, std::placeholders::_2);
    m_msghandler.registerSocket(fcreatereg, freg);

    connect_to_broker();

    m_msghandler.start("MsgDispatcher");
}

MsgDispatcher::~MsgDispatcher()
{
    delete m_client;
    delete m_app_reg_inner;
    delete m_dispatch_inner;
}

void MsgDispatcher::register_app_task(TASKTYPE tt, const std::string &servicename)
{
    if (m_msghandler.getID() == std::this_thread::get_id()) {
        _mapAppTask[tt] = servicename;
    }
    else {
        zmq::socket_t sck(*g_inproc_context, ZMQ_REQ);
        sck.connect(m_app_reg_endpoint_i);

        zmsg msg;
        MQMsgPush(&msg, REG, tt, servicename);
        msg.send(sck);
    }
}

void MsgDispatcher::unregister_app_task(TASKTYPE tt)
{
    if (m_msghandler.getID() == std::this_thread::get_id()) {
        _mapAppTask.erase(tt);
    }
    else {
        zmq::socket_t sck(*g_inproc_context, ZMQ_REQ);
        sck.connect(m_app_reg_endpoint_i);

        zmsg msg;
        MQMsgPush(&msg, UNREG, tt);
        msg.send(sck);
    }
}

void MsgDispatcher::dispatch(const char *taskbuf, int len, const string& ip, uint32_t port)
{
    if (m_msghandler.getID() == std::this_thread::get_id()) {
        if (port == 0 && ip.empty())
            dispatch_to_myself(taskbuf, len);
        else
            dispatch_real(taskbuf, len, ip, port);
    }
    else {

        if (!msgtransfer.get()) {
            msgtransfer.reset(new zmq::socket_t(*g_inproc_context, ZMQ_DEALER));
            msgtransfer->connect(m_dispatch_endpoint_i);
        }

        zmsg msg(taskbuf, len);
        MQMsgPush(&msg, ip, port);
        msg.push_front("");
        msg.send(*msgtransfer);
    }
}


void MsgDispatcher::dispatch_to_myself(const char* taskbuf, int len)
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    //HCE: Update neighbor node
    string buff(taskbuf, ProtocolHeaderLen);
    ITask::setTaskType(&buff[0], TASKTYPE::ACTIVE_NODE);

    //HCE: send task of ActiveNodeTask to myself
    zmsg activerequest(buff.c_str(), buff.size());
    send(NODE_T_SERVICE, &activerequest);

    zmsg request((const char*)taskbuf, len);
    TASKTYPE tt = ITask::getTaskType(taskbuf);

    switch (tt) {
    case TASKTYPE::CROSS_CHAIN_TX:
        send(CONSENSUS_T_SERVICE, &request);
        break;

    //case TASKTYPE::BROADCAST_NEIGHBOR:
    //    send(NODE_T_SERVICE, &request);
    //    break;

    //case TASKTYPE::NO_HEADERHASHMTROOT_RSP:
    //    send(HYPERCHAINSPACE_T_SERVICE, &request);
    //    break;

    default:
        if (!_mapAppTask.count(tt)) {
            //HCE: received unknown message type
            return;
        }
        //HCE: send messages to application
        send(_mapAppTask[tt], &request);
    }
}



void MsgDispatcher::dispatch_real(const char *taskbuf, int len, const string& ip, uint32_t port)
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    CUInt128 nodeid = ITask::getTaskNodeID(taskbuf);

    //HCE: Check GENHHASH first
    if (!nodemgr->IsNodeInKBuckets(nodeid)) {

        nodemgr->updateNode(nodeid, ip, port);

        zmsg request((const char*)taskbuf, len);
        TASKTYPE tt = ITask::getTaskType(taskbuf);
        if (tt == TASKTYPE::BROADCAST_NEIGHBOR ||
            tt == TASKTYPE::PING_PONG_WITH_GENHHASH ||
            tt == TASKTYPE::PING_PONG_WITH_GENHHASH_RSP) {
            send(NODE_T_SERVICE, &request);
            return;
        }

        NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();
        nodeUpkeep->AddToPingList(nodeid);
        return;
    }       

    //HCE: Tell NodeManager to mark node actively
    //HCE: Update neighbor node
    string buff(taskbuf, ProtocolHeaderLen);
    ITask::setTaskType(&buff[0], TASKTYPE::ACTIVE_NODE);
    buff.append((char*)&port, sizeof(uint32_t));
    buff.append(ip);

    //HCE: send task of ActiveNodeTask to myself
    zmsg activerequest(buff.c_str(), buff.size());
    send(NODE_T_SERVICE, &activerequest);

    zmsg request((const char*)taskbuf, len);
    TASKTYPE tt = ITask::getTaskType(taskbuf);

    switch (tt) {
    case TASKTYPE::ON_CHAIN:
    case TASKTYPE::ON_CHAIN_RSP:
    case TASKTYPE::ON_CHAIN_CONFIRM:
    case TASKTYPE::ON_CHAIN_CONFIRM_RSP:
    case TASKTYPE::GLOBAL_BUDDY_START_REQ:
    case TASKTYPE::GLOBAL_BUDDY_SEND_REQ:
    case TASKTYPE::GLOBAL_BUDDY_RSP:
    case TASKTYPE::ON_CHAIN_WAIT:
    case TASKTYPE::COPY_BLOCK:
    case TASKTYPE::ON_CHAIN_REFUSE:
        //HCE:HASH CONSENSUS:
    case TASKTYPE::ON_CHAIN_HASH:
    case TASKTYPE::ON_CHAIN_HASH_RSP:
    case TASKTYPE::ON_CHAIN_BLOCK:
    case TASKTYPE::GLOBAL_BUDDY_HASH_START_REQ:
    case TASKTYPE::GLOBAL_BUDDY_HASH_RSP:
    case TASKTYPE::GLOBAL_BUDDY_HASH_RSP_FORWARD:
    case TASKTYPE::GLOBAL_BUDDY_HASH_SEND_REQ:
    case TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK:
    case TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK_RSP:
    case TASKTYPE::GLOBAL_BUDDY_HASH_FORWARD:
        send(CONSENSUS_T_SERVICE, &request);
        break;

    case TASKTYPE::SEARCH_NEIGHBOUR:
    case TASKTYPE::SEARCH_NEIGHBOUR_RSP:
    case TASKTYPE::PING_PONG:
    case TASKTYPE::PING_PONG_RSP:
    case TASKTYPE::PING_PONG_WITH_GENHHASH:
    case TASKTYPE::PING_PONG_WITH_GENHHASH_RSP:
    case TASKTYPE::BROADCAST_NEIGHBOR:
        send(NODE_T_SERVICE, &request);
        break;

    case TASKTYPE::HYPER_CHAIN_SPACE_PULL:
    case TASKTYPE::HYPER_CHAIN_SPACE_PULL_RSP:
    case TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ:
    case TASKTYPE::GET_HYPERBLOCK_BY_PREHASH_REQ:
    case TASKTYPE::GET_HEADERHASHMTROOT_REQ:
    case TASKTYPE::GET_HEADERHASHMTROOT_RSP:
    case TASKTYPE::GET_HEADERHASH_REQ:
    case TASKTYPE::GET_HEADERHASH_RSP:
    case TASKTYPE::GET_BLOCKHEADER_REQ:
    case TASKTYPE::GET_BLOCKHEADER_RSP:
    case TASKTYPE::BOARDCAST_HYPER_BLOCK:
    case TASKTYPE::NO_HYPERBLOCK_RSP:
    case TASKTYPE::NO_BLOCKHEADER_RSP:
    case TASKTYPE::NO_HEADERHASHMTROOT_RSP:
        send(HYPERCHAINSPACE_T_SERVICE, &request);
        break;

    default:
        if (!_mapAppTask.count(tt)) {
            //HCE: received unknown message type
            return;
        }
        //HCE: send messages to application module
        send(_mapAppTask[tt], &request);
    }
}

void MsgDispatcher::msg_received(void *sock, zmsg *msg)
{
    msg->unwrap();

    std::string taskbuf;
    string ip;
    int port;
    MQMsgPop(msg, taskbuf, ip, port);
    dispatch_real(taskbuf.c_str(), taskbuf.size(), ip, port);
}

void MsgDispatcher::reg_received(void *sock, zmsg *msg)
{
    msg->unwrap();

    string req;
    MQMsgPop(msg, req);

    TASKTYPE tt;
    if (req == REG) {
        std::string appsvc;
        MQMsgPop(msg, tt, appsvc);
        register_app_task(tt, appsvc);
    }
    else if (req == UNREG) {
        MQMsgPop(msg, tt);
        unregister_app_task(tt);
    }
}


void MsgDispatcher::connect_to_broker()
{
    if (m_client) {
        delete m_client;
    }
    m_client = new zmq::socket_t(*m_context, ZMQ_DEALER);
    s_set_id(*m_client);

    int linger = 200;
    m_client->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
    m_client->connect(HC_BROKER);
    if (m_verbose) {
        s_console("I: connecting to hc_broker...");
    }
}

zmsg* MsgDispatcher::send(std::string service, zmsg *request)
{
    assert(request);

    //HCE: Prefix request with protocol frames
    //HCE: Frame 1: "MDPCxy" (six bytes, MDP/Client x.y)
    //HCE: Frame 2: Service name (printable string)
    request->push_front((char*)service.c_str());
    request->push_front((char*)MDPC_CLIENT);
    request->push_front("");
    if (m_verbose) {
        s_console("MsgDispatcher: send request to '%s' service:", service.c_str());
        request->dump();
    }
    request->send(*m_client);

    return nullptr;
}


