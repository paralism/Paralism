/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#include "ITask.hpp"
#include "ObjectFactory.hpp"
#include "HCMQWrk.h"
#include "HCMQClient.h"

#include "util/ElapsedTime.h"

#if !defined WIN32 
#include <sys/syscall.h>
#endif

#include <boost/thread/tss.hpp>

#include <vector>
#include <functional>
#include <thread>
using namespace std;

class priority_scheduler;

class MsgHandler
{
public:

    MsgHandler();
    MsgHandler(const MsgHandler &) = delete;
    MsgHandler & operator=(const MsgHandler &) = delete;

    ~MsgHandler();

    template<class TASK>
    void registerTaskType(TASKTYPE tt)
    {
        _taskFactory.RegisterType<ITask, TASK, TASKBUF>(static_cast<uint32_t>(tt));
    }

    //HCE: Bind handleTask and servicename,then register  to taskworker
    void registerTaskWorker(const char* servicename);

    //HCE: Bind fun and servicename,then register to taskworker
    void registerTaskWorker(const char* servicename, std::function<void(void*, zmsg*)> func);

    //HCE: Bind handleRequest and servicename,then register  to taskworker
    void registerRequestWorker(const char* servicename);

    //HCE: Bind fun and servicename,then add to _pending_service
    void registerWorker(const char* servicename, std::function<void(void*, zmsg*)> func);

    //HCE: Push timer{ delaymilliseconds, delaymilliseconds + s_clock(), func } to _poll_func_timers
    size_t registerTimer(int delaymilliseconds, std::function<void()> func, bool isticket = false);

    //HCE: Notice: at first register workers, then register other zmq sockets.
    void registerSocket(std::function<zmq::socket_t*()> sockcreatefunc, std::function<void(void*, zmsg*)> func);

    void enableStatis(bool enable) {
        _enablestt = enable;
    }

    string getStatistics(const std::string_view& header) const {
        return _taskcoststt.Statistics(header);
    }

    void start(const char* threadname);
    void stop();
    bool isstopped();

    inline void addfiber() { _fiber_count_created_++; }

    std::thread::id getID();
    string details();

private:
    void dispatchMQEvent();
    void dispatchMQEvent_fb();
    void handleTask(void *wrk, zmsg *msg);
    void handleRequest(void *wrk, zmsg *msg);
    void registerSocket(zmq::socket_t* s, std::function<void(void*, zmsg*)> func);

private:

#ifndef WIN32
    std::string _lwp;
#endif;

    bool _isstop = false;
    bool _isstarted = false;

    std::unique_ptr<std::thread> _eventloopthread;

    objectFactory _taskFactory;

    std::vector<HCMQWrk*> _wrks;
    std::vector<zmq::socket_t*> _socks;
    std::vector<zmq::pollitem_t> _poll_items;
    std::vector<std::function<void(void*, zmsg*)>> _poll_funcs;
    std::vector<std::function<void(void*, zmsg*)>> _poll_funcs_s;

    typedef struct
    {
        int delay;  //milliseconds
        int64_t when;
        std::function<void()> func;
    } timer;

    std::vector<timer> _poll_func_timers;
    std::vector<timer> _poll_func_tickets;

    typedef struct
    {
        std::string servicename;
        std::function<void(void*, zmsg*)> func;
    } pendingservice;

    std::vector<pendingservice> _pending_service;

    typedef struct
    {
        std::function<zmq::socket_t*()> sockcreatefunc;
        std::function<void(void*, zmsg*)> func;
    } pendingsock;

    std::vector<pendingsock> _pending_sock;

    int _fiber_count_created_ = 0;

    priority_scheduler * _my_scheduler_algo = nullptr;

    bool _enablestt = false;
    CActionCostStatistics _taskcoststt;
 };


inline void MQMsgPush(zmsg *msg)
{
    (void)(msg);
}

template<typename... Args>
inline void MQMsgPush(zmsg *msg, const string& str, Args... args)
{
    msg->push_back(str.c_str(), str.size());
    MQMsgPush(msg, std::forward<Args>(args)...);
}

template<typename... Args>
inline void MQMsgPush(zmsg *msg, const void *p, Args... args)
{
    msg->push_back(&p, sizeof(void*));
    MQMsgPush(msg, std::forward<Args>(args)...);
}

template<typename T, typename... Args>
inline void MQMsgPush(zmsg *msg, T t, Args... args)
{
    msg->push_back(&t, sizeof(T));
    MQMsgPush(msg, std::forward<Args>(args)...);
}

extern boost::thread_specific_ptr<HCMQClient> mqrsyncclient;

template<typename... Args>
inline zmsg* MQRequest(const char *servicename, int nReq, Args... args)
{
    HCMQClient client(ZMQ_REQ);

    zmsg msg;
    MQMsgPush(&msg, args...);
    msg.push_front((char*)&nReq, sizeof(nReq));

    return (zmsg*)client.cocall(servicename, &msg);
}

template<typename... Args>
inline void MQRequestNoWaitResult(const char *servicename, int nReq, Args... args)
{
    if(!mqrsyncclient.get())
        mqrsyncclient.reset(new HCMQClient(ZMQ_DEALER));


    zmsg msg;
    MQMsgPush(&msg, args...);
    msg.push_front((char*)&nReq, sizeof(nReq));

    mqrsyncclient->rsynccall(servicename, &msg);
}


inline void MQMsgParseHlp(zmsg *rspmsg)
{
    (void)(rspmsg);
}

template<typename... Args>
inline void MQMsgParseHlp(zmsg *rspmsg, string &str, Args&... args)
{
    str = rspmsg->pop_front();
    MQMsgParseHlp(rspmsg, args...);
}

template<typename T, typename... Args>
inline void MQMsgParseHlp(zmsg *rspmsg, T &t, Args&... args)
{
    std::string str = rspmsg->pop_front();
    memcpy(&t, str.c_str(), str.size());
    MQMsgParseHlp(rspmsg, args...);
}

template<typename... Args>
inline void MQMsgPop(zmsg *rspmsg, Args&... args)
{
    MQMsgParseHlp(rspmsg, args...);
}
