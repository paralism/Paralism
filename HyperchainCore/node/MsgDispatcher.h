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

#include "MsgHandler.h"
#include "zmsg.h"
#include "mdp.h"

#include <map>

class MsgDispatcher
{
public:
    MsgDispatcher();
    virtual ~MsgDispatcher();

    MsgDispatcher(const MsgDispatcher &) = delete;
    MsgDispatcher & operator=(const MsgDispatcher &) = delete;

    //HCE: Add app to _mapAppTask 
    void register_app_task(TASKTYPE tt, const std::string &servicename);

    //HCE: Remove app from _mapAppTask
    void unregister_app_task(TASKTYPE tt);

    //HCE: Dispatch task to the node with ip and port
    void dispatch(const char *taskbuf, int len, const string& ip, uint32_t port);

    void stop()
    {
        m_msghandler.stop();
    }

    std::string MQID()
    {
        return m_msghandler.details();
    }


private:

    void connect_to_broker();

    //HCE: Dispatch task to the node with ip and port
    void dispatch_real(const char* taskbuf, int len, const string& ip, uint32_t port);

    void dispatch_to_myself(const char* taskbuf, int len);

    zmsg* send(std::string service, zmsg *request_p);

    //HCE: Dispatch the received message 
    void msg_received(void* sock, zmsg* msg);

    //HCE: Register the app task in received message
    void reg_received(void* sock, zmsg* msg);

 private:
    const std::string REG = "reg";
    const std::string UNREG = "unreg";

    zmq::context_t * m_context = nullptr;
    zmq::socket_t * m_client = nullptr;     //HCE: Socket to broker
    int m_verbose;                          //HCE: Print activity to stdout
    zmq::socket_t *m_dispatch_inner = nullptr;
    std::string m_dispatch_endpoint_i;

    zmq::socket_t *m_app_reg_inner = nullptr;
    std::string m_app_reg_endpoint_i;

    MsgHandler m_msghandler;
    std::map<TASKTYPE, string> _mapAppTask;

};
