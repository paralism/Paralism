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

#include "zmsg.h"
#include "mdp.h"

class HCMQWrk {
public:

    HCMQWrk(const char *servicename, int socktype = ZMQ_DEALER);
    virtual ~HCMQWrk() {}

    //HCE: Send message to m_worker 
    //HCE: @para command Command char buffer
    //HCE: @para option Option char buffer
    //HCE: @para msg Pointer to zmsg
    void send_to_broker(char *command, std::string option, zmsg *_msg);

    //HCE: Connect to broker and register service with broker
    void connect_to_broker();

    //HCE: Set m_heartbeat_at = s_clock() + m_heartbeat;
    void set_heartbeat_at();

    //HCE: Set m_liveness = HEARTBEAT_LIVENESS;
    void live();

    //HCE: Connect to broker and heartbeat
    void keepalive(zmq::pollitem_t &poll_item);

    void idle();

    //HCE: Reply to broker
    void reply(string reply_who, zmsg *&reply_p);

    zmq::socket_t* getsocket() { return m_worker.get(); }

    void accumWork() {
        m_created_work++;
    }

    void accumWorkCompleted() {
        m_completed_work++;
    }

private:

    void heartbeat();

private:
    std::string m_broker;
    std::string m_service;
    zmq::context_t *m_context = nullptr;
    int m_socktype;
    std::shared_ptr<zmq::socket_t> m_worker;      //HCE: Socket to broker

    //HC: Heartbeat management
    int64_t m_heartbeat_at;       //HCE: When to send HEARTBEAT
    size_t m_liveness;            //HCE: How many attempts left
    int m_heartbeat = 2500;              //HCE: Heartbeat delay, msecs
    int m_reconnect = 2500;              //HCE: Reconnect delay, msecs

    //HCE: Internal state
    bool m_expect_reply = false;         //HCE: Zero only at start

    //HCE: Return address, if any
    std::string m_reply_to;

    int m_created_work = 0;
    int m_completed_work = 0;
    int m_next_request_work_at = 0;
};

