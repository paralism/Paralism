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

#include "utility/ElapsedTime.h"

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <memory>
#include <cstring>
#include <thread>
#include <ctime>
#include <map>
#include <deque>
#include <sstream>
#include <atomic>

#ifdef WIN32
#include <winsock2.h>
#include<ws2tcpip.h>
#include <wspiapi.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#endif
#include "udt/udt.h"
#include "SyncQueue.h"

#define MAX_UDTBUF_SIZE 10240000		//HCE: 10M
#define MAX_LIST_COUNT	50000			//HCE: Maximum list length

#ifdef FD_SETSIZE
#undef FD_SETSIZE // prevent redefinition compiler warning
#endif
#define FD_SETSIZE 1024 // max number of fds in fd_set


class priority_scheduler;

typedef struct _tudtrecv
{
    int64_t tmlastrecv = 0;
    int  nrecv = 0;

    inline void refresh() {
        nrecv++;
        tmlastrecv = time(nullptr);
    }
} udtrecv;

typedef struct _tudtnode
{
    string Ip;
    uint32_t Port = 0;

    bool isInRecvFiber = false;
    bool isInSndFiber = false;

    //HC: using for state monitor
    udtrecv uRecv;

    _tudtnode() {}
    _tudtnode(const string IPAddr, int port) : Ip(IPAddr), Port(port)
    {}

    bool operator<(_tudtnode const& other) const
    {
        if (Ip == other.Ip) {
            return Port < other.Port;
        }
        return Ip < other.Ip;
    }

    string toString() const;

} T_UDTNODE, *T_PUDTNODE;

typedef struct _tudtrecvnode
{
    T_UDTNODE fromAddr;
    std::shared_ptr<std::stringbuf> spDataBuf;
    char compressed = false;
}T_UDTRECV, *T_PUDTRECV;


typedef struct _tUDTData{
    std::set<UDTSOCKET> udtsckset;
    int64_t tmlastconn = 0; //time of last reconnection
    int nretryconn = 0;     //retry times
    deque<std::tuple<int64_t, string>> datas;

    //HCE: using for state monitor
    int64_t tmlastsent = 0;
    int  nsent = 0;
    map<UDTSOCKET, udtrecv> sockrecv;


    inline bool isLongTimeNotConn()
    {
        return (udtsckset.size() == 0 && nretryconn > 30);
    }

    inline void refreshReconn(bool bConnSucc) {
        tmlastconn = time(nullptr);
        bConnSucc ? nretryconn = 0 : nretryconn++;
    }

    inline bool isReconnAllowed() {
        const int nBaseInterval = 100;
        const int nLow = 10;

        int nInterval = nBaseInterval;
        if (nretryconn > nLow) {
            //HCE: every nLow retry times, double increase reconnection interval
            nInterval = (1 + nretryconn / nLow) * nBaseInterval;
        }
        return time(nullptr) > tmlastconn + nInterval;
    }

    inline void addSock(UDTSOCKET sock, const udtrecv &urecv)
    {
        if (!udtsckset.count(sock)) {
            udtsckset.insert(sock);
            sockrecv.insert({ sock, urecv });
        }
    }

    inline void removeSock(UDTSOCKET sock)
    {
        if (udtsckset.count(sock)) {
            udtsckset.erase(sock);
            sockrecv.erase(sock);
        }
    }


    string toString() const;
} UDTData;

typedef map<UDTSOCKET, T_UDTNODE>		  MAP_CONNECTED_SOCKET;
typedef MAP_CONNECTED_SOCKET::iterator    ITR_MAP_CONNECTED_SOCKET;

class UdtThreadPool
{
public:
    UdtThreadPool(const char* localIp, uint32_t localPort = 8115, uint32_t numthreads = std::thread::hardware_concurrency(), uint32_t maxnumtasks = MAX_LIST_COUNT);
    ~UdtThreadPool();
    int send(const string &peerIP, uint32_t peerPort, const char * buf, size_t len);
    void start();
    void stop();

    bool peerConnected(const string& peerIP, uint32_t peerPort)
    {
        T_UDTNODE peer(peerIP, peerPort);

        std::lock_guard<std::mutex> lk(m_sendDatasLock);
        if (m_sendDatas.count(peer)) {
            auto udata = m_sendDatas[peer];
            return udata.udtsckset.size() > 0;
        }
        return false;
    }

    //HCE: Get socket state infomation
    string getUdtStatics();

    size_t getUdtSendQueueSize();
    size_t getUdtRecvQueueSize() { return m_recvList.size(); }

    string fiberDetails();
    inline void addfiber() { _fiber_count_created_++; }

  private:
    void Listen();
    void Listen_fb();

    //HCE: Process received data to handler which dispatches them to high layers
    void ProcessDataRecv();

    //HCE: Loop send data and make sure UDT doesn't enter state of waiting infinitely
    void SendData(int eid, int udtsck);

    //HCE: Create listen socket
    int  CreateListenSocket();

    void CloseAllConnectedSocket();

    //HCE: Loop receive data
    void RecvData(int eid, UDTSOCKET socket_fd);

    //HCE: Add eid into m_listenFd and connect
    void FillFdSets(int eid);

    void FillRecvSocketList(UDT::UDSET &readfds, int &activeNum);
    bool AcceptConnectionSocket(int eid, UDTSOCKET listenFd);

    //HCE: Bind my address with socket_fd  
    int BindSocket(UDTSOCKET &socket_fd);

    //HCE: Create connect socket with server node
    UDTSOCKET CreateConnectionSocket(const T_UDTNODE &serverNode);

    //HCE: Remove node from m_sendDatas
    void removeSendNode(T_UDTNODE& node);



private:
    bool                    m_isstop;
    uint32_t                m_localPort;
    const char*             m_localIp;
    UDTSOCKET m_listenFd;

    std::mutex              m_sendDatasLock;
    map<T_UDTNODE, UDTData> m_sendDatas;

    atomic_int64_t     m_nWaitingSnd = 0;
    atomic_int64_t     m_nWaitingSndBytes = 0;

    atomic_int64_t     m_nDiscardedSnd = 0;
    atomic_int64_t     m_nDiscardedSndBytes = 0;

    int64_t            m_nTotalSnd = 0;
    int64_t            m_nTotalSndBytes = 0;

    int64_t            m_nTotalRecv = 0;
    int64_t            m_nTotalRecvBytes = 0;

    SyncQueue<T_UDTRECV>    m_recvList;
    std::thread             m_listenthread;
    std::list<std::thread>  m_recvthreads;
    uint32_t                m_recvthreads_num;
    MAP_CONNECTED_SOCKET    m_socketMap;

    CActionCostStatistics   m_actioncoststt;

    int _fiber_count_created_ = 0;
    priority_scheduler* _my_scheduler_algo = nullptr;

};
