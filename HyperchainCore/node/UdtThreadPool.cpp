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
#include "defer.h"
#include "headers/inter_public.h"

#include "UdtThreadPool.h"
#include "UdpRecvDataHandler.hpp"

#include "algo.h"

#include <chrono>
#include <random>
#include <algorithm>

#include <boost/fiber/all.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zlib.hpp>


string T_UDTNODE::toString() const
{
    return StringFormat("%s:%d", Ip, Port);
}

string UDTData::toString() const
{
    return StringFormat("sent:%d(%s) queue:%u reconn:%d,%s",
        nsent, time2string_s(tmlastsent),
        datas.size(), nretryconn, time2string_s(tmlastconn));
}

UdtThreadPool::UdtThreadPool(const char* localIp, uint32_t localPort, uint32_t numthreads, uint32_t maxnumtasks) :
    m_recvList(maxnumtasks)
{
    m_isstop = true;
    m_listenFd = UDT::INVALID_SOCK;
    m_localIp = localIp;
    m_localPort = localPort;
    m_recvthreads_num = numthreads > 2 ? 2 : numthreads;

    UDT::startup();
}

UdtThreadPool::~UdtThreadPool()
{
    if (!m_isstop)
        stop();

    m_localIp = NULL;
    m_localPort = 0;

    UDT::cleanup();
}

void UdtThreadPool::start()
{
    g_daily_logger->info("UdtThreadPool::Start ...");

    m_isstop = false;

    m_actioncoststt.AddAction(0, "sendreq");
    m_actioncoststt.AddAction(1, "SendData");
    m_actioncoststt.AddAction(2, "epoll-FillSets");

    m_listenthread = std::thread(&UdtThreadPool::Listen, this);

    for (size_t i = 0; i < m_recvthreads_num; i++)
        m_recvthreads.push_back(std::thread(&UdtThreadPool::ProcessDataRecv, this));
}

void UdtThreadPool::stop()
{
    m_isstop = true;

    m_listenthread.join();
    cout << "\tListen and event dispatcher exited\n";

    CloseAllConnectedSocket();
    cout << "\tAll sockets closed\n";

    m_recvList.stop();

    for (auto& t : m_recvthreads)
        t.join();

    cout << "\tData process threads exited\n";

    m_recvthreads.clear();

    //HCE: destructor won't run
    UDT::cleanup();
}

size_t UdtThreadPool::getUdtSendQueueSize()
{
    return m_nWaitingSnd;
}

static vector<const char*> udtstatusdesc = {
    "Undefined",
    "INIT",
    "OPENED",
    "LISTENING",
    "CONNECTING",
    "CONNECTED",
    "BROKEN",
    "CLOSING",
    "CLOSED",
    "NONEXIST",
};


string UdtThreadPool::getUdtStatics()
{
    ostringstream oss;
    oss << "UDTPool:\n";
    {
        std::lock_guard<std::mutex> lk(m_sendDatasLock);
        for (auto& sendsock : m_sendDatas) {

            oss << StringFormat("\t%s  %s ", sendsock.first.toString(), sendsock.second.toString());

            UDTSTATUS status = UDTSTATUS::CLOSED;
            for (auto s : sendsock.second.udtsckset) {
                status = UDT::getsockstate(s);
                auto sr = sendsock.second.sockrecv[s];
                oss << StringFormat("sck:(%s recv:%d,%s) ", udtstatusdesc[status], sr.nrecv, time2string_s(sr.tmlastrecv));
            }
            oss << "\n";
        }
    }

    oss << StringFormat("\tSummary: Waiting to be sent: %d,   %s\n"
        "\t\tData discarded: %" PRI64d ",   %s\n"
        "\t\tData sent successfully: %" PRI64d ",   %s\n"
        //"\t\tTotal data sent: %" PRI64d ",   %s\n"
        "\t\tTotal data received: %" PRI64d ",   %s\n"
        "\t\tRequest/Reply loss rate: %.1f%%\n"
        "\t\tBytes loss rate: %.1f%%\n"
        "\t\tRecvList size: %d\n"
        "\t\tFibers: %s\n\n"
        "%s\n",
        (int)m_nWaitingSnd, toReadable(m_nWaitingSndBytes),
        (int64)m_nDiscardedSnd, toReadable(m_nDiscardedSndBytes),
        m_nTotalSnd - m_nDiscardedSnd, toReadable(m_nTotalSndBytes - m_nDiscardedSndBytes),
        //m_nTotalSnd, toReadable(m_nTotalSndBytes),
        m_nTotalRecv, toReadable(m_nTotalRecvBytes),
        (m_nTotalSnd ? m_nDiscardedSnd * 100.0 / m_nTotalSnd : 0),
        (m_nTotalSndBytes ? m_nDiscardedSndBytes * 100.0 / m_nTotalSndBytes : 0),
        m_recvList.size(),
        fiberDetails(),
        m_actioncoststt.Statistics("UDTPool cost statistics: "));
    return oss.str();
}

void UdtThreadPool::removeSendNode(T_UDTNODE &node)
{
    UDTData& udtd = m_sendDatas[node];
    auto& datas = udtd.datas;
    m_nWaitingSnd -= (int64_t)datas.size();
    m_nDiscardedSnd += (int64_t)datas.size();

    auto iter = datas.begin();
    for (; iter != datas.end(); ++iter) {
        size_t nBytes = std::get<1>(*iter).size();
        m_nWaitingSndBytes -= nBytes;
        m_nDiscardedSndBytes += nBytes;
    }

    datas.clear();

    g_console_logger->info("UdtThreadPool: [{}:{}] cannot connect for a long time, remove the node", node.Ip, node.Port);

    m_sendDatas.erase(node);
}

int UdtThreadPool::send(const string &peerIP, uint32_t peerPort, const char * buffer, size_t len)
{
    T_UDTNODE tTcpNode(peerIP, peerPort);

    auto ststonce = m_actioncoststt.NewStatt(0);

    std::lock_guard<std::mutex> lk(m_sendDatasLock);

    if (m_sendDatas.count(tTcpNode)) {
        auto& udtd = m_sendDatas[tTcpNode];
        auto& datas = udtd.datas;

        if (udtd.isLongTimeNotConn()) {
            m_nDiscardedSnd++;
            m_nDiscardedSndBytes += len;
            return 0;
        }
        datas.push_back(make_tuple(time(nullptr), string(buffer, len)));
    } else {
        UDTData udtdata;
        deque<std::tuple<int64_t, string>> deq;
        deq.push_back(make_tuple(time(nullptr), string(buffer, len)));
        udtdata.datas = std::move(deq);
        m_sendDatas[tTcpNode] = std::move(udtdata);
    }

    m_nWaitingSnd++;
    m_nWaitingSndBytes += (int64_t)len;
    m_nTotalSnd++;
    m_nTotalSndBytes += (int64_t)len;
    return 0;
}

class vfstream : public std::fstream
{
public:
    vfstream()
    {
        iostream* f = this;
        f->rdbuf(_ssdata.rdbuf());
    }

    void add(const string &databuf)
    {
        int32_t datalen = 0;
        char iscompressed = 0;
        if (databuf.size() > 1024) {
            //HCE: zip compress
            stringstream tmpssdata;
            boost::iostreams::filtering_ostream out;
            out.push(boost::iostreams::zlib_compressor(boost::iostreams::zlib::best_compression));
            out.push(tmpssdata);
            out.write(databuf.c_str(), databuf.size());
            out.pop();

            tmpssdata.seekp(0, ios::end);
            datalen = tmpssdata.tellp();

            iscompressed = true;
            _ssdata.write((char*)&datalen, sizeof(datalen));
            _ssdata.write((char*)&iscompressed, sizeof(iscompressed));
            _ssdata.write(tmpssdata.str().c_str(), datalen);
        } else {
            datalen = (int32_t)databuf.size();
            iscompressed = false;
            _ssdata.write((char*)&datalen, sizeof(datalen));
            _ssdata.write((char*)&iscompressed, sizeof(iscompressed));
            _ssdata.write(databuf.c_str(), datalen);
        }
        _nsize += datalen + sizeof(datalen) + sizeof(iscompressed);
        _npackagenum++;

    }

    inline int GetSize()
    {
        return (int)_nsize;
    }

    inline int GetPackageNum()
    {
        return _npackagenum;
    }

private:
    stringstream _ssdata;
    size_t _nsize = 0;
    int _npackagenum = 0;
};

bool HaveSndRoom(int udtsck)
{
    int nSndbuf = 0;
    int nOptlen = sizeof(int);
    UDT::getsockopt(udtsck, 0, UDT_SNDBUF, &nSndbuf, &nOptlen);

    int nMss = 0;
    nOptlen = sizeof(int);
    UDT::getsockopt(udtsck, 0, UDT_MSS, &nMss, &nOptlen);

    int nSndDataSize = 0;
    nOptlen = sizeof(int);
    UDT::getsockopt(udtsck, 0, UDT_SNDDATA, &nSndDataSize, &nOptlen);

    //HCE: m_iSndBufSize
    int nMaxSndBufSize = nSndbuf / (nMss - 28); //HCE: 28, see getsockopt

    if (nMaxSndBufSize <= nSndDataSize)
        return false;

    return true;
}

void UdtThreadPool::SendData(int eid, int udtsck)
{
    if (!m_socketMap.count(udtsck)) {
        return;
    }

    auto &peer = m_socketMap[udtsck];

    auto ststonce = m_actioncoststt.NewStatt(1);

    std::unique_lock<std::mutex> unilck(m_sendDatasLock);
    if (!m_sendDatas.count(peer)) {
        return;
    }

    const int blocksize = 364000; //HCE: 364000, see UDT::sendfile
    const int maxsendingsize = blocksize * 2;
    const int maxrequestnum = 10;

    int nSndbuf = 0;
    int nOptlen = sizeof(int);
    if (UDT::ERROR == UDT::getsockopt(udtsck, 0, UDT_SNDBUF, &nSndbuf, &nOptlen)) {
        return;
    }

    nSndbuf = std::min(nSndbuf, maxsendingsize);

    auto &sendings = m_sendDatas[peer].datas;
    m_sendDatas[peer].nsent++;
    m_sendDatas[peer].tmlastsent = time(nullptr);
    m_sendDatas[peer].sockrecv[udtsck] = peer.uRecv; //HCE: data received info
    unilck.unlock();

    int sndsize = 0;

    vfstream vfst;
    while (!m_isstop) {
        unilck.lock();
        if (sendings.empty()) {
            unilck.unlock();
            UDT::epoll_remove_usock(eid, udtsck);
            break;
        }

        auto& sendingD = sendings.front();
        sndsize = (int)(std::get<1>(sendingD).size());
        if (time(nullptr) - std::get<0>(sendingD) > 300) {
            //HCE: timeout, discard
            m_nDiscardedSnd++;
            m_nDiscardedSndBytes += sndsize;

            m_nWaitingSnd--;
            m_nWaitingSndBytes -= sndsize;

            sendings.pop_front();
            unilck.unlock();
            continue;
        }

        vfst.add(std::get<1>(sendingD));

        sendings.pop_front();
        unilck.unlock();

        m_nWaitingSnd--;
        m_nWaitingSndBytes -= sndsize;

        if (vfst.GetPackageNum() > maxrequestnum)
            break;

        if (vfst.GetSize() >= nSndbuf) {
            break;
        }
    }

    int leftsize = vfst.GetSize();
    int totalsize = leftsize;
    int64_t offset = 0;

    g_console_logger->trace("UdtThreadPool::SendData ({}:{}) : {}[{}]", peer.Ip, peer.Port, totalsize, vfst.GetPackageNum());

    //HCE: loop send data
    while (leftsize > 0 && !m_isstop) {

        //HCE: make sure UDT doesn't enter state of waiting infinitely when calling UDT::sendfile
        while (!HaveSndRoom(udtsck)) {
            UDTSTATUS status = UDT::getsockstate(udtsck);
            if (status == CLOSED || status == CLOSING || status == BROKEN || status == NONEXIST || m_isstop) {
                goto err;
            }
            boost::this_fiber::sleep_for(std::chrono::milliseconds(100));
        }

        int nbytes = leftsize > blocksize ? blocksize : leftsize;
        int sended = (int)UDT::sendfile(udtsck, vfst, offset, nbytes);
        if (UDT::ERROR == sended) {
            goto err;
        }
        leftsize -= sended;
    }

    return;

err:

    //HCE: discard
    m_nDiscardedSnd += vfst.GetPackageNum();
    m_nDiscardedSndBytes += totalsize;

    g_console_logger->debug("UdtThreadPool::SendData ({}:{}) failed! [{}]", peer.Ip, peer.Port, UDT::getlasterror().getErrorMessage());

    UDT::epoll_remove_usock(eid, udtsck);
    UDT::close(udtsck);
}

int UdtThreadPool::BindSocket(UDTSOCKET &socket_fd)
{
    string bindIp;
    struct sockaddr_in my_addr;

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(m_localPort);

    if (m_localIp == NULL || strlen(m_localIp) == 0) {
        my_addr.sin_addr.s_addr = INADDR_ANY;
        bindIp = "INADDR_ANY";
    } else {
        inet_pton(AF_INET, m_localIp, &my_addr.sin_addr);
        bindIp = m_localIp;
    }

    int ret = UDT::bind(socket_fd, (const sockaddr *)&my_addr, sizeof(struct sockaddr));
    if (UDT::ERROR == ret) {
        //boost::this_fiber::sleep_for(std::chrono::seconds(20));
        g_console_logger->error("UdtThreadPool::BindSocket(), bind [{}:{}] error: {}", bindIp, m_localPort, UDT::getlasterror().getErrorMessage());
    }

    return ret;
}

int UdtThreadPool::CreateListenSocket()
{
    UDTSTATUS status = UDT::getsockstate(m_listenFd);
    if (LISTENING == status)
        return 0;

    m_listenFd = UDT::socket(AF_INET, SOCK_STREAM, 0);
    if (m_listenFd == UDT::INVALID_SOCK) {
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), m_listenFd == UDT::INVALID_SOCK");
        return -1;
    }

    //HCE: In practice, we cannot use UDT socket blocking mode.
    //bool isblock = false;
    //UDT::setsockopt(m_listenFd, 0, UDT_SNDSYN, &isblock, sizeof(bool));
    //UDT::setsockopt(m_listenFd, 0, UDT_RCVSYN, &isblock, sizeof(bool));

    int ret = BindSocket(m_listenFd);
    if (UDT::ERROR == ret) {
        return -1;
    }

    ret = UDT::listen(m_listenFd, 4096);
    if (ret == UDT::ERROR) {
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), listen error: {}", UDT::getlasterror().getErrorMessage());
        UDT::close(m_listenFd);
        return -1;
    }

    return 0;
}

void setrecvsendtimeout(UDTSOCKET socket_fd)
{
    int nTimeout = 1000; //1 second
    //HCE: In fact, sending timeout option is unnecessary
    UDT::setsockopt(socket_fd, 0, UDT_SNDTIMEO, &nTimeout, sizeof(int));
    UDT::setsockopt(socket_fd, 0, UDT_RCVTIMEO, &nTimeout, sizeof(int));
}

UDTSOCKET UdtThreadPool::CreateConnectionSocket(const T_UDTNODE& serverNode)
{
    int ret = 0;
    UDTSOCKET socket_fd;

    socket_fd = UDT::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_console_logger->error("UdtThreadPool, socket_fd == UDT::INVALID_SOCK");
        return UDT::INVALID_SOCK;
    }

    ret = BindSocket(socket_fd);
    if (UDT::ERROR == ret) {
        return UDT::INVALID_SOCK;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverNode.Ip.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(serverNode.Port);

    //HCE: close linger
    linger ling;
    ling.l_onoff = 0;
    UDT::setsockopt(socket_fd, 0, UDT_LINGER, &ling, sizeof(linger));

    setrecvsendtimeout(socket_fd);

    //#ifdef WIN32
    //    int mss = 1052;
    //    UDT::setsockopt(socket_fd, 0, UDT_MSS, &mss, sizeof(int));
    //#endif

    ret = UDT::connect(socket_fd, (const sockaddr *)&serverAddr, sizeof(serverAddr));
    if (UDT::ERROR == ret) {
        UDT::close(socket_fd);
        g_console_logger->trace("{} [{}:{}] cannot connect \n", __FUNCTION__, serverNode.Ip, serverNode.Port);
        return UDT::INVALID_SOCK;
    }

    g_console_logger->trace("{} [{}:{}] connected, socket {}\n", __FUNCTION__, serverNode.Ip, serverNode.Port, socket_fd);

    return socket_fd;
}

bool UdtThreadPool::AcceptConnectionSocket(int eid, UDTSOCKET listenFd)
{
    if (m_socketMap.size() >= FD_SETSIZE)
        return false;

    struct sockaddr_in serverAddr;
    int serverAddrLen = sizeof(serverAddr);
    UDTSOCKET socket_fd = UDT::accept(listenFd, (struct sockaddr*)&serverAddr, &serverAddrLen);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_console_logger->error("UdtThreadPool accept : [{}]", UDT::getlasterror().getErrorMessage());
        return false;
    }

    setrecvsendtimeout(socket_fd);

    char str[INET_ADDRSTRLEN] = { 0 };
    string fromIp = inet_ntop(AF_INET, &serverAddr.sin_addr, str, sizeof(str));

    uint32_t fromPort = ntohs(serverAddr.sin_port);

    //HCE: add a new connection for two nodes, so their connections >= 2,
    //HEC: finally, which one will be used? it is decided by data sending and receiving between nodes.
    T_UDTNODE udtnode(fromIp, fromPort);
    m_socketMap[socket_fd] = udtnode;

    linger ling;
    ling.l_onoff = 0;
    UDT::setsockopt(socket_fd, 0, UDT_LINGER, &ling, sizeof(linger));

    g_console_logger->trace("{}: [{}:{}] socket {}", __FUNCTION__, fromIp, fromPort, socket_fd);

    //HCE: insert new one into m_sendDatas or update
    std::lock_guard<std::mutex> lk(m_sendDatasLock);
    m_sendDatas[udtnode].addSock(socket_fd, udtrecv());
    m_sendDatas[udtnode].refreshReconn(true);

    return true;
}

void UdtThreadPool::CloseAllConnectedSocket()
{
    for (auto& t : m_socketMap)
        UDT::close(t.first);

    m_socketMap.clear();
}

void UdtThreadPool::FillFdSets(int eid)
{
    int eventsIn = UDT_EPOLL_IN;

    UDT::epoll_add_usock(eid, m_listenFd, &eventsIn);

    auto ststonce = m_actioncoststt.NewStatt(2);

    deque<T_UDTNODE> reconnnodes;  //HCE: who need to reconnect
    {
        std::lock_guard<std::mutex> lkdata(m_sendDatasLock);
        for (auto it = m_socketMap.begin(); it != m_socketMap.end();) {
            UDTSTATUS status = UDT::getsockstate(it->first);

            if (UDTSTATUS::CONNECTED != status && UDTSTATUS::CONNECTING != status) {
                if (m_sendDatas.count(it->second)) {

                    g_console_logger->trace("{} [{}:{}] {} will be closed for {}\n",
                        __FUNCTION__, it->second.Ip, it->second.Port, it->first, udtstatusdesc[status]);

                    UDT::close(it->first);
                    auto& udtdata = m_sendDatas[it->second];
                    udtdata.removeSock(it->first);
                }
                UDT::epoll_remove_usock(eid, it->first);
                it = m_socketMap.erase(it);
                continue;
            }

            int events = 0;
            if (!it->second.isInRecvFiber) {
                events = UDT_EPOLL_IN;
            }

            if (m_sendDatas.count(it->second)) {
                auto& udtdata = m_sendDatas[it->second];
                udtdata.addSock(it->first, it->second.uRecv);
                if (UDTSTATUS::CONNECTED == status && udtdata.datas.size() > 0 && !it->second.isInSndFiber) {
                    //HCE: There are data need to send
                    events |= UDT_EPOLL_OUT;
                }
            }

            if (events > 0)
                UDT::epoll_add_usock(eid, it->first, &events);
            ++it;
        }

        for (auto& sending : m_sendDatas) {
            if (sending.second.udtsckset.size() == 0) {
                reconnnodes.push_back(sending.first);
            }
        }
    }

    //HCE: reconnect
    const int maxConnectNodes = 5;
    int connNodes = 0;

    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(reconnnodes.begin(), reconnnodes.end(), g);

    while (!reconnnodes.empty() && !m_isstop) {

        if (connNodes > maxConnectNodes) {
            break;
        }

        auto& node = reconnnodes.front();

        std::unique_lock<std::mutex> unilck(m_sendDatasLock);

        if (m_sendDatas.count(node)) {
            auto& udtd = m_sendDatas[node];

            if (udtd.isLongTimeNotConn()) {
                //HCE: node cannot connect, so remove it
                removeSendNode(node);
                unilck.unlock();
                reconnnodes.pop_front();
                continue;
            }

            unilck.unlock();
            if (udtd.isReconnAllowed()) {
                auto s = CreateConnectionSocket(node);
                udtd.refreshReconn(s != UDT::INVALID_SOCK);
                if (s != UDT::INVALID_SOCK) {
                    m_socketMap[s] = std::move(node);
                }
                connNodes++;
            }
            reconnnodes.pop_front();
            continue;
        }
        unilck.unlock();
        reconnnodes.pop_front();
    }
}

string UdtThreadPool::fiberDetails()
{
    int nfiber_terminated = 0;
    if (_my_scheduler_algo) {
        nfiber_terminated = _my_scheduler_algo->fibers_count();
    }
    ostringstream oss;
    oss << m_listenthread.get_id() << " created: " << _fiber_count_created_
        << " deleted: " << nfiber_terminated;
    return oss.str();
}

template<typename Fn>
static void co_create_start(UdtThreadPool* udtpool, int priority, int eid, int udtsck, Fn &&f)
{
    udtpool->addfiber();
    boost::fibers::fiber fb(Newfiber([](int udt_eid, int udt_sck, Fn &&fn) {
        fn(udt_eid, udt_sck);
        }, "udt_child_task", priority, eid, udtsck, f));
    fb.detach();
    return;
}


void UdtThreadPool::Listen_fb()
{
    int nFds = 0;
    if (CreateListenSocket())
        exit(-1);

    set<UDTSOCKET> writefds;
    set<UDTSOCKET> readfds;
    int eid = UDT::epoll_create();

    defer{
        UDT::close(m_listenFd);
        UDT::epoll_release(eid);
    };

    while (!m_isstop) {

        boost::this_fiber::yield();

        FillFdSets(eid);
        nFds = UDT::epoll_wait(eid, &readfds, &writefds, 1500);
        if (nFds < 0) {
            //HC: 超时
            //HCE: Overtime
            continue;
        }

        if (readfds.count(m_listenFd)) {
            //HC: 处理连接请求
            //HCE: Handle connect request
            AcceptConnectionSocket(eid, m_listenFd);
            readfds.erase(m_listenFd);
        }

        for (auto s : readfds) {
            if (!m_isstop) {
                {
                    std::lock_guard<std::mutex> lkdata(m_sendDatasLock);
                    if (m_socketMap[s].isInRecvFiber) {
                        //HCE: The socket is receiving data
                        continue;
                    }
                    m_socketMap[s].isInRecvFiber = true;
                }
                //HCE: let receiving(priority:1) have high priority than sending(0)
                co_create_start(this, 1, eid, s, [this](int eid, UDTSOCKET socket_fd) {
                    RecvData(eid, socket_fd);
                    {
                        std::lock_guard<std::mutex> lkdata(m_sendDatasLock);
                        m_socketMap[socket_fd].isInRecvFiber = false;
                    }
                    });
            }
        }

        for (auto s : writefds) {
            if (!m_isstop) {
                {
                    std::lock_guard<std::mutex> lkdata(m_sendDatasLock);
                    if (m_socketMap[s].isInSndFiber) {
                        //HCE: The socket is sending data
                        continue;
                    }
                    m_socketMap[s].isInSndFiber = true;
                }
                co_create_start(this, 0, eid, s, [this](int eid, UDTSOCKET socket_fd) {
                    SendData(eid, socket_fd);
                    {
                        std::lock_guard<std::mutex> lkdata(m_sendDatasLock);
                        m_socketMap[socket_fd].isInSndFiber = false;
                    }
                    });
            }
        }
    }
}

void UdtThreadPool::Listen()
{
    boost::fibers::use_scheduling_algorithm<priority_scheduler>();
    _my_scheduler_algo = new priority_scheduler();
    boost::fibers::context::active()->get_scheduler()->set_algo(_my_scheduler_algo);

    boost::this_fiber::properties< priority_props >().name = "main";

    boost::fibers::fiber fdispatch(Newfiber([&]() {
        Listen_fb();
        }, "UdtThreadPool", 0));

    fdispatch.join();
}

class vifstream : public std::fstream
{
public:
    vifstream()
    {
        iostream *f = this;
        f->rdbuf(&_recvstreamb);
    }

    inline
        stringbuf& GetData()
    {
        return _recvstreamb;
    }

private:
    stringbuf _recvstreamb;
};

bool HaveRecvRoom(int udtsck)
{
    int nRecvbuf = 0;
    int nOptlen = sizeof(int);
    UDT::getsockopt(udtsck, 0, UDT_RCVDATA, &nRecvbuf, &nOptlen);

    if (nRecvbuf <= 0)
        return false;

    return true;
}

void UdtThreadPool::RecvData(int eid, UDTSOCKET socket_fd)
{
    T_UDTRECV RecvNode;

    vifstream vfst;
    int64_t offset = 0;
    int recvNum = 0;

    const int blocksize = 7280000; //HCE: 7280000, see UDT::recvfile

    RecvNode.fromAddr = m_socketMap[socket_fd];

    int datasize = 0;
    char headrecv[6] = { 0 };

    int ret = UDT::recv(socket_fd, (char*)&headrecv, 5, 0);
    if (UDT::ERROR == ret || ret != 5) {
        //if (CUDTException::ETIMEOUT == UDT::getlasterror().getErrorCode()) {
        if (ret > 0)
            g_console_logger->info(StringFormat("UdtThreadPool::RecvData: [%s:%d] only %d bytes, reconnect...\n",
                RecvNode.fromAddr.Ip, RecvNode.fromAddr.Port, ret));
        goto err;
    }

    m_socketMap[socket_fd].uRecv.refresh();

    memcpy(&datasize, headrecv, sizeof(int32_t));
    RecvNode.compressed = headrecv[4];

    m_nTotalRecv++;
    m_nTotalRecvBytes += datasize;

    //HCE: loop recv data
    while (datasize > 0 && !m_isstop) {

        //HCE: make sure I can receive data from UDT when calling UDT::recvfile
        while (!HaveRecvRoom(socket_fd)) {
            UDTSTATUS status = UDT::getsockstate(socket_fd);
            if (status == CLOSED || status == CLOSING || status == BROKEN || status == NONEXIST || m_isstop) {
                goto err;
            }
            boost::this_fiber::sleep_for(std::chrono::milliseconds(100));
        }

        int nbytes = datasize > blocksize ? blocksize : datasize;
        recvNum = (int)UDT::recvfile(socket_fd, vfst, offset, nbytes);
        if (recvNum == UDT::ERROR) {
            goto err;
        }
        datasize -= recvNum;
        //cout << StringFormat("recvfile[%d]: %d[%d] id: %x\n", socket_fd, recvNum, datasize, &boost::this_fiber::get_id());
    }

    if (m_isstop)
        goto err;

    RecvNode.spDataBuf = make_shared<std::stringbuf>();
    RecvNode.spDataBuf->swap(vfst.GetData());

    if (false == m_recvList.push(std::move(RecvNode))) {
        g_console_logger->warn("UdtThreadPool::RecvData m_recvList.push() failed! m_recvList.size={}", m_recvList.size());
    }

    return;

err:
    g_console_logger->info("UdtThreadPool::RecvData {}", UDT::getlasterror().getErrorMessage());

    UDT::epoll_remove_usock(eid, socket_fd);
    UDT::close(socket_fd);
}


void UdtThreadPool::ProcessDataRecv()
{
    list<T_UDTRECV> recvlist;
    UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::getInstance();

    while (!m_isstop) {
        m_recvList.pop(recvlist);
        for (auto &t : recvlist)
        {
            TASKBUF taskbuf;
            std::stringstream ss_decomp;
            if (t.compressed) {
                //HCE: unzip
                try {
                    boost::iostreams::filtering_istream recvData;
                    recvData.push(boost::iostreams::zlib_decompressor());
                    recvData.push(*t.spDataBuf);
                    boost::iostreams::copy(recvData, ss_decomp);
                } catch (std::exception &e) {
                    cerr << StringFormat("%s exception: ([%s:%d] size(%d) %s\n",
                        __FUNCTION__,
                        t.fromAddr.Ip, t.fromAddr.Port, t.spDataBuf->str().size(), e.what());
                    continue;
                } catch (...) {
                    cerr << StringFormat("%s exception...: ([%s:%d] size(%d)\n",
                        __FUNCTION__,
                        t.fromAddr.Ip, t.fromAddr.Port, t.spDataBuf->str().size());
                    continue;
                }

                taskbuf = std::make_shared<std::string>(ss_decomp.str());
            } else {
                taskbuf = std::make_shared<std::string>(t.spDataBuf->str());
            }

            //HCE: push data to handler which dispatches them to high layers
            udprecvhandler->put(t.fromAddr.Ip.c_str(), t.fromAddr.Port, taskbuf);
            if (m_isstop)
                break;

            g_console_logger->trace("{} ([{}:{}], len = {}) ", __FUNCTION__, t.fromAddr.Ip, t.fromAddr.Port, taskbuf->size());
        }

        recvlist.clear();
    }
}
