/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zlib.hpp>

UdtThreadPool::UdtThreadPool(const char* localIp, uint32_t localPort, uint32_t numthreads, uint32_t maxnumtasks) :
   m_recvList(maxnumtasks)
{
    m_isstop = true;
    m_listenFd = UDT::INVALID_SOCK;
    m_localIp = localIp;
    m_localPort = localPort;
    m_recvthreads_num = numthreads;

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
        m_recvthreads.push_back(std::thread(&UdtThreadPool::Recv, this));
}

void UdtThreadPool::stop()
{
    m_isstop = true;

    m_listenthread.join();
    m_recvList.stop();

    for (auto& t : m_recvthreads)
        t.join();

    m_recvthreads.clear();

    CloseAllConnectedSocket();

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

            oss << StringFormat("\t%s:%d queue:%d ", sendsock.first.Ip, sendsock.first.Port,
                sendsock.second.datas.size());

            UDTSTATUS status = UDTSTATUS::CLOSED;
            for (auto s : sendsock.second.udtsckset) {
                status = UDT::getsockstate(s);
                oss << StringFormat("sck:%d(%s) ", s, udtstatusdesc[status]);
            }
            oss << "\n";
        }
    }

    oss << StringFormat("\tSummary: Waiting to send: %d, %.1f(KB)\n"
        "\tSenddata discarded: %d, %.1f(KB)\n"
        "\tRecvList size: %d\n\n"
        "%s",
        (int)m_nWaitingSnd, m_nWaitingSndBytes / 1024.0,
        (int)m_nDiscardedSnd, m_nDiscardedSndBytes / 1024.0,
        m_recvList.size(),
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
        datas.push_back(make_tuple(time(nullptr),string(buffer, len)));
    } else {
        UDTData udtdata;
        deque<std::tuple<int64_t,string>> deq;
        deq.push_back(make_tuple(time(nullptr), string(buffer, len)));
        udtdata.datas = std::move(deq);
        m_sendDatas[tTcpNode] = std::move(udtdata);
    }

    m_nWaitingSnd++;
    m_nWaitingSndBytes += (int64_t)len;
    return 0;
}

class vfstream : public std::fstream
{
public:
    vfstream(string &databuf)
    {
        if (databuf.size() > 1024) {

            boost::iostreams::filtering_ostream out;
            out.push(boost::iostreams::zlib_compressor(boost::iostreams::zlib::best_compression));
            out.push(_ssdata);
            out.write(databuf.c_str(), databuf.size());
            out.pop();

            _ssdata.seekp(0, ios::end);
            _nsize = _ssdata.tellp();
            _iscompressed = true;
        }
        else {
            _nsize = databuf.size();
            _ssdata = stringstream(databuf);
        }

        iostream* f = this;
        f->rdbuf(_ssdata.rdbuf());
    }

    inline size_t GetSize(char &isCompress)
    {
        isCompress = _iscompressed;
        return _nsize;
    }

private:
    stringstream _ssdata;
    size_t _nsize;
    char _iscompressed = false;
};

inline
int sendheader(int udtsck, int32_t nsize, char iscompress)
{
    char headsend[6];
    memcpy(headsend, &nsize, sizeof(int32_t));
    headsend[4] = iscompress;
    return UDT::send(udtsck, (char*)&headsend, 5, 0);
}

inline
int recvheader(int udtsck, int32_t &nsize, char &iscompress)
{
    char headrecv[6] = {0};
    if (UDT::ERROR == UDT::recv(udtsck, (char*)&headrecv, 5, 0)) {
        return UDT::ERROR;
    }
    memcpy(&nsize, headrecv, sizeof(int32_t));
    iscompress = headrecv[4];
    return sizeof(int32_t) + 1;
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

    auto &sendings = m_sendDatas[peer].datas;
    unilck.unlock();

    int sndsize = 0;
    int64_t nStartingtime = time(nullptr);
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

            m_nDiscardedSnd++;
            m_nDiscardedSndBytes += sndsize;

            m_nWaitingSnd--;
            m_nWaitingSndBytes -= sndsize;

            sendings.pop_front();
            unilck.unlock();
            continue;
        }

        vfstream vfst(std::get<1>(sendingD));
        sendings.pop_front();
        unilck.unlock();

        m_nWaitingSnd--;
        m_nWaitingSndBytes -= sndsize;

        char isCommpressed = false;
        int leftsize = (int)vfst.GetSize(isCommpressed);

        if (UDT::ERROR == sendheader(udtsck, leftsize, isCommpressed)) {
            if (CUDTException::ETIMEOUT == UDT::getlasterror().getErrorCode()) {

                unilck.lock();
                sendings.push_front(sendingD);
                unilck.unlock();

                m_nWaitingSnd++;
                m_nWaitingSndBytes += sndsize;
                return;
            }
            goto err;
        }

        int64_t offset = 0;

        while (leftsize > 0 && !m_isstop) {
            int sended = (int)UDT::sendfile(udtsck, vfst, offset, leftsize);
            if (UDT::ERROR == sended) {
                goto err;
            }
            offset += sended;
            leftsize -= sended;
        }

        if (time(nullptr) - nStartingtime > 2) {

            break;
        }
    }

    return;

err:


    m_nDiscardedSnd++;
    m_nDiscardedSndBytes += sndsize;

    g_daily_logger->error("UdtThreadPool::SendData() send (ip = {}, port = {}) failed! [{}]",
        peer.Ip, peer.Port, UDT::getlasterror().getErrorMessage());

    int errCode = UDT::getlasterror().getErrorCode();
    if (errCode == CUDTException::ECONNLOST ||
        errCode == CUDTException::ENOCONN ||
        errCode == CUDTException::EINVSOCK) {

        UDT::close(udtsck);
    }
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
    }
    else {
        inet_pton(AF_INET, m_localIp, &my_addr.sin_addr);
        bindIp = m_localIp;
    }

    int ret = UDT::bind(socket_fd, (const sockaddr *)&my_addr, sizeof(struct sockaddr));
    if (UDT::ERROR == ret) {
        g_daily_logger->error("UdtThreadPool::BindSocket(), bind [{}:{}] error: {}", bindIp, m_localPort, UDT::getlasterror().getErrorMessage());
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
        g_daily_logger->error("UdtThreadPool::CreateListenSocket(), m_listenFd == UDT::INVALID_SOCK");
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), m_listenFd == UDT::INVALID_SOCK");
        return -1;
    }


    //bool isblock = false;
    //UDT::setsockopt(m_listenFd, 0, UDT_SNDSYN, &isblock, sizeof(bool));
    //UDT::setsockopt(m_listenFd, 0, UDT_RCVSYN, &isblock, sizeof(bool));

    int ret = BindSocket(m_listenFd);
    if (UDT::ERROR == ret) {
        UDT::close(m_listenFd);
        return -1;
    }

    ret = UDT::listen(m_listenFd, 1024);
    if (ret == UDT::ERROR) {
        g_daily_logger->error("UdtThreadPool::CreateListenSocket(), listen error: {}", UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), listen error: {}", UDT::getlasterror().getErrorMessage());
        UDT::close(m_listenFd);
        return -1;
    }

    g_daily_logger->info("UdtThreadPool::CreateListenSocket(), socket_fd = {}", m_listenFd);

    return 0;
}

void setrecvsendtimeout(UDTSOCKET socket_fd)
{
    int nTimeout = 1000; //1 second
    UDT::setsockopt(socket_fd, 0, UDT_SNDTIMEO, &nTimeout, sizeof(int));
    UDT::setsockopt(socket_fd, 0, UDT_RCVTIMEO, &nTimeout, sizeof(int));
}

UDTSOCKET UdtThreadPool::CreateConnectionSocket(const T_UDTNODE& serverNode)
{
    int ret = 0;
    UDTSOCKET socket_fd;

    socket_fd = UDT::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_daily_logger->error("UdtThreadPool, socket_fd == UDT::INVALID_SOCK");
        g_console_logger->error("UdtThreadPool, socket_fd == UDT::INVALID_SOCK");
        return UDT::INVALID_SOCK;
    }

    ret = BindSocket(socket_fd);
    if (UDT::ERROR == ret) {
        UDT::close(socket_fd);
        return UDT::INVALID_SOCK;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverNode.Ip.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(serverNode.Port);

    setrecvsendtimeout(socket_fd);

//#ifdef WIN32
//    int mss = 1052;
//    UDT::setsockopt(socket_fd, 0, UDT_MSS, &mss, sizeof(int));
//#endif

    ret = UDT::connect(socket_fd, (const sockaddr *)&serverAddr, sizeof(serverAddr));
    if (UDT::ERROR == ret) {
        UDT::close(socket_fd);
        g_console_logger->trace("{} [{}:{}] cannot connect \n",
            __FUNCTION__, serverNode.Ip, serverNode.Port);

        return UDT::INVALID_SOCK;
    }

    g_console_logger->trace("{} [{}:{}] connected, socket {}\n",
        __FUNCTION__, serverNode.Ip, serverNode.Port, socket_fd);
    g_daily_logger->trace("{} [{}:{}] connected, socket {}\n",
        __FUNCTION__, serverNode.Ip, serverNode.Port, socket_fd);

    return socket_fd;
}

bool UdtThreadPool::AcceptConnectionSocket(int eid, UDTSOCKET listenFd)
{
    if (m_socketMap.size() >= FD_SETSIZE)
        return false;

    struct sockaddr_in serverAddr;
    int serverAddrLen = sizeof(serverAddr);
    UDTSOCKET socket_fd = UDT::accept(listenFd, (struct sockaddr*) & serverAddr, &serverAddrLen);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_daily_logger->error("UdtThreadPool accept : [{}]", UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool accept : [{}]", UDT::getlasterror().getErrorMessage());
        return false;
    }

    setrecvsendtimeout(socket_fd);

    char str[INET_ADDRSTRLEN] = {0};
    string fromIp = inet_ntop(AF_INET, &serverAddr.sin_addr, str, sizeof(str));

    uint32_t fromPort = ntohs(serverAddr.sin_port);



    T_UDTNODE udtnode(fromIp, fromPort);
    m_socketMap[socket_fd] = udtnode;

    g_console_logger->trace("{}: [{}:{}] socket {}", __FUNCTION__, fromIp, fromPort, socket_fd);
    g_daily_logger->trace("{}: [{}:{}] socket {}", __FUNCTION__, fromIp, fromPort, socket_fd);


    std::lock_guard<std::mutex> lk(m_sendDatasLock);
    m_sendDatas[udtnode].udtsckset.insert(socket_fd);
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
    int eventsInOut = UDT_EPOLL_IN | UDT_EPOLL_OUT;

    UDT::epoll_add_usock(eid, m_listenFd, &eventsIn);

    auto ststonce = m_actioncoststt.NewStatt(2);

    deque<T_UDTNODE> reconnnodes;
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
                    udtdata.udtsckset.erase(it->first);
                }
                UDT::epoll_remove_usock(eid, it->first);
                it = m_socketMap.erase(it);
                continue;
            }

            int events = eventsIn;

            if (m_sendDatas.count(it->second)) {
                auto& udtdata = m_sendDatas[it->second];
                udtdata.udtsckset.insert(it->first);
                if (UDTSTATUS::CONNECTED == status && udtdata.datas.size() > 0) {

                    events = eventsInOut;
                }
            }

            UDT::epoll_add_usock(eid, it->first, &events);
            ++it;
        }

        for (auto& sending : m_sendDatas) {
            if (sending.second.udtsckset.size() == 0) {
                reconnnodes.push_back(sending.first);
            }
        }
    }


    while (!reconnnodes.empty() && !m_isstop) {
        auto& node = reconnnodes.front();

        std::unique_lock<std::mutex> unilck(m_sendDatasLock);

        if (m_sendDatas.count(node)) {
            auto& udtd = m_sendDatas[node];

            if (udtd.isLongTimeNotConn()) {

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
            }
            reconnnodes.pop_front();
            continue;
        }
        unilck.unlock();
        reconnnodes.pop_front();
    }
}

void UdtThreadPool::Listen()
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

        FillFdSets(eid);
        nFds = UDT::epoll_wait(eid, &readfds, &writefds, 3000);
        if (nFds < 0) {

            continue;
        }

        if (readfds.count(m_listenFd)) {

            AcceptConnectionSocket(eid, m_listenFd);
            readfds.erase(m_listenFd);
        }

        for (auto s : readfds) {
            if (!m_isstop) {
                RecvData(eid, s);
            }
        }

        for (auto s : writefds) {
            if (!m_isstop) {
                SendData(eid, s);
            }
        }
    }
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

void UdtThreadPool::RecvData(int eid, UDTSOCKET socket_fd)
{
    T_UDTRECV RecvNode;

    vifstream vfst;
    int64_t offset = 0;
    int recvNum = 0;

    int datasize = 0;
    if (UDT::ERROR == recvheader(socket_fd, datasize, RecvNode.compressed)) {
        goto err;
    }


    while (datasize > 0 && !m_isstop) {
        recvNum = (int)UDT::recvfile(socket_fd, vfst, offset, datasize);
        if (recvNum == UDT::ERROR) {
            goto err;
        }
        offset += recvNum;
        datasize -= recvNum;
    }

    RecvNode.fromAddr = m_socketMap[socket_fd];

    RecvNode.spDataBuf = make_shared<std::stringbuf>();
    RecvNode.spDataBuf->swap(vfst.GetData());

    if (false == m_recvList.push(std::move(RecvNode))) {
        g_daily_logger->error("UdtThreadPool::RecvData() m_recvList.push() failed! m_recvList.size={}", m_recvList.size());
        cout << "UdtThreadPool::RecvData() m_recvList.push() failed! m_recvList.size=" << m_recvList.size() << endl;
    }

    return;

err:
    g_daily_logger->error("UdtThreadPool::RecvData() recv [fd: {}] error: {}", socket_fd, UDT::getlasterror().getErrorMessage());

    UDT::epoll_remove_usock(eid, socket_fd);
    UDT::close(socket_fd);
}


void UdtThreadPool::Recv()
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

                boost::iostreams::filtering_istream recvData;
                recvData.push(boost::iostreams::zlib_decompressor());
                recvData.push(*t.spDataBuf);
                boost::iostreams::copy(recvData, ss_decomp);
                taskbuf = std::make_shared<std::string>(ss_decomp.str());
            } else {
                taskbuf = std::make_shared<std::string>(t.spDataBuf->str());
            }


            udprecvhandler->put(t.fromAddr.Ip.c_str(), t.fromAddr.Port, taskbuf);
            if (m_isstop)
                break;

            g_daily_logger->trace("UdtThreadPool::udprecvhandler->put(serverAddr [{}:{}], len = {}) ",
                t.fromAddr.Ip, t.fromAddr.Port, taskbuf->size());
        }

        recvlist.clear();
    }
}
