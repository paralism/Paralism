/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "headers.h"

#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/SearchNeighbourTask.h"
#include "node/UdpAccessPoint.hpp"
#include "node/UdpRecvDataHandler.hpp"

#include "cryptocurrency.h"

#include "util/common.h"
#include "paratask.h"
#include "protocol.h"

#include <iostream>
#include <map>
using namespace std;

extern bool AppInit2(int argc, char* argv[]);
extern void ShutdownExcludeRPCServer();
void ReInitSystemRunningEnv();

static bool isControlingApp = false;
int OperatorApplication(std::shared_ptr<OPAPP> parg)
{
    if (isControlingApp) {
        return -1;
    }
    auto t = parg.get();

    auto& apphash = std::get<0>(*t);
    auto& mapParas = std::get<1>(*t);

    mapParas["-coinhash"] = apphash;

    ShutdownExcludeRPCServer();

    //HCE: prepare the coin starting parameters
    std::deque<string> appli;

    appli.push_front("hc");

    int app_argc = mapParas.size() + 1;
    std::shared_ptr<char*> app_argv(new char* [app_argc]);

    for (auto& elm : mapParas) {

        string stroption = elm.first;
        if (!elm.second.empty()) {
            stroption += "=";
            stroption += elm.second;
        }
        appli.push_back(stroption);
    }


    int i = 0;
    char** p = app_argv.get();
    for (auto& elm : appli) {
        p[i++] = &elm[0];
    }

    ReInitSystemRunningEnv();
    AppInit2(app_argc, app_argv.get());

    isControlingApp = false;
    return 0;
}

void ThreadSearchParacoinNode(void* parg)
{
    std::function<void(int)> sleepfn = [](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (fShutdown) {
                break;
            }
            Sleep(200);
        }
    };


    while (!fShutdown) {
        ParaPingTask task;
        task.exec();
        sleepfn(30);
    }
}

#include <iomanip>
#include <ctime>
void outputlog(const string& msg)
{
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    char mbstr[32];
    std::strftime(mbstr, sizeof(mbstr), "%F %T:", &tm);
    std::cout << mbstr << msg << endl;
}

bool PickupMessages(CDataStream& vSendStream, uint32_t nLimitSize, string &tskmsg)
{
    int nSize = 0;
    int nHeaderSize = vSendStream.GetSerializeSize(CMessageHeader());
    while (nSize < nLimitSize) {
        CDataStream::iterator pstart = search(vSendStream.begin(), vSendStream.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vSendStream.end() - pstart < nHeaderSize) {
            if (vSendStream.size() > nHeaderSize) {
                ERROR_FL("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vSendStream.erase(vSendStream.begin(), vSendStream.end() - nHeaderSize);
            }
            break;
        }

        if (pstart - vSendStream.begin() > 0)
            WARNING_FL("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vSendStream.begin());
        vSendStream.erase(vSendStream.begin(), pstart);

        // Read header
        vector<char> vHeaderSave(vSendStream.begin(), vSendStream.begin() + nHeaderSize);
        CMessageHeader hdr;
        vSendStream >> hdr;
        if (!hdr.IsValid()) {
            ERROR_FL("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }

        //if (hdr.GetCommand() == "getdata") {
        //    outputlog(strprintf("getdata message:  IN HEADER %s", hdr.GetCommand().c_str()));
        //}

        //if (hdr.GetCommand() == "block") {

        //    if (vSendStream.size() > hdr.nMessageSize)
        //    {
        //        vector<char> vBlock(vSendStream.begin(), vSendStream.begin() + hdr.nMessageSize);

        //        CBlock blk;
        //        vSendStream >> blk;

        //        vSendStream.insert(vSendStream.begin(), vBlock.begin(), vBlock.end());

        //        outputlog(strprintf("Block message:  height is %d", blk.nHeight));
        //    }
        //    else
        //        outputlog(strprintf("Block message:  height is %d", 0));
        //}

        //HCE: Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE) {
            ERROR_FL("PickupMessages(%u bytes) : nMessageSize > MAX_SIZE\n", nMessageSize);
            continue;
        }

        if (nMessageSize > vSendStream.size() || (nSize > 0 && nSize + nMessageSize > nLimitSize)) {
            //HCE: Rewind and wait for rest of message or reach size limit if append next message
            ERROR_FL("Rewind and wait for rest of message or reach size limit if append next message ");
            vSendStream.insert(vSendStream.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        //HCE: Copy message to its own buffer
        tskmsg.append(vHeaderSave.begin(), vHeaderSave.end());
        tskmsg.append(vSendStream.begin(), vSendStream.begin() + nMessageSize);
        vSendStream.ignore(nMessageSize);

        nSize += nHeaderSize + nMessageSize;
    }

    return nSize > 0;
}

void sendToNode(CNode* pnode)
{
    std::string sndbuf;
    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
    {
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty()) {
            int nBytes = vSend.size();
            if (nBytes > 0) {

                //HCE: copy data will be sent.
                //HCE: We cannot send out data directly before calling vSend.erase,
                //HCE: because calling ParaTask.exec() will possibly switch the message,
                //HCE: struct of vSend will be damaged, and cause unpredictable behavior.

                sndbuf = string(vSend.begin(), vSend.begin() + nBytes);
                vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                pnode->nLastSend = GetTime();

                //HCE: put 4096 bytes messages at most
                //if (PickupMessages(vSend, 4096, sndbuf)) {
                //    pnode->nLastSend = GetTime();
                //}
            }
            if (vSend.size() > SendBufferSize()) {
                if (!pnode->fDisconnect)
                    cerr << StringFormat("%s: socket send flood control disconnect (%d bytes)\n",
                        pnode->addr.ToString(), vSend.size());
                pnode->CloseSocketDisconnect();
            }
        }
    }

    if (sndbuf.size() > 0 && !pnode->fDisconnect) {
        ParaTask tsk(pnode->nodeid, std::move(sndbuf));
        tsk.exec();
    }
}

void recvFromNode(CNode* pnode, const char *pchBuf, size_t nBytes)
{
    CDataStream& vRecv = pnode->vRecv;
    unsigned int nPos = vRecv.size();

    if (nPos > ReceiveBufferSize()) {
        if (!pnode->fDisconnect)
            cerr << StringFormat("%s: socket recv flood control disconnect (%d bytes)********************************\n",
                pnode->addr.ToString(),
                vRecv.size());
        pnode->CloseSocketDisconnect();
    }
    else {
        // typical socket buffer is 8K-64K
        if (nBytes > 0) {
            vRecv.resize(nPos + nBytes);
            memcpy(&vRecv[nPos], pchBuf, nBytes);
            pnode->nLastRecv = GetTime();
        }
        else if (nBytes == 0) {
            // socket closed gracefully
            if (!pnode->fDisconnect)
                TRACE_FL("socket closed\n");
            pnode->CloseSocketDisconnect();
        }
        else if (nBytes < 0) {
            // error
            int nErr = WSAGetLastError();
            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                if (!pnode->fDisconnect)
                    TRACE_FL("socket recv error %d\n", nErr);
                pnode->CloseSocketDisconnect();
            }
        }
    }
}


///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
ParaRecver recver;

void ParaRecver::AddNodeData(const string &node, TASKBUF&& data)
{
    CRITICAL_BLOCK(_cs_NRecv)
    {
        auto& ndatas = _mapNodedata[node];
        ndatas.datas.push_back(data);
    }
}


void ParaRecver::HandleData()
{
    bool iscanremove = false;
    TRY_CRITICAL_BLOCK(_cs_NRecv)
    {
        //HCE: if cannot get locker, try it next time
        TRY_CRITICAL_BLOCK(cs_vNodes)
        {
            iscanremove = true;
            BOOST_FOREACH(CNode * pnode, vNodes)
                if (!_activeNodes.count(pnode->nodeid) && !pnode->fDisconnect) {
                    _activeNodes[pnode->nodeid] = pnode;
                    pnode->AddRef();
                }
        }

        auto it = _mapNodedata.begin();
        for (; it != _mapNodedata.end(); ) {
            if (_activeNodes.count(it->first)) {
                CNode* pnode = _activeNodes[it->first];
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    auto& ndatas = it->second;
                    auto& datas = it->second.datas;
                    for (auto& d : datas) {
                        ndatas.totallenpushed += d->size();
                        char* payload = (char*)(d->c_str() + ProtocolHeaderLen) + sizeof(PARA_TASKTYPE);
                        int payloadlen = d->size() - ProtocolHeaderLen - sizeof(PARA_TASKTYPE);
                        recvFromNode(pnode, payload, payloadlen);
                    }
                    ndatas.waitinghandle = pnode->vRecv.size();
                    ndatas.tmlastpushed = time(nullptr);
                    datas.clear();
                }
            }
            else if (iscanremove) {
                _mapNodedata.erase(it++);
                continue;
            }
            ++it;
        }

        TRY_CRITICAL_BLOCK(cs_vNodes)
        {
            auto itNodes = _activeNodes.begin();
            for (; itNodes != _activeNodes.end(); ) {
                if (itNodes->second->fDisconnect) {
                    itNodes->second->Release();
                    _activeNodes.erase(itNodes++);
                    continue;
                }
                ++itNodes;
            }
        }
    }
}


std::string ParaRecver::GetStatus()
{
    CRITICAL_BLOCK(_cs_NRecv) {
        ostringstream oss;
        auto it = _mapNodedata.begin();
        for (; it != _mapNodedata.end(); ++it) {
            auto& ndatas = it->second;
            if (_activeNodes.count(it->first)) {
                CNode* pnode = _activeNodes[it->first];
                oss << StringFormat("%s: MQ cache: %u, pushed: (%s) %s, sndbuf: %s, recvbuf: %s, proc: %s\n", pnode->addr.ToString(),
                    ndatas.datas.size(),
                    time2string(ndatas.tmlastpushed), toReadable(ndatas.totallenpushed),
                    toReadable(pnode->vSend.size()),
                    toReadable(pnode->vRecv.size()),
                    time2string_s(pnode->tmlastProcessRecv) );
            } else {
                oss << StringFormat("%s: MQ cache: %u, pushed: %s %d, recvbuf: %s\n", it->first,
                    ndatas.datas.size(),
                    time2string(ndatas.tmlastpushed), toReadable(ndatas.totallenpushed),
                    toReadable(ndatas.waitinghandle));
            }
        }
        return oss.str();
    }
    return "";
}

void ParaTask::exec()
{
    char prefix = (char)PARA_TASKTYPE::PARACOIN;
    _msg.insert(_msg.begin(), prefix);

    DataBuffer<ParaTask> msgbuf(std::move(_msg));
    _nodemgr->sendTo(CUInt128(_nodeid), msgbuf);
}

void ParaTask::execRespond()
{
    //Received para message from other node.
    //push message into node buffer.
    PARA_TASKTYPE tt = (PARA_TASKTYPE)*_payload;
    switch (tt)
    {
        case PARA_TASKTYPE::PARACOIN: {
            string sentnodeid = _sentnodeid.ToHexString();
            recver.AddNodeData(sentnodeid, getRecvBuf());

            recver.HandleData();
            break;
        }
        case PARA_TASKTYPE::PARA_PING_NODE: {
            ParaPingTask task(getRecvBuf());
            task.execRespond();
            break;
        }
        case PARA_TASKTYPE::PARA_PING_NODE_RSP: {
            ParaPingRspTask task(getRecvBuf());
            task.execRespond();
            break;
        }
        default:
            return;
    }
}


///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

void ParaPingRspTask::exec()
{
    uint32 hid = g_cryptoCurrency.GetHID();
    uint32 chainnum = g_cryptoCurrency.GetChainNum();
    uint32 localid = g_cryptoCurrency.GetLocalID();

    T_APPTYPE apptype;
    apptype.set(hid, chainnum, localid);
    string buffer(apptype.serialize());
    buffer += _nodemgr->myself()->serialize();

    char prefix = (char)PARA_TASKTYPE::PARA_PING_NODE_RSP;
    buffer.insert(buffer.begin(), prefix);

    DataBuffer<ParaPingRspTask> databuf(std::move(buffer));
    _nodemgr->sendTo(_sentnodeid, databuf);
}

void ParaPingRspTask::execRespond()
{
    //save node
    string payload(_payload, _payloadlen);
    T_APPTYPE apptype;
    size_t offset = apptype.unserialize(payload) + 1;

    uint32 hid;
    uint16 chainnum;
    uint16 localid;
    apptype.get(hid, chainnum, localid);
    if (!g_cryptoCurrency.IsCurrencySame(hid,chainnum,localid)) {
        TRACE_FL("application type is different.\n");
        return;
    }

    UdpAccessPoint udppoint("", 0);
    if (!_nodemgr->getNodeAP(_sentnodeid, &udppoint)) {
        if (!_nodemgr->parseNode(payload.substr(offset), &udppoint)) {
            TRACE_FL("cannot find udp access point\n");
            return;
        }
        TRACE_FL("added a new Paracoin node.\n");
    }

    CAddress addrConnect(udppoint.ip(), (int)udppoint.port());

    CNode* pNode = nullptr;
    CRITICAL_BLOCK(cs_vNodes)
    {
        int64 nMaxRating = 0;
        BOOST_FOREACH(CNode * pnode, vNodes) {
            nMaxRating = std::max(nMaxRating, pnode->GetRating());
            if (pnode->nodeid == _sentnodeid.ToHexString()) {
                if (pnode->addr != addrConnect) {
                    pnode->addr = addrConnect;
                }
                pnode->AddRef(300);
                return;
            }
        }

        //no found
        TRACE_FL("Create a new outbound node and insert into Paracoin nodes.\n");
        pNode = new CNode(-1, addrConnect, false);
        pNode->nodeid = _sentnodeid.ToHexString();
        pNode->SetRating(nMaxRating); //HC: To new node, set maximum value as rating
        pNode->nTimeConnected = GetTime();
        pNode->AddRef(300);
        vNodes.push_back(pNode);
    }

    TRACE_FL("reachable node %s\n", addrConnect.ToString().c_str());
}


void ParaPingTask::exec()
{
    DataBuffer<ParaPingTask> databuf(1);
    char *p = databuf.payload();
    *p = (char)PARA_TASKTYPE::PARA_PING_NODE;

    set<CUInt128> nodesExcluded;
    CRITICAL_BLOCK(cs_vNodes)
    {
        BOOST_FOREACH(CNode * pnode, vNodes) {
            nodesExcluded.insert({ CUInt128(pnode->nodeid) });
        }
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->sendToNodes(databuf, nodesExcluded);
}

void ParaPingTask::execRespond()
{
    ParaPingRspTask task(std::move(_sentnodeid), _payload);
    task.exec();
}

static bool isRegistered = false;

extern "C" BOOST_SYMBOL_EXPORT
bool RegisterTask(void* objFac)
{
    UdpRecvDataHandler* datahandler = reinterpret_cast<UdpRecvDataHandler*>(objFac);
    if (!datahandler) {
        return false;
    }

    datahandler->registerAppTask(TASKTYPE::PARACOIN, PARACOIN_T_SERVICE);
    isRegistered = true;
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
void UnregisterTask(void* objFac)
{
    if (!isRegistered) {
        return;
    }

    UdpRecvDataHandler* datahandler = reinterpret_cast<UdpRecvDataHandler*>(objFac);
    if (!datahandler) {
        return;
    }

    datahandler->unregisterAppTask(TASKTYPE::PARACOIN);
}

MsgHandler paramsghandler;
extern ParaMQCenter paramqcenter;

static void handleParacoinTask(void *wrk, zmsg *msg)
{
    msg->unwrap();
    string buf = msg->pop_front();
    auto taskbuf = std::make_shared<string>(std::move(buf));

    HCMQWrk *realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    TASKTYPE tt = *(TASKTYPE*)(taskbuf->c_str() + CUInt128::value + sizeof(ProtocolVer));
    if (tt != TASKTYPE::PARACOIN) {
        return;
    }

    ParaTask task(std::move(taskbuf));
    task.execRespond();
}

void StartMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&handleParacoinTask, std::placeholders::_1, std::placeholders::_2);

    paramsghandler.registerTaskWorker(PARACOIN_T_SERVICE, fwrk);
    paramsghandler.start("ParaMsgHandler");
    paramqcenter.start();
    cout << "Para MQID:   " << paramsghandler.getID() << endl;

}

void StopMQHandler()
{
    //g_sys_interrupted = 1;
    paramsghandler.stop();
    paramqcenter.stop();
}
