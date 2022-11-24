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

#include "../newLog.h"

#include "ITask.hpp"
#include "Singleton.h"
#include "NodeManager.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include "UdpAccessPoint.hpp"

class PingPongWithGenBlockHHashRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PING_PONG_WITH_GENHHASH_RSP>
{
public:
    using ITask::ITask;

    PingPongWithGenBlockHHashRspTask(const HCNodeSH& toNodeSH, const char* buf, size_t buflen) :
        _toNodeSH(toNodeSH), _buf(buf, buflen) {}
    ~PingPongWithGenBlockHHashRspTask() {}

    void exec() override
    {
        DataBuffer<PingPongWithGenBlockHHashRspTask> datamsgbuf(std::move(_buf));

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_toNodeSH, datamsgbuf);
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);

        T_SHA256 genhhash;
        string localAPS;
        string toAPS;
        CUInt128 toNodeID1;
        CUInt128 toNodeID2;
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        try {
            ia >> genhhash;
            ia >> localAPS;
            ia >> toAPS;
            ia >> toNodeID1;
            ia >> toNodeID2;
        }
        catch (boost::archive::archive_exception &e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        if (genesis_block_header_hash != T_SHA256(0) && genhhash != genesis_block_header_hash) {
            g_daily_logger->info("PingPongWithGenBlockHHashRspTask::execRespond(), genesis_block_header_hash not compatible!");
            return;
        }

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();

        HCNodeSH nodeSH = make_shared<HCNode>(std::move(CUInt128(toNodeID2)));
        nodeSH->parseAP(toAPS);
        nodemgr->addNode(nodeSH);
        nodemgr->EnableNodeActive(toNodeID2, true);
        nodeUpkeep->RemoveNodeFromPingList(toNodeID2);

        //HC:seed节点有2个nodeid，保留toNodeID2
        if (toNodeID1 != toNodeID2) {
            nodemgr->GetKBuckets()->RemoveNode(toNodeID1);
            nodemgr->RemoveFromNodeMap(toNodeID1);
        }
    }

private:
    string _buf;
    HCNodeSH _toNodeSH;
};


//HC: 握手响应任务,增加了创始块头哈希
class PingPongWithGenBlockHHashTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PING_PONG_WITH_GENHHASH>
{
public:
    using ITask::ITask;

    PingPongWithGenBlockHHashTask(vector<HCNodeSH>& vectNodeSH) : _vectNodeSH(vectNodeSH) {}
    ~PingPongWithGenBlockHHashTask() {}

    void exec() override
    {
        if (genesis_block_header_hash == T_SHA256(0)) {
            g_daily_logger->info("PingPongWithGenBlockHHashTask::exec(), genesis_block_header_hash is not ready!");
            return;
        }

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        string strIP;
        int nPort;
        nodemgr->myself()->getUDPAP(strIP, nPort);
        HCNodeSH localSH = make_shared<HCNode>(std::move(nodemgr->getMyNodeId<CUInt128>()));
        localSH->addAP(std::make_shared<UdpAccessPoint>(nodemgr->GetLocalIP(), nPort));

        for (auto& nodeSH : _vectNodeSH) {
            stringstream ssBuf;
            boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
            try {
                oa << genesis_block_header_hash;
                oa << localSH->serializeAP();
                oa << nodeSH->serializeAP();
                oa << nodeSH->getNodeId<CUInt128>();
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->info("{} {}", __FUNCTION__, e.what());
                return;
            }

            DataBuffer<PingPongWithGenBlockHHashTask> datamsgbuf(std::move(ssBuf.str()));
            nodemgr->sendTo(nodeSH, datamsgbuf);
        }
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);
        stringstream outBuf;

        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        CUInt128 MyNodeID = nodemgr->getMyNodeId< CUInt128>();

        T_SHA256 genhhash;
        string localAPS;
        string toAPS;
        CUInt128 toNodeID;
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        boost::archive::binary_oarchive oa(outBuf, boost::archive::archive_flags::no_header);
        try {
            ia >> genhhash;
            ia >> localAPS;
            ia >> toAPS;
            ia >> toNodeID;

            oa << genesis_block_header_hash;
            oa << localAPS;
            oa << toAPS;
            oa << toNodeID;
            oa << MyNodeID;
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }

        if (genesis_block_header_hash != T_SHA256(0) && genhhash != genesis_block_header_hash) {
            g_daily_logger->info("PingPongWithGenBlockHHashTask::execRespond(), genesis_block_header_hash not compatible!");
            return;
        }

        string strPubAPS = "EMPTY";
        HCNodeSH pubSH = nodemgr->getNode(_sentnodeid);
        if (pubSH) {
            strPubAPS = pubSH->serializeAP();
            NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();
            nodemgr->EnableNodeActive(_sentnodeid, true);   //HC: 记录到活跃桶里
            nodeUpkeep->RemoveNodeFromPingList(_sentnodeid);
        }

        //HC:保存localAPS到mapBroadcastNodeAPS;
        if (nodemgr->mapBroadcastNodeAPS.count(_sentnodeid) > 0) {
            //HC:该节点已经存在，只更新外网IP
            if (strPubAPS.compare(localAPS) != 0) {
                nodemgr->mapBroadcastNodeAPS[_sentnodeid].strPubAPS = strPubAPS;
                nodemgr->mapBroadcastNodeAPS[_sentnodeid].lasttime = time(nullptr);
            }
        }
        else {
            struct stNodeAPS stTemp;
            stTemp.strLanAPS = localAPS;
            stTemp.strPubAPS = strPubAPS;
            nodemgr->mapBroadcastNodeAPS[_sentnodeid] = stTemp;
        }

        if (pubSH) {        
            PingPongWithGenBlockHHashRspTask task(pubSH, outBuf.str().c_str(), outBuf.str().size());
            task.exec();
        }
    }

private:
    vector<HCNodeSH> _vectNodeSH; //HC: 发送对象
};


class BroadcastNeighborTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BROADCAST_NEIGHBOR> {
public:
    using ITask::ITask;
    ~BroadcastNeighborTask() {};
    void exec() override
    {
        //HC: 准备广播信息
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        int32 nCount = nodemgr->mapBroadcastNodeAPS.size();

        if (nCount > 0) {
            stringstream ssBuf;
            boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
            try {
                oa << nCount;
                auto itr = nodemgr->mapBroadcastNodeAPS.begin();
                for (; itr != nodemgr->mapBroadcastNodeAPS.end(); itr++) {
                    oa << itr->first.ToHexString();
                    oa << itr->second.strLanAPS;
                    oa << itr->second.strPubAPS;
                    oa << itr->second.lasttime;

                }
            }
            catch (boost::archive::archive_exception& e) {
                g_console_logger->error("{} {}", __FUNCTION__, e.what());
                return;
            }

            DataBuffer<BroadcastNeighborTask> msgbuf(std::move(ssBuf.str()));

            //HC: 向所有节点广播邻居节点信息
            auto itr = nodemgr->mapBroadcastNodeAPS.begin();
            for (; itr != nodemgr->mapBroadcastNodeAPS.end(); itr++) {
                CUInt128 nodeID = itr->first;
                struct stNodeAPS& nodeAPS = itr->second;
                if (nodeID != nodemgr->getMyNodeId<CUInt128>()) {
                    HCNodeSH nodeSH = nodemgr->getNode(nodeID);
                    if (nodeSH) {
                        nodemgr->sendTo(nodeSH, msgbuf);
                    }
                    else {
                        HCNodeSH nodeSH = make_shared<HCNode>(std::move(CUInt128(nodeID)));
                        if (nodeAPS.strPubAPS.compare("EMPTY") != 0)
                            nodeSH->parseAP(nodeAPS.strPubAPS);
                        else
                            nodeSH->parseAP(nodeAPS.strLanAPS);

                        nodemgr->addNode(nodeSH);
                        nodemgr->sendTo(nodeSH, msgbuf);
                    }
                }
            }
        }
    }

    void execRespond() override
    {
        //HC: 将邻居节点信息保存到mapBroadcastNodeAPS
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        stringstream ssBuf(string(_payload, _payloadlen));
        boost::archive::binary_iarchive ss(ssBuf, boost::archive::archive_flags::no_header);
        try {
            uint32 nNeighborCount;
            vector<CUInt128> vectNode;
            ss >> nNeighborCount;
            for (int i = 0; i < nNeighborCount; i++) {
                string strNodeId;
                string strLanAPS;
                string strPubAPS;
                size_t lasttime;
                ss >> strNodeId;
                ss >> strLanAPS;
                ss >> strPubAPS;
                ss >> lasttime;

                CUInt128 nodeid(strNodeId);
                auto itr = nodemgr->mapBroadcastNodeAPS.find(nodeid);
                if (itr != nodemgr->mapBroadcastNodeAPS.end()) {
                    if (itr->second.lasttime < lasttime) {
                        itr->second.strLanAPS = strLanAPS;
                        itr->second.strPubAPS = strPubAPS;
                        itr->second.lasttime = lasttime;
                    }
                }
                else {
                    struct stNodeAPS stTemp;
                    stTemp.strLanAPS = strLanAPS;
                    stTemp.strPubAPS = strPubAPS;
                    stTemp.lasttime = lasttime;
                    nodemgr->mapBroadcastNodeAPS[nodeid] = stTemp;
                }
            }
        }
        catch (boost::archive::archive_exception& e) {
            g_console_logger->error("{} {}", __FUNCTION__, e.what());
            return;
        }
    }
};
