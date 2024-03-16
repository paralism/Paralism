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

#include "UdtThreadPool.h"
#include "NodeUpkeepThreadPool.h"
#include "newLog.h"

#include "NodeManager.h"
#include "Singleton.h"
#include "SearchNeighbourTask.h"
#include "PingPongTask.h"
#include "PingPongWithGenBlockHHashTask.hpp"
#include <boost/fiber/all.hpp>

NodeType g_nodetype = NodeType::Bootstrap;

void NodeUPKeepThreadPool::start()
{
    InitPullList();
}

void NodeUPKeepThreadPool::stop()
{
    m_lstPullNode.clear();
    m_setPingNode1.clear();
    m_setPingNode2.clear();
}

//HC: 把_nodemap节点(32个)先放入到pull列表里
//HCE: Put the nodes in _nodemap into pulllist first
void NodeUPKeepThreadPool::InitPullList()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    vector<CUInt128> vecNodes;
    nodemgr->GetNodeMapNodes(vecNodes);
    for (CUInt128& id : vecNodes)
        m_lstPullNode.push_back(id);
}

void NodeUPKeepThreadPool::PreparePullList()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    std::set<HCNode> setNodes;
    nodemgr->PickRandomNodes(16, setNodes);

    UdtThreadPool* pUdtPool = Singleton<UdtThreadPool, const char*, uint32_t>::getInstance();

    string peerIP;
    for (auto& node : setNodes) {
        if (pUdtPool && !nodemgr->IsSeedServer(node)) {
            m_lstPullNode.push_back(node.getNodeId<CUInt128>());
        }
    }

    if (g_nodetype == NodeType::Normal) {
        for (auto& ss : nodemgr->seedServers()) {
            CUInt128 seedID = ss->getNodeId<CUInt128>();
            if (!nodemgr->IsNodeInKBuckets(seedID))
                m_lstPullNode.push_back(seedID);
        }
    }
}

//HC: 每3min取k桶16个节点获取10个邻居
//HCE: Pick 16 nodes in KBuckets and get 10 neighbor nodes every 3 min
void NodeUPKeepThreadPool::NodeFind()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    //HC: K桶选出一批节点用于拉取
    //HCE: Pull some nodes in KBucket
    if (m_lstPullNode.empty())
        PreparePullList();
    g_console_logger->debug("Pickup {} nodes to refresh K Buckets", m_lstPullNode.size());

    for (CUInt128& node : m_lstPullNode) {
        //HCE: nodemgr->EnableNodeActive(node, false);

        SearchNeighbourTask tsk(node);
        tsk.exec();
    }
    m_lstPullNode.clear();
    g_console_logger->debug("Finish Refresh K Buckets");
}

std::set<CUInt128>& NodeUPKeepThreadPool::getPingNodeSet()
{
    return m_pingSecSet ? m_setPingNode2 : m_setPingNode1;
}

std::set<CUInt128>& NodeUPKeepThreadPool::getAddNodeSet()
{
    return m_pingSecSet ? m_setPingNode1 : m_setPingNode2;
}

void NodeUPKeepThreadPool::PreparePingSet()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    //HC: 产生随机ID, 获取距离最近的ID集合作为刷新节点
    //HCE: Generate random ID, ping the near node id set
    string str = HCNode::generateNodeId();
    vector<HCNode> vecNodes;
    nodemgr->PickNeighbourNodesEx(CUInt128(str), 30, vecNodes);

    UdtThreadPool* pUdtPool = Singleton<UdtThreadPool, const char*, uint32_t>::getInstance();

    string peerIP;
    int peerPort;
    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    for (auto& node : vecNodes) {
        if (pUdtPool) {
            if (!nodemgr->IsNodeInKBuckets(node.getNodeId<CUInt128>())) {
                //HCE: If not in KBuckets, need ping for check GENHHASH
                addNodeSet.insert(node.getNodeId<CUInt128>());
            }

            node.getUDPAP(peerIP, peerPort);
            //HCE: In case network layer tell me peer is connected, skip ping action.
            if (!pUdtPool->peerConnected(peerIP, peerPort)) {
                addNodeSet.insert(node.getNodeId<CUInt128>());
            }
        }
    }
    m_pingSecSet = !m_pingSecSet;
}


void NodeUPKeepThreadPool::DoPing()
{
    //HC: 对超时没有更新的节点，删除并移出Activenode
    //HCE: Remove the nodes that do not update in time out of active node list
    set<CUInt128> removedNodes;
    if (m_pingstate == pingstate::ping1)
        removedNodes = UpdateBroadcastMap();

    //HC: 准备广播节点
    //HC: 如果内网IP已经连接，不用加入广播；如果外网IP已连接，只加入外网IP；如果尚未连接，内外网IP都加入广播
    //HCE: Prepare broadcast node list
    //HCE: If lan ip is connected, don't add it into broadcast list;if pub ip is connected, add it into broadcast list; if it isn't connected, lan and pub ip add into broadcast list both.
    vector<HCNodeSH> vectNodeSH;

    auto fnAddPingNode = [&](CUInt128 nodeid, const string& aps) {
        if (!removedNodes.count(nodeid)) {
            HCNodeSH lanNodeSH = make_shared<HCNode>(std::move(nodeid));
            lanNodeSH->parseAP(aps);
            vectNodeSH.push_back(lanNodeSH);
        }
    };

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    CUInt128 meNode = nodemgr->getMyNodeId<CUInt128>();
    auto itr1 = nodemgr->mapBroadcastNodeAPS.begin();
    for (; itr1 != nodemgr->mapBroadcastNodeAPS.end(); itr1++) {
        CUInt128 nodeid = itr1->first;
        struct stNodeAPS& nodeAPS = itr1->second;
        if (nodeid != meNode) {
            //HC: 是否已经连接
            //HCE: If it is connected
            if (nodemgr->IsNodeInKBuckets(nodeid)) {
                string strNodeAPS = nodemgr->getNode(nodeid)->serializeAP();
                if (strNodeAPS.compare(nodeAPS.strLanAPS) != 0) {
                    if (nodeAPS.strPubAPS.compare("EMPTY") != 0) {
                        fnAddPingNode(nodeid, nodeAPS.strPubAPS);
                    }
                }
            }
            else {
                if (nodeAPS.strLanAPS.compare("EMPTY") != 0) {
                    fnAddPingNode(nodeid, nodeAPS.strLanAPS);
                }
                if (nodeAPS.strPubAPS.compare("EMPTY") != 0) {
                    fnAddPingNode(nodeid, nodeAPS.strPubAPS);
                }
            }
        }
    }

    //HC: 将pingset加入到广播节点
    //HCE: Add pingset into broadcast list
    std::set<CUInt128>& pingNodeSet = getPingNodeSet();
    for (auto& nodeID : pingNodeSet) {
        //HC:已加入节点不再加入
        //HCE: Node aready in broadcast list
        if (nodemgr->mapBroadcastNodeAPS.count(nodeID) == 0) {
            HCNodeSH nodeSH = nodemgr->getNode(nodeID);
            if (nodeSH && !removedNodes.count(nodeID)) {
                vectNodeSH.push_back(nodeSH);
            }
        }
    }

    //HC: 加入因超时未更新而被删除的节点
    for (auto & elm : removedNodes) {
        HCNodeSH n = make_shared<HCNode>(std::move(CUInt128(elm)));
        vectNodeSH.push_back(n);
    }

    PingPongWithGenBlockHHashTask task(vectNodeSH);
    task.exec();
}

void NodeUPKeepThreadPool::NodePing()
{
    switch (m_pingstate) {
        case pingstate::prepare: {
            PreparePingSet();
            std::set<CUInt128>& pingNodeSet = getPingNodeSet();

            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            if (!pingNodeSet.size() && nodemgr->mapBroadcastNodeAPS.empty()) {
                EmitPingSignal(5);
                break;
            }

            m_pingstate = pingstate::ping1;
            DoPing();

            m_pingstate = pingstate::ping2;
            EmitPingSignal(5);
            break;
        }
        case pingstate::ping2: {
            DoPing();
            m_pingstate = pingstate::check;
            EmitPingSignal(5);
            break;
        }
        case pingstate::check: {
            //HC: 删除ping失败的节点
            //HCE: Delete the node id if it is failed to ping it 
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            std::set<CUInt128>& pingNodeSet = getPingNodeSet();
            for (auto& node : pingNodeSet) {
                nodemgr->EnableNodeActive(node, false);
            }
            pingNodeSet.clear();

            //HCE: after 30 seconds, ping again
            m_pingstate = pingstate::prepare;
            EmitPingSignal(30);
            break;
        }
        default:
            break;
    }
}


void NodeUPKeepThreadPool::EmitPingSignal(int nDelaySecond)
{
    MsgHandler& msgh = Singleton<NodeManager>::getInstance()->GetMsgHandler();
    msgh.registerTimer(nDelaySecond * 1000, std::bind(&NodeUPKeepThreadPool::NodePing, this), true);
}

void NodeUPKeepThreadPool::AddToPingList(const CUInt128 nodeid)
{
    if (Singleton<NodeManager>::getInstance()->getMyNodeId<CUInt128>() == nodeid)
        return;
    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    addNodeSet.insert(nodeid);
}

void NodeUPKeepThreadPool::AddToPingList(vector<CUInt128>& vecNewNode)
{
    auto *nodemgr = Singleton<NodeManager>::getInstance();
    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    for (CUInt128& id : vecNewNode) {
        if(nodemgr->getMyNodeId<CUInt128>() != id)
            addNodeSet.insert(id);
    }
}

void NodeUPKeepThreadPool::RemoveNodeFromPingList(const CUInt128 &nodeid)
{
    std::set<CUInt128>& pingNodeSet = getPingNodeSet();
    pingNodeSet.erase(nodeid);
}

//HC: 定期广播邻居节点信息
//HCE: Broadcast neighbor nodes regularly
void NodeUPKeepThreadPool::BroadcastNeighbor() {
    //HC: 广播邻居节点信息
    BroadcastNeighborTask task;
    task.exec();
}
    
//HC: 对超时没有更新的节点，删除并移出Activenode
//HCE: Remove the nodes that do not update in time out of active node list
set<CUInt128> NodeUPKeepThreadPool::UpdateBroadcastMap() {
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    CUInt128 meNode = nodemgr->getMyNodeId<CUInt128>();

    set<CUInt128> removedNodes;

    auto itr = nodemgr->mapBroadcastNodeAPS.begin();
    int64 now = time(nullptr);
    CUInt128 nodeid;
    for (; itr != nodemgr->mapBroadcastNodeAPS.end(); ) {
        nodeid = itr->first;

        //HC:自己节点不检查
        //HCE: Dont check itself
        if (nodeid == meNode) {
            itr++;
            continue;
        }

        //HCE: Don't check node not active
        if (!nodemgr->IsNodeInKBuckets(nodeid)) {
            itr++;
            continue;
        }

        //HCE: Lan connection needn't check;
        string strNodeAPS = nodemgr->getNode(nodeid)->serializeAP();
        if (strNodeAPS.compare(itr->second.strLanAPS) == 0) {
            removedNodes.insert(itr->first);
            nodemgr->mapBroadcastNodeAPS.erase(itr++);
            continue;
        }

        int timespan = now - itr->second.lasttime;
        if (timespan > 10 * 60) {
            g_console_logger->info("Never connected over {} seconds,remove from active node bucket:{}", timespan, itr->second.strPubAPS);

            nodemgr->GetKBuckets()->RemoveNode(itr->first);     //HC:从Activenode移除
                                                                //HCE: Remove from active node list
            removedNodes.insert(itr->first);
            nodemgr->mapBroadcastNodeAPS.erase(itr++);
        }
        else
            itr++;
    }
    return removedNodes;
}
