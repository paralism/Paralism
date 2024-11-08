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

#include <ctime>

#include "newLog.h"
#include "NodeManager.h"
#include "../db/dbmgr.h"
#include "../util/common.h"
#include "NodeUpkeepThreadPool.h"
#include "Singleton.h"
#include "ITask.hpp"
#include "UdpAccessPoint.hpp"
#include "SearchNeighbourTask.h"
#include "PingPongTask.h"
#include "PingPongWithGenBlockHHashTask.hpp"

#include <cpprest/json.h>
using namespace web;
ProtocolVer pro_ver = 0;
T_SHA256 genesis_block_header_hash = T_SHA256(0);

NodeManager::NodeManager() : _me(make_shared<HCNode>())
{
}

void NodeManager::startMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&NodeManager::DispatchService, this, std::placeholders::_1, std::placeholders::_2);

    _msghandler.registerWorker(NODE_SERVICE, fwrk);
    _msghandler.registerTaskWorker(NODE_T_SERVICE);

    _msghandler.registerTimer(1000 * 5 * 60, std::bind(&NodeManager::SaveLastActiveNodesToDB, this));

    NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();
    //HC: 程序启动后延时10秒获取邻居
    //HCE: Delay 10 seconds to get neighbor nodes after the program start
    _msghandler.registerTimer(10 * 1000, std::bind(&NodeUPKeepThreadPool::NodeFind, nodeUpkeep), true);

    //HC: 每间隔5min获取邻居
    //HCE: Get neighbor nodes every 5 min
    _msghandler.registerTimer(300 * 1000, std::bind(&NodeUPKeepThreadPool::NodeFind, nodeUpkeep));

    _msghandler.registerTimer(12 * 1000, std::bind(&NodeUPKeepThreadPool::NodePing, nodeUpkeep), true);

    _msghandler.registerTaskType<SearchNeighbourTask>(TASKTYPE::SEARCH_NEIGHBOUR);
    _msghandler.registerTaskType<SearchNeighbourRspTask>(TASKTYPE::SEARCH_NEIGHBOUR_RSP);
    _msghandler.registerTaskType<ActiveNodeTask>(TASKTYPE::ACTIVE_NODE);
    _msghandler.registerTaskType<PingPongTask>(TASKTYPE::PING_PONG);
    _msghandler.registerTaskType<PingPongRspTask>(TASKTYPE::PING_PONG_RSP);
    _msghandler.registerTaskType<PingPongWithGenBlockHHashTask>(TASKTYPE::PING_PONG_WITH_GENHHASH);
    _msghandler.registerTaskType<PingPongWithGenBlockHHashRspTask>(TASKTYPE::PING_PONG_WITH_GENHHASH_RSP);
    _msghandler.registerTaskType<BroadcastNeighborTask>(TASKTYPE::BROADCAST_NEIGHBOR);

    NODESERVICEForEach([this](NODESERVICE i) {
        m_actioncoststt.AddAction((int32_t)i, NODESERVICEValueName(i));
        });


    //HC: 定周期广播邻居节点信息
    //HCE: Broadcast neighbor nodes in fix circle 
    _msghandler.registerTimer(60 * 1000, std::bind(&NodeUPKeepThreadPool::BroadcastNeighbor, nodeUpkeep));

    _msghandler.enableStatis(true);

    _msghandler.start("NodeManager");
    cout << "NodeManager MQID: " << MQID() << endl;
}

void NodeManager::DispatchService(void* wrk, zmsg* msg)
{
    HCMQWrk* realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();
    string u = msg->pop_front();

    int service_t = 0;
    memcpy(&service_t, u.c_str(), sizeof(service_t));

    auto acss = m_actioncoststt.NewStatt(service_t);

    switch ((NODESERVICE)service_t) {
    case NODESERVICE::ToAllNodes: {

        string data = msg->pop_front();
        ToAllNodes(data);

        //HCE: no respond to client
        return;
    }
    case NODESERVICE::ToNodes: {
        string data;
        std::set<CUInt128>* pnodes = nullptr;
        bool isincluded;

        MQMsgPop(msg, data, pnodes, isincluded);
        ToNodes(data, *pnodes, isincluded);
        return;
    }
    case NODESERVICE::UpdateNode: {

        string strnodeid;
        string ip;
        uint32_t port;
        MQMsgPop(msg, strnodeid, ip, port);

        CUInt128 nodeid(strnodeid);
        updateNode(nodeid, ip, port);

        //HCE: no respond to client
        return;
    }
    case NODESERVICE::GetNodesJson: {

        vector<string> *pvecNodes = nullptr;
        MQMsgPop(msg, pvecNodes);
        size_t r = GetNodesJson(*pvecNodes);
        MQMsgPush(msg, r);
        break;
    }

    case NODESERVICE::ParseNode: {

        string node;
        UdpAccessPoint *ap = nullptr;
        MQMsgPop(msg, node, ap);

        bool ret = parseNode(node, ap);
        MQMsgPush(msg, ret);

        break;
    }
    case NODESERVICE::ParseNodeList: {

        string nodes;
        vector<CUInt128> *pvecNewNode = nullptr;
        MQMsgPop(msg, nodes, pvecNewNode);

        ParseNodeList(nodes, *pvecNewNode);
        break;
    }
    case NODESERVICE::GetNodeAP: {

        CUInt128 *pnodeid = nullptr;
        UdpAccessPoint *ap = nullptr;
        MQMsgPop(msg, pnodeid, ap);

        bool ret = getNodeAP(*pnodeid, ap);

        MQMsgPush(msg, ret);

        break;
    }
    case NODESERVICE::EnableNodeActive: {
        CUInt128 *pnodeid = nullptr;
        bool bEnable = false;
        MQMsgPop(msg, pnodeid, bEnable);

        EnableNodeActive(*pnodeid, bEnable);
        break;
    }
    case NODESERVICE::GetNodeMapNodes: {
        vector<CUInt128> *pvecNodes = nullptr;
        MQMsgPop(msg, pvecNodes);

        GetNodeMapNodes(*pvecNodes);
        break;
    }

    case NODESERVICE::ToFormatString: {
        string info = toFormatString();
        MQMsgPush(msg, info);
        break;
    }

    case NODESERVICE::PickNeighbourNodes: {
        CUInt128 *pnodeid = nullptr;
        int num = 0;
        vector<CUInt128> *pvnodes = nullptr;
        MQMsgPop(msg, pnodeid, num, pvnodes);
        PickNeighbourNodes(*pnodeid, num, *pvnodes);
        break;
    }

    case NODESERVICE::PickNeighbourNodesEx: {
        CUInt128* pnodeid = nullptr;
        int num = 0;
        vector<HCNode>* pvnodes = nullptr;
        MQMsgPop(msg, pnodeid, num, pvnodes);
        PickNeighbourNodesEx(*pnodeid, num, *pvnodes);
        break;
    }

    case NODESERVICE::IsNodeInKBuckets: {

        CUInt128 *pnodeid = nullptr;
        MQMsgPop(msg, pnodeid);
        bool ret = IsNodeInKBuckets(*pnodeid);
        MQMsgPush(msg, ret);
        break;
    }
    case NODESERVICE::GetAllNodes: {
        std::set<CUInt128> *psetNodes = nullptr;

        MQMsgPop(msg, psetNodes);
        GetAllNodes(*psetNodes);
        break;
    }
    case NODESERVICE::PickRandomNodes: {
        int nNum;
        std::set<HCNode> *pnodes = nullptr;

        MQMsgPop(msg, nNum, pnodes);
        PickRandomNodes(nNum, *pnodes);
        break;
    }
    case NODESERVICE::GetNodesNum: {
        int ret = 0;
        ret = GetNodesNum();
        MQMsgPush(msg, ret);
        break;
    }
    case NODESERVICE::SendTo: {

        string targetnodeid;
        string msgbuf;
        MQMsgPop(msg, targetnodeid, msgbuf);

        sendToHlp(targetnodeid, msgbuf);

        //HCE: no respond to client
        return;
    }
    case NODESERVICE::UpdateMyself: {
        std::map<string, T_APPTYPE>* pnodeApps = nullptr;
        MQMsgPop(msg, pnodeApps);
        UpdateMyself(*pnodeApps);
    }
    case NODESERVICE::MQCostStatistics: {
        string info = GetMQCostStatistics();
        MQMsgPush(msg, info);
        break;
    }
    default:
        //HCE: throw it
        return;
    }
    realwrk->reply(reply_who, msg);
}

void NodeManager::UpdateMyself(const std::map<string, T_APPTYPE>& nodeApps)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        //onNodePropertiesChanged();
        _me->updateLocalChains(nodeApps);
    }
    else {
        zmsg* rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::UpdateMyself, &nodeApps);
        if (rspmsg) {
            delete rspmsg;
        }
    }

}

void NodeManager::ToAllNodes(const string& data)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        std::set<CUInt128> Nodes = m_actKBuchets.GetAllNodes();
        for (CUInt128 nodeID : Nodes) {
            if (_nodemap.count(nodeID)) {
                _nodemap[nodeID]->send(data);
            }
        }
    } else {
        MQRequestNoWaitResult(NODE_SERVICE, (int)NODESERVICE::ToAllNodes, data);
    }
}

void NodeManager::ToNodes(const string& data, const set<CUInt128> &nodes, bool nodesisincluded)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        std::set<CUInt128> Nodes = m_actKBuchets.GetAllNodes();
        for (CUInt128 nodeID : Nodes) {
            if (_nodemap.count(nodeID)) {
                if (nodesisincluded && nodes.count(nodeID)) {
                    _nodemap[nodeID]->send(data);
                    continue;
                }

                if (!nodesisincluded && !nodes.count(nodeID)) {
                    _nodemap[nodeID]->send(data);
                }
            }
        }
    } else {
        zmsg* rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::ToNodes, data, &nodes, nodesisincluded);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


int NodeManager::GetNodesNum()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_actKBuchets.GetNodesNum();
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::GetNodesNum);

        int ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }

}

void NodeManager::PickRandomNodes(int nNum, std::set<HCNode> &nodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        set<CUInt128> nodeIDs;
        nodeIDs = m_actKBuchets.PickRandomNodes(nNum);
        for (auto& id : nodeIDs) {
            HCNodeSH n = getNode(id);
            if (n) {
                nodes.insert(*n);
            }
        }
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::PickRandomNodes, nNum, &nodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }

}

void NodeManager::GetAllNodes(std::set<CUInt128> &setNodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        setNodes = m_actKBuchets.GetAllNodes();
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::GetAllNodes, &setNodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool NodeManager::IsNodeInKBuckets(const CUInt128 &nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_actKBuchets.IsNodeInKBuckets(nodeid);
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::IsNodeInKBuckets, &nodeid);
        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

void NodeManager::PickNeighbourNodes(const CUInt128 &nodeid, int num, vector<CUInt128> &vnodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        vnodes = m_actKBuchets.PickNeighbourNodes(nodeid, num);
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::PickNeighbourNodes, &nodeid, num, &vnodes);

        if (rspmsg) {
            delete rspmsg;
        }
    }
}


void NodeManager::PickNeighbourNodesEx(const CUInt128& nodeid, int num, vector<HCNode> &vnodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        vector<CUInt128> vnodeIDs;
        vnodeIDs = m_actKBuchets.PickNeighbourNodes(nodeid, num);
        for (auto &id : vnodeIDs) {
            HCNodeSH n = getNode(id);
            if (n) {
                vnodes.push_back(*n);
            }
        }
    } else {
        zmsg* rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::PickNeighbourNodesEx, &nodeid, num, &vnodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

HCNodeSH NodeManager::getNode(const CUInt128 &nodeid)
{
    if (!_nodemap.count(nodeid)) {
        //return null node
        HCNodeSH no;
        return no;
    }
    return _nodemap[nodeid];
}



const HCNodeMap* NodeManager::getNodeMap()
{
    return &_nodemap;
}

size_t NodeManager::getNodeMapSize()
{
    return _nodemap.size();
}

void NodeManager::addNode(HCNodeSH & node)
{
    _nodemap[node->getNodeId<CUInt128>()] = node;
}


void NodeManager::updateNode(const CUInt128 &nodeid, const string &ip, uint32_t port)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        HCNodeSH neighborNode;
        if (_nodemap.count(nodeid)) {
            neighborNode = _nodemap[nodeid];
            string currip;
            int currport = 0;
            if (neighborNode->getUDPAP(currip, currport)) {
                if (port != currport || currip != ip) {
                    neighborNode->updateAP(std::make_shared<UdpAccessPoint>(ip, port));
                }
            }
        } else {
            HCNodeSH neighborNode = std::make_shared<HCNode>(std::move(CUInt128(nodeid)));
            neighborNode->addAP(std::make_shared<UdpAccessPoint>(ip, port));
            addNode(neighborNode);
        }

        /*
        CUInt128 id = neighborNode->getNodeId<CUInt128>();
        if (_nodemap.count(id)) {
            auto& n = _nodemap[id];
            HCNode::APList& aplist = neighborNode->getAPList();
            for (auto& ap : aplist) {
                n->updateAP(ap);
            }
        }
        else {
            addNode(neighborNode);
        }*/
    }
    else {
        string strnodeid = nodeid.ToHexString();
        MQRequestNoWaitResult(NODE_SERVICE, (int)NODESERVICE::UpdateNode, strnodeid, ip, port);
    }
}

size_t NodeManager::GetNodesJson(vector<string>& vecNodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        vecNodes.resize(_nodemap.size());
        auto iter = _nodemap.begin();
        for (int i = 0; iter != _nodemap.end(); iter++, i++) {
            vecNodes[i] = iter->second->serialize();
        }
        return vecNodes.size();
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::GetNodesJson, &vecNodes);

        size_t ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

void NodeManager::loadMyself()
{
    DBmgr *pDb = Singleton<DBmgr>::instance();

    pDb->query("SELECT * FROM myself;",
        [this](CppSQLite3Query & q) {
            string id = q.getStringField("id");
            string aps = q.getStringField("accesspoint");

            _me->setNodeId(id);
            _me->parseAP(aps);
        });
}

bool NodeManager::RemoveMyself()
{
    DBmgr* pDb = Singleton<DBmgr>::instance();
    return pDb->exec("delete from myself;") > 0;
}

void NodeManager::saveMyself()
{
    int num = 0;
    DBmgr *pDb = Singleton<DBmgr>::instance();

    pDb->query("SELECT count(*) as num FROM myself;",
        [this, &num](CppSQLite3Query & q) {
            num = q.getIntField("num");
        });

    if (num > 0) {
        pDb->exec("delete from myself;");
    }
    pDb->exec("insert into myself(id,accesspoint) values(?,?);",
        _me->getNodeId<string>().c_str(),
        _me->serializeAP().c_str());
}


string NodeManager::toFormatString()
{
    ostringstream oss;

    if (_msghandler.getID() == std::this_thread::get_id()) {

        std::set<CUInt128> setResult = m_actKBuchets.GetAllNodes();
        for (CUInt128 nodeID : setResult) {
            if (_nodemap.count(nodeID)) {
                oss << "\t" << _nodemap[nodeID]->serialize() << endl;
            }
        }
        oss << "Total number: " << setResult.size() << endl;

        if (oss.str().empty()) {
            oss.str("\n\tempty");
        }
        return oss.str();
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::ToFormatString);

        string ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}


std::string NodeManager::GetMQCostStatistics()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        ostringstream oss;
        oss << m_actioncoststt.Statistics("NodeManager MQ cost statistics: ");
        oss << endl;
        oss << _msghandler.getStatistics("NodeManager Task cost statistics: ");
        return oss.str();
    } else {
        zmsg* rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::MQCostStatistics);

        string ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

bool NodeManager::getNodeAP(const CUInt128 &nodeid, UdpAccessPoint *ap)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (_nodemap.count(nodeid) > 0) {
            string ip;
            int nport = 0;
            if (_nodemap[nodeid]->getUDPAP(ip, nport)) {
                *ap = UdpAccessPoint(ip, nport);
                return true;
            }
        }
        return false;
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::GetNodeAP, &nodeid, ap);

        bool ret = false;

        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

bool NodeManager::parseNode(const string &node, UdpAccessPoint *ap)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        json::value obj = json::value::parse(s2t(node));

        string objstr = t2s(obj.serialize());
        auto n = make_shared<HCNode>();

        HCNode::parse(objstr, *n.get());

        _nodemap[n->getNodeId<CUInt128>()] = n;

        HCNode::APList &aplist = n->getAPList();
        UdpAccessPoint udppoint("127.0.0.1", 0);
        auto ret = std::find_if(aplist.begin(), aplist.end(), [&](const HCNode::APList::reference apCurr) {
            if (apCurr->id() == udppoint.id()) {
                *ap = *(dynamic_cast<UdpAccessPoint*>(apCurr.get()));
                return true;
            }
            return false;
            });

        if (ret == std::end(aplist)) {
            //HCE: cannot find udp access point
            return false;
        }
        return true;
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::ParseNode, node, ap);

        bool ret = false;

        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}


bool NodeManager::IsSeedServer(const HCNode & node)
{
    for (auto &ss : _seeds) {
        if (ss->getNodeId<CUInt128>() == node.getNodeId<CUInt128>())
            return true;

        //HCE: Here is lowly efficient, should improve in the future.
        string ap = ss->serializeAP();
        if (!ap.empty() && 0 == ap.compare(node.serializeAP())) {
            return true;
        }
    }

    return false;
}


/////////////////////////////
/////////////////////////////
void NodeManager::InitKBuckets()
{
    m_actKBuchets.InitKbuckets(_me->getNodeId<CUInt128>());
}

void NodeManager::PushToKBuckets(const CUInt128 &nodeid)
{
    CUInt128 idRemove;
    bool bret = m_actKBuchets.AddNode(nodeid, idRemove);
    if (!bret)
    {
        //HC: 放到ping测试
        //HCE: put to ping test
        NodeUPKeepThreadPool* nodeUpkeepThreadpool = Singleton<NodeUPKeepThreadPool>::instance();
        nodeUpkeepThreadpool->AddToPingList(idRemove);
    }
}


//HC: 分析返还的节点列表值，记录到_nodemap， 同时提取出新节点，用于Ping测试
//HCE: Parse the return node list, record to nodemap and draw the new nodes to ping test
void NodeManager::ParseNodeList(const string &nodes, vector<CUInt128> &vecNewNode)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (nodes == "")
            return;
        json::value obj = json::value::parse(s2t(nodes));

        if (!obj.is_array()) {
            return;
        }

        size_t num = obj.size();

        for (size_t i = 0; i < num; i++) {
            string objstr = t2s(obj[i].serialize());

            auto n = make_shared<HCNode>();
            HCNode::parse(objstr, *n.get());

            auto id = n->getNodeId<CUInt128>();
            vecNewNode.push_back(id);

            //HCE: in any case here should update into map
            addNode(n);
        }
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::ParseNodeList, nodes, &vecNewNode);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


void NodeManager::AddToDeactiveNodeList(const CUInt128& nodeid)
{
    auto iter = m_lstDeactiveNode.begin();
    for (; iter != m_lstDeactiveNode.end(); iter++)
    {
        if (iter->m_id == nodeid)
        {
            m_lstDeactiveNode.erase(iter);
            break;
        }
    }
    m_lstDeactiveNode.push_back(CKBNode(nodeid));

    //HC: 超过一定数量(100个)就保存50个到数据库
    //HCE: Save 50 to db if over 100
    if (m_lstDeactiveNode.size() > 100)
    {
        int nNum = 0;
        while (nNum < 50 && !m_lstDeactiveNode.empty())
        {
            CKBNode nodeT = m_lstDeactiveNode.front();
            m_lstDeactiveNode.pop_front();
            if (SaveNodeToDB(nodeT.m_id, nodeT.m_lastTime))
                nNum++;
        }
    }
}

void NodeManager::RemoveNodeFromDeactiveList(const CUInt128 &nodeid)
{
    for (auto iter = m_lstDeactiveNode.begin(); iter != m_lstDeactiveNode.end(); iter++)
    {
        if (iter->m_id == nodeid)
        {
            m_lstDeactiveNode.erase(iter);
            break;
        }
    }
}

bool NodeManager::SaveNodeToDB(const CUInt128 &nodeid, system_clock::time_point  lastActTime)
{
    //HCE: Before call this function, make sure has already gotten lock for _nodemap by upper layer
    if (!_nodemap.count(nodeid))
        return false;

    HCNodeSH& nodeSH = _nodemap[nodeid];
    if (!nodeSH->isValid())
        return false;

    std::time_t lasttime = system_clock::to_time_t(lastActTime);

    //HC: 注意更新时间
    //HCE: Notice update time
    DBmgr *pDb = Singleton<DBmgr>::instance();

    int num = 0;
    pDb->query("SELECT count(*) as num FROM neighbornodes where id=?;",
        [this, &num](CppSQLite3Query & q) {
            num = q.getIntField("num");
        }, nodeid.ToHexString().c_str());

    if (num > 0) {
        pDb->exec("update neighbornodes set accesspoint = ?,lasttime=? where id=?;",
            nodeSH->serializeAP().c_str(),
            lasttime,
            nodeSH->getNodeId<string>().c_str());
    } else {
        pDb->exec("insert into neighbornodes(id,accesspoint,lasttime) values(?,?,?);",
            nodeSH->getNodeId<string>().c_str(),
            nodeSH->serializeAP().c_str(),
            lasttime);
    }

    return true;
}

void NodeManager::loadNeighbourNodes_New()
{
    //HC: 按最后活跃时间调入节点列表
    //HCE: Load node list according to the last active time
    DBmgr *pDb = Singleton<DBmgr>::instance();

    pDb->query("SELECT * FROM neighbornodes ORDER BY lasttime DESC limit 32;",
        [this](CppSQLite3Query & q) {
            string id = q.getStringField("id");
            string aps = q.getStringField("accesspoint");

            CUInt128 nodeid(id);
            HCNodeSH node = make_shared<HCNode>(std::move(nodeid));
            node->parseAP(aps);
            _nodemap[CUInt128(id)] = node;
        });
}

void NodeManager::GetNodeMapNodes(vector<CUInt128>& vecNodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        HCNodeMap::iterator iter;
        for (iter = _nodemap.begin(); iter != _nodemap.end(); iter++) {
            CUInt128 nodeID = iter->first;
            vecNodes.push_back(nodeID);
        }
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::GetNodeMapNodes, &vecNodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void NodeManager::EnableNodeActive(const CUInt128 &nodeid, bool bEnable)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (bEnable) {
            if (_me->getNodeId<CUInt128>() != nodeid) {
                PushToKBuckets(nodeid);
            }
            RemoveNodeFromDeactiveList(nodeid);
        } else {
            GetKBuckets()->RemoveNode(nodeid);
            if (_me->getNodeId<CUInt128>() != nodeid) {
                AddToDeactiveNodeList(nodeid);
            }
        }
    } else {
        zmsg *rspmsg = MQRequest(NODE_SERVICE, (int)NODESERVICE::EnableNodeActive, &nodeid, bEnable);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void NodeManager::SaveLastActiveNodesToDB()
{
    system_clock::time_point curr = system_clock::now();

    int nMinutes = 5;

    //HC: 产生随机ID, 获取距离最近的ID集合存储
    //HCE: Generate random ID and save the nearest node id to db
    string str = HCNode::generateNodeId();
    vector<CUInt128> vecResult = m_actKBuchets.PickLastActiveNodes(CUInt128(str), 10, nMinutes);
    if (!vecResult.empty()) {
        for (CUInt128 nodeID : vecResult)
            SaveNodeToDB(nodeID, curr);
    }
}

int NodeManager::getPeerList(CUInt128 excludeID, vector<CUInt128>& vecNodes, string & peerlist)
{
    int nNum = vecNodes.size();
    json::value obj = json::value::array();
    int k = 0;
    for (int i = 0; i < nNum; i++)
    {
        CUInt128 id = vecNodes[i];
        if (id != excludeID)
        {
            HCNodeSH node = _nodemap[id];// getNode(id);
            obj[k] = json::value::parse(s2t(node->serialize()));
            k++;
        }
    }
    if (k > 0)
    {
        std::stringstream oss;
        obj.serialize(oss);
        peerlist = std::move(oss.str());
    } else
        peerlist = "";
    return k;
}
