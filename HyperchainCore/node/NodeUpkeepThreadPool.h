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

#include <set>
#include <thread>
#include "ITask.hpp"

using namespace std;
using std::chrono::system_clock;

//HC: 节点维护线程池
//HCE: Node upkeep thread pool
class NodeUPKeepThreadPool
{
public:
    NodeUPKeepThreadPool() = default;
    ~NodeUPKeepThreadPool() { stop(); }

    void start();
    void stop();

    //HCE: Add a node id to pinglist
    //HCE: @para nodeid Node id
    void AddToPingList(const CUInt128 nodeid);

    //HCE: Add a vector of node id to pinglist
    //HCE: @para vecNewNode Node id vector
    void AddToPingList(vector<CUInt128>& vecNewNode);   //HC：K桶里被挤走的节点进入Ping列表
                                                        //HCE: Put nodes not in KBucket into ping list
    //HCE: Remove a node id from pinglist
    //HCE: @para nodeid Node id
    void RemoveNodeFromPingList(const CUInt128& nodeid);

    //HCE: Ping to nodes in nodelist
    void NodePing();

    void NodeFind();

	//HC: 定期广播邻居节点信息
    //HCE: Broadcast neighbor nodes infomation regularly
    void BroadcastNeighbor();

private:

    //HCE: Init pulllist,put the nodes in _nodemap into pulllist first
    void InitPullList();

    //HCE: Prepare pulllist
    void PreparePullList();

    std::set<CUInt128>& getPingNodeSet();
    std::set<CUInt128>& getAddNodeSet();

    //HCE: Prepare ping node set
    void PreparePingSet();

    //HCE: Start ping task using ping list
    void DoPing();

    //HCE: Start NodePing after nDelaySecond 
    void EmitPingSignal(int nDelaySecond);

    //HCE: Update broadcast node list.Remove the nodes that do not update in time out of active node list
    std::set<CUInt128> UpdateBroadcastMap();

    std::list<CUInt128> m_lstPullNode;

    //HC: 一个集合用于ping，一个集合添加节点，到ping的时候切换
    //HCE: a set to ping, a set to add nodes, and switch when ping start
    bool                m_pingSecSet;
    std::set<CUInt128> m_setPingNode1;
    std::set<CUInt128> m_setPingNode2;

    enum class pingstate : char {
        prepare,
        ping1,
        ping2,
        check,
    };
    pingstate m_pingstate = pingstate::prepare;
};
