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

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"
#include "headers/lambda.h"



class GlobalBuddyHashRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_RSP> {
public:
    using ITask::ITask;
    GlobalBuddyHashRspTask(const CUInt128 fromnode, const CUInt128 tonode, const CUInt128 destnode):
        _fromnode(fromnode), _tonode(tonode), _destnode(destnode){};
    ~GlobalBuddyHashRspTask() {};

    //HCE: Respond to GlobalBuddyHash message task
    //HCE: send the merged listGlobalBuddyChainInfo to send node
    //HCE: @returns void
    void exec() override;

    void execRespond() override;

private:
    CUInt128 _fromnode, _tonode, _destnode;
};

class GlobalBuddyHashRspForwardTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_RSP_FORWARD> {
public:
    using ITask::ITask;
    GlobalBuddyHashRspForwardTask(const CUInt128 destnode, const char* buf, size_t len) :
        _destnode(destnode), _buf(buf, len) {};
    ~GlobalBuddyHashRspForwardTask() {};

    //HCE: Forward GlobalBuddyHashRsp message task
    //HCE: send to requester
    //HCE: @returns void
    void exec() override;

    //HCE: Respond to forward GlobalBuddyHashRsp message task
    //HCE: @returns void
    void execRespond() override;

private:
    CUInt128 _destnode;
    string _buf;
};


class GlobalBuddyHashBlockRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK_RSP> {
public:
    using ITask::ITask;

    GlobalBuddyHashBlockRspTask(const CUInt128 fromnode, const CUInt128 tonode, const CUInt128 destnode, const list< T_LOCALCONSENSUS >& listconsensus) :
        _fromnode(fromnode), _tonode(tonode), _destnode(destnode), _listconsensus(listconsensus) {};
    ~GlobalBuddyHashBlockRspTask() {};

    //HCE: Respond to GlobalBuddyHashBlock message task
    //HCE: send block data to requester
    //HCE: @returns void
    void exec() override;

    //HCE: Respond to respond to GlobalBuddyHashBlock message task
    //HCE: merge the completed solo chain into listGlobalBuddyChainInfo,then send it to requester
    //HCE: @returns void
    void execRespond() override;
    
private:
    CUInt128 _fromnode, _tonode, _destnode;
    list< T_LOCALCONSENSUS > _listconsensus;
};

class GlobalBuddyHashBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_BLOCK> {
public:
    using ITask::ITask;

    GlobalBuddyHashBlockTask(const CUInt128 fromnode, const CUInt128 tonode, const CUInt128 destnode, const list< T_SHA256>& blockhashlist) :
        _fromnode(fromnode),_tonode(tonode), _destnode(destnode), _blockhashlist(blockhashlist) {};

    ~GlobalBuddyHashBlockTask() {};

    //HCE: Send GlobalBuddyHashBlock message task
    //HCE: send hash of uncompleted block to requester
    //HCE: @returns void
    void exec() override;

    //HCE: Respond to GlobalBuddyHashBlock message task
    //HCE: send the block data to requester according to the block hash 
    //HCE: @returns void
    void execRespond() override;

private:
    CUInt128 _fromnode, _tonode, _destnode;
    list< T_SHA256> _blockhashlist;
};

class GlobalBuddyHashForwardTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_FORWARD> {
public:
    using ITask::ITask;
    GlobalBuddyHashForwardTask(const CUInt128 peerid, const char* buf, size_t len) :
        _peerid(peerid), _buf(buf,len) {};

    ~GlobalBuddyHashForwardTask() {};

    //HCE: GlobalBuddyHash message forward task
    //HCE: @returns void
    void exec() override;

    //HCE: Responde to GlobalBuddyHash message forward task
    //HCE: @returns void
    void execRespond() override;

private:
    CUInt128 _peerid;
    string _buf;
};

class GlobalBuddyHashStartTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_START_REQ> {
public:
    using ITask::ITask;

    ~GlobalBuddyHashStartTask() {};

    //HCE: GlobalBuddyHashStart message task
    //HCE: broadcast listLocalBuddyChainInfo, and the block data in it is optimized to hash of the block data
    //HCE: @returns void
    void exec() override;

    //HCE: Responde to GlobalBuddyHashStart message task
    //HCE: @returns void
    void execRespond() override;
};

class GlobalBuddyHashSendTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_HASH_SEND_REQ> {
public:
    using ITask::ITask;

    ~GlobalBuddyHashSendTask() {};

    //HCE: GlobalBuddyHashSend message task
    //HCE: broadcast listGlobalBuddyChainInfo, and the block data in it is optimized to hash of the block data
    //HCE: @returns void
    void exec() override;

    //HCE: Responde to GlobalBuddyHashSend message task
    //HCE: @returns void
    void execRespond() override;
};
