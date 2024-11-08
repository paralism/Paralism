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

#include "util/MutexObj.h"
#include "node/MsgHandler.h"
#include "crosschaintx.h"


#include <thread>
#include <memory>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
using namespace std;

enum class ONCHAINSTATUS :char {
    queueing,       //HC: 排队上链中
                    //HCE: on chain queueing
    onchaining1,    //HCE: local consensus
    onchaining2,    //HCE: global consensus
    onchained,      //HC: 刚刚完成上链，in mapSearchOnChain
                    //HCE: just on chained, in mapSearchOnChain
    matured,        //HC: 成熟，指几个共识周期（MATURITY_TIME秒）后，如果依然存在，表示成熟，这样发生分叉被刷下的可能性很小
                    //HCE: matured means the block still exits after several consensus cycles.
    nonexistent,    //HC: 未上过链
                    //HCE: never on chained
    failed,         //HC: 上链失败
                    //HCE: failed to on chain
    unknown,        //HCE: system internal error
    pending,        //HC: 批量上链数据，等待提交到共识层
                    //HCE: batch on chained,wait for submitting to consensus layer
};

class HCMQWrk;
class zmsg;

struct _tp2pmanagerstatus;

typedef struct
{
    string hashMTRoot;          //HC: 交易merkle树根hash
                                //HCE: hash of the root of the merkle tree                               
    vector<string> vecMT;       //HC: 每一笔交易的Hash
                                //HCE: hash of every transaction
    string payload;             //HC: 块数据
                                //HCE: payload
    CUInt128 nodeid;            //HC: 块创建节点nodeid
                                //HCE: id of the node creats the block
} PostingBlock;


class ConsensusEngine {
public:
    //HCE: Constructor function
    ConsensusEngine();

    //HCE: Destructor function
    ~ConsensusEngine();

    //HCE: Start consensus engine module
    //HCE: @returns void
    void start();

    //HCE: Stop consensus engine module
    //HCE: @returns void
    void stop();

    void requestStop() {
        _is_user_request_exit = true;
    }

    bool isRequestStop() {
        return _is_user_request_exit;
    }

    std::string MQID()
    {
        return _msghandler.details();
    }

    //HCE: start test thread which auto creates local block and does consensus
    void startTest() {
        if (_testthread) {
            return;
        }
        _isstoptest = false;
        _testthread.reset(new thread(&ConsensusEngine::TestOnchain, this));
    }
    void stopTest() {
        _isstoptest = true;
        if (!_testthread) {
            return;
        }
        if (_testthread->joinable()) {
            _testthread->join();
        }
        _testthread.release();
    }

    bool IsTestRunning() {
        if (_testthread) {
            return true;
        }
        return false;
    }

    //HCE: Create a new block and add the block to request on chain queue
    //HCE: @param data Data to create a new block
    //HCE: @param requestid ID of the request node
    //HCE: @param nOrder The size of the request on chain queue
    //HCE: @returns True if success.
    bool AddNewBlockEx(const SubmitData& data, string& requestid, uint32& nOrder, string& excp_desc);

    //HCE: Build a block chain and add the block chain into the global chain container
    //HCE: @param app App type
    //HCE: @param postingchain The vector of on chain data
    //HCE: @returns the number of block on chained.
    uint32 AddChainEx(const T_APPTYPE& app, vector<PostingBlock>& postingchain);

    bool IsParaAppLoaded();

    //HCE: Register call back App
    //HCE: @para app App type
    //HCE: @para notify CONSENSUSNOTIFY
    //HCE: @returns void
    void RegisterAppCallback(const T_APPTYPE& app, const CONSENSUSNOTIFY& notify);

    //HCE: Unregister call back App
    //HCE: @para app App type
    //HCE: @returns void
    void UnregisterAppCallback(const T_APPTYPE& app);

    //HCE: Get details of current consensus 
    //HCE: @returns void
    ONCHAINSTATUS GetOnChainState(const LB_UUID& requestId, size_t& queuenum);

    //HCE: Check if the on chain request is in mapSearchOnChain
    //HCE: @para requestId On chain request ID 
    //HCE: @para addr Block address 
    //HCE: @returns True if find in mapSearchOnChain
    bool CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr);

    //HCE: Send global buddy request
    //HCE: @returns void
    uint GetStateOfCurrentConsensus(uint64& blockNo, uint16& blockNum, uint16& chainNum);

    //HCE: Get details of current consensus 
    //HCE: @returns void
    void GetDetailsOfCurrentConsensus(size_t& reqblknum,
        size_t& rspblknum,
        size_t& reqchainnum,
        size_t& rspchainnum,
        size_t& localchainBlocks,
        LIST_T_LOCALCONSENSUS* localbuddychaininfos,
        size_t& globalbuddychainnum);

    //HCE: Dispatch a message to the corresponding service to handle
    //HCE: @para *wrk Pointer to class HCMQWrk
    //HCE: @returns void
    void InitOnChainingState(uint64_t blockid);

    //HCE: Handle the on chain state of a block 
    //HCE: @para blockid block ID to handle
    //HCE: @returns void
    void RehandleOnChainingState(uint64_t blockid);

    bool IsAbleToConsensus() { return _is_able_to_consensus; }

    //HC: 计算本节点是否是共识链上最后一个节点如果是则负责创建超块
    //HCE: Check if the node is end node. If it is,it will create hyper block
    //HCE: @returns True if it is end node
    bool IsEndNode();

    //HCE: Check if there is a buddy in listCurBuddyRsp is confirming
    //HCE: @para currBuddyHash Hash of the buddy is confirming
    //HCE: @returns True if there is
    bool IsConfirming(string& currBuddyHash);

    //HCE: Make buddy
    //HCE: @para confirmhash String of confirm hash
    //HCE: @returns True if making buddy success
    bool MakeBuddy(const string& confirmhash);

    //HCE: Put blocks into consensus list: listLocalBuddyChainInfo
    //HCE: @para buddyinfostate T_BUDDYINFOSTATE data
    //HCE: @returns void
    void PutIntoConsensusList(T_BUDDYINFOSTATE& buddyinfostate);

    //HCE: Merge a buddy into the global buddy chain
    //HCE: @para listLocalBuddyChainInfo A buddy to be merged
    //HCE: @returns True if success
    bool MergeToGlobalBuddyChains(LIST_T_LOCALCONSENSUS& listLocalBuddyChainInfo);

    //HCE: Check pay load datas in local block list
    //HCE: @para localList local block list
    //HCE: @returns True if they are valid
    bool CheckPayload(LIST_T_LOCALCONSENSUS& localList);

    //HCE: Verify if there is a block is making buddy in listCurBuddyReq or listCurBuddyRsp
    //HCE: @returns True if there is
    bool IsMakeBuddy();

    struct _tp2pmanagerstatus* GetConsunsusState()
    {
        return _tP2pManagerStatus;
    }

    int64 _onchaindatasize;
    static int64 GetConsensusCircle() {
        return (time(nullptr) / NEXTBUDDYTIME);
    }

    std::pair<bool, string> CheckCrossChainTx(uint32_t hid,         //HCE: hyper block id where genesis block of local block is located
        uint16_t chainid,
        uint16_t localid,
        const vector<unsigned char>& hhash,                         //HCE: the last 20 bytes of hyper block hash
        const vector<unsigned char>& genesis_block_hash             //HCE: Hash of genesis block of target local chain
        );

    std::pair<bool, string> CreateTxOnTargetChain(uint32_t hid,         //HCE: hyper block id where genesis block of local block is located
        uint16_t chainid,
        uint16_t localid,
        const vector<unsigned char>& hhash,                         //HCE: the last 20 bytes of hyper block hash
        const vector<unsigned char>& genesis_block_hash,            //HCE: Hash of genesis block of target local chain
        const vector<unsigned char>& recv_address);

    string Swap2Eth(const string& fromaddress,
        const string& chainaddress,
        const string& amount,
        const string& accountaddress,
        const string& name);

    std::string Swap2Para(const string& fromaddress,
        const string& paraaddress,
        const string& amount,
        const string& name);

    std::string Swap(const string& action,
        const string& param1,
        const string& param2);

private:

    //HCE: Handle the first buddy in listRecvLocalBuddyReq on LOCALBUDDY_PHASE
    //HCE: @returns void
    void LocalBuddyReq();

    //HCE: Handle the first buddy in listRecvLocalBuddyRsp on LOCALBUDDY_PHASE
    //HCE: @returns void
    void LocalBuddyRsp();

    //HCE: Check the state of blocks in mapSearchOnChain
    //HCE: Blocks will be delete if it's matured and not in consensus nos.
    //HCE: @returns void
    void SearchOnChainState();

    //HCE: Check if there is a new version
    //HCE: @returns void
    void CheckMyVersionThread();

    //HCE: Create genesis block,block id is 0,previous hyper block id is -1
    //HCE: @returns void
    void CreateGenesisBlock();

    //HCE: Send local buddy request
    //HCE: @returns void
    void SendLocalBuddyReq();

    //HCE: Process on chain response message which is defined as P2pProtocolOnChainRspRecv type
    //HCE: @para peerid Node id
    //HCE: @pBuf A char buffer contains a P2pProtocolOnChainRspRecv data
    //HCE: @uiBufLen Size of pBuf
    //HCE: @returns void
    void ProcessOnChainRspMsg(const CUInt128& peerid, char* pBuf, size_t uiBufLen);

    //HCE: Start global buddy
    //HCE: @returns void
    void StartGlobalBuddy();

    //HCE: Send global buddy request
    //HCE: @returns void
    void SendGlobalBuddyReq();

    //HCE: Hyper block updated
    //HCE: @para sock Pointer to socket
    //HCE: @para msg Pointer to zmsg
    //HCE: @returns Void
    void HyperBlockUpdated(void* sock, zmsg* msg);

    //HCE: Asynchronous update Hyper block
    //HCE: @para h Hyper block
    //HCE: @returns Void
    void AsyncHyperBlockUpdated(const T_HYPERBLOCK& h);

    //HCE: Check consensus condition
    //HCE: @returns True if condition is ok.
    bool CheckConsensusCond();

    //HCE: Generate simulate data and create a test block on chain 
    //HCE: @returns void
    void TestOnchain();

    //HCE: Prepare local buddy
    //HCE: @returns void
    void PrepareLocalBuddy();

    //HC: 块数据是否上链成功，如果不成功下个共识周期继续上链
    //HC: 如果上链成功，清空上链数据链表
    //HC: TO DO: 这里不完善需要改进，未考虑分叉情况,一旦分叉上链的结果可能完全不同。
    //HCE: Check if the block is on chained.If it is not successful to on chain,the block will continue to on chain in next consensus cycle
    //HCE: If it is on chained successfully,clear the block in listLocalBuddyChainInfo
    //HCE: TO DO: Here needs to be improved because the branching situation can not be considered. The result would be totally different when branching accured.
    //HCE: @para h Hyperchain block
    //HCE: @returns Void
    void UpdateMyBuddyBlock(const T_HYPERBLOCK& h);

    //HCE: On chain try again
    //HCE: @returns void
    void ReOnChainFun();

    //HCE: Get on chain infomation
    //HCE: @returns void
    void GetOnChainInfo();

    //HCE: Try to create hyper block
    //HCE: @returns void
    void TryCreateHyperBlock();

    //HCE: Create hyper block
    //HCE: @para tHyperBlock hyper block
    //HCE: @returns True if success
    bool CreateHyperBlock(T_HYPERBLOCK& tHyperBlock);

    //HCE: Start message queue handlers
    //HCE: @returns void
    void StartMQHandler();

    //HCE: Dispatch a message to the corresponding service to handle
    //HCE: @para *wrk Pointer to class HCMQWrk
    //HCE: @para *msg Pointer to a message to be handled
    //HCE: @returns void
    void DispatchService(void* wrk, zmsg* msg);

    //HCE: Dispatch consensus process according to four consensus phases
    //HCE: The four phases is PREPARE_LOCALBUDDY_PHASE,LOCALBUDDY_PHASE,GLOBALBUDDY_PHASE and PERSISTENCE_CHAINDATA_PHASE
    //HCE: @returns void
    void DispatchConsensus();

    //HCE: Call DispatchConsensus function again after several seconds delay
    //HCE: @para nDelaySecond Seconds delayed
    //HCE: @returns void
    void EmitConsensusSignal(int nDelaySecond);

    void onAppChanged();

    using SPCCContextBase = std::shared_ptr<crosschain::CrossChainExecutorBase>;

    std::pair<int, std::string> AddCrossChainTx(SPCCContextBase ctx);

    bool CrossChainTxExist(const string& name);

    bool CheckSwapCond(string& err);

private:

    enum class SERVICE : short
    {
        GetOnChainState = 1,
        AddNewBlockEx,
        AddChainEx,      //HCE: Para coin and ledger call this
        HyperBlockUpdated,
        GetStateOfCurrentConsensus,
        GetDetailsOfCurrentConsensus,
        CheckSearchOnChainedPool,
        InitOnChainingState,
        RehandleOnChainingState,
        RegisterAppCallback,
        UnregisterAppCallback,
        Swap2Eth,
        Swap2Para,
        Swap,
    };

    std::list<std::thread> _threads;
    std::unique_ptr<std::thread> _testthread;

    bool _is_user_request_exit = false;
    bool _isstop;
    bool _isstoptest = false;
    bool _is_able_to_consensus;
    bool _is_requested_latest_hyperblock = false;

    struct _tp2pmanagerstatus* _tP2pManagerStatus = nullptr;

    zmq::socket_t* _hyperblock_updated = nullptr;
    MsgHandler _msghandler;

    std::map<int, SPCCContextBase> _mapCrossChainTx;

};

