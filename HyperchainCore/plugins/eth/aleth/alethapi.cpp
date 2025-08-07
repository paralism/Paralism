/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

#include "alethapi.h"
#include "cryptoethcurrency.h"
#include "blocktriaddr.h"
#include "hyperblockmsgs.h"
#include "utilc.h"

#include "util/common.h"
#include "AccountManager.h"

#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/compute/detail/lru_cache.hpp>

#include <future>

#include <libdevcore/Common.h>
#include <libdevcore/LoggingProgramOptions.h>

#include <libethcore/Common.h>
#include <libethcore/CommonJS.h>
#include <libwebthree/WebThree.h>

#include <libethashseal/EthashCPUMiner.h>

#include <libethereum/BlockChainSync.h>
#include <libethereum/hyperchaininfo.h>
#include <libweb3jsonrpc/Eth.h>
#include <libweb3jsonrpc/ModularServer.h>
#include <libweb3jsonrpc/JsonHelper.h>
#include <libweb3jsonrpc/AccountHolder.h>

#include "../AppPlugins.h"




using namespace std;
using namespace dev;
using namespace dev::eth;

namespace fs = boost::filesystem;
namespace pod = boost::program_options::detail;
namespace po = boost::program_options;


static bool g_isshutdown = true;

std::future<bool> g_aleth_future;
string g_aleth_argv;

map<string, vector<std::pair<string, string>>> map_Aleth_MultiArgs;

std::map<std::string, std::string> mapArgs;
std::map<std::string, std::vector<std::string> > mapMultiArgs;

Logger g_logger{ createLogger(VerbosityInfo, "hc") };
Logger g_loggerWarning{ createLogger(VerbosityWarning, "hc") };


extern dev::WebThreeDirect *g_ptrWeb3;
extern unique_ptr<ModularServer<>> g_jsonrpcIpcServer;
extern unique_ptr<SimpleAccountHolder> g_accountHolder;
extern string logChannels;
extern LoggingOptions loggingOptions;

extern void dev::setupLogging(LoggingOptions const& _options);

extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern void RSyncRemotePullHyperBlock(uint32_t starthid, uint32_t endhid, string nodeid = "");
extern int plugin_main(int argc, char** argv);

string ToString(const BlockHeader &header);

struct PluginContext;


bool RegisterTask(void* objFac)
{
    UNUSED(objFac);
    return true;
}

void UnregisterTask(void* objFac)
{
    UNUSED(objFac);
}


void LoadAlethSettings(const string& cfgfile,
        map<std::string, std::string> &map_al_Args,
        map<std::string, vector<std::pair<string, string>>> &map_al_MultiArgs)
{
    if (cfgfile.empty()) {
        return;
    }

    cout << StringFormat("Read configuration file: %s\n", cfgfile);

    fs::ifstream streamConfig(cfgfile);
    if (!streamConfig.good())
        return;

    set<string> setOptions;
    setOptions.insert("*");

    try {
        for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
            // Don't overwrite existing settings so command line settings override hc.conf
            string strKey = string("-") + it->string_key;
            if (it->string_key.size() > 1) {
                strKey.insert(0, "-");
            }

            if (map_al_Args.count(strKey) == 0)
                map_al_Args[strKey] = it->value[0];
            map_al_MultiArgs[strKey].push_back(std::make_pair(strKey, it->value[0]));
        }
    }
    catch (const std::exception& e) {
        cerr << StringFormat("Read configuration file exception: %s\n", e.what());
    }
}


void AppParseParameters(int argc, char* argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();
    for (int i = 1; i < argc; i++)
    {
        char psz[10000];
        strlcpy(psz, argv[i], sizeof(psz));
        char* pszValue = (char*)"";
        if (strchr(psz, '='))
        {
            pszValue = strchr(psz, '=');
            *pszValue++ = '\0';
        }
#ifdef __WXMSW__
        _strlwr(psz);
        if (psz[0] == '/')
            psz[0] = '-';
#endif
        if (psz[0] != '-')
            break;
        mapArgs[psz] = pszValue;
        mapMultiArgs[psz].push_back(pszValue);
    }
}


string GetHyperChainDataDirInApp()
{
    string datapath;
    boost::filesystem::path pathDataDir;
    if (mapArgs.count("-datadir")) {
        pathDataDir = boost::filesystem::system_complete(mapArgs["-datadir"]);
        if (!boost::filesystem::exists(pathDataDir))
            if (!boost::filesystem::create_directories(pathDataDir)) {
                cerr << "can not create directory: " << pathDataDir << endl;
                pathDataDir = boost::filesystem::system_complete(".");
            }
    } else
        pathDataDir = boost::filesystem::system_complete(".");

    if (mapArgs.count("-model") && mapArgs["-model"] == "informal")
        pathDataDir /= "informal";
    else if (mapArgs.count("-model") && mapArgs["-model"] == "formal")
        pathDataDir /= "formal";
    else
        pathDataDir /= "sandbox";

    if (!boost::filesystem::exists(pathDataDir))
        boost::filesystem::create_directories(pathDataDir);

    return pathDataDir.string();
}

string CreateChildDir(const string& childdir)
{
    string log_path = GetHyperChainDataDirInApp();
    boost::filesystem::path logpath(log_path);
    logpath /= childdir;
    if (!boost::filesystem::exists(logpath)) {
        boost::filesystem::create_directories(logpath);
    }
    return logpath.string();
}


const CUInt128& getMyNodeID()
{
    static CUInt128 myID;
    if (myID.IsZero()) {
        NodeManager* mgr = Singleton<NodeManager>::getInstance();
        HCNodeSH& me = mgr->myself();
        myID = me->getNodeId<CUInt128>();
    }
    return myID;
}


bool ReadBlockFromChainSpace(const T_LOCALBLOCKADDRESS& addr, bytes& block)
{
    CHyperChainSpace* chainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!chainspace->GetLocalBlockPayload(addr, payload)) {
        return false;
    }
    block = bytes(payload.begin(), payload.end());
    return true;
}

//HC: headers存放m_prevHID相同的块头, 容器中的元素按块号大到小存放
//HC: 如果找到了, 返回headers中的索引值，该索引所指的块头在超块链上, 否则返回-1
int ForwardFindBlockInMain(const std::vector<BlockHeader> &headers, int h1, int h2, BLOCKTRIPLEADDRESS &blktriaddr, vector<int> &vecHyperBlkIdLacking)
{
    if (headers.size() <= 0) {
        return -1;
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    h256 hgenesis = g_cryptoEthCurrency.GetHashGenesisBlock();


    int64_t prevhid = headers[0].prevHID();
    int nPos = 0;
    for (auto &header : headers) {
        if (prevhid != header.prevHID())
            return -1; //HC：数据异常

        if (header.number() == 0 && header.hash() == hgenesis) {
            blktriaddr.hid = g_cryptoEthCurrency.GetHID();
            blktriaddr.chainnum = g_cryptoEthCurrency.GetChainNum();
            blktriaddr.id = g_cryptoEthCurrency.GetLocalID();
            hyperchainspace->GetHyperBlockHash(blktriaddr.hid, blktriaddr.hhash);
            return nPos;
        }
        ++nPos;
    }


    int genesisHID = g_cryptoEthCurrency.GetHID();
    T_APPTYPE app(APPTYPE::ethereum, genesisHID, g_cryptoEthCurrency.GetChainNum(), g_cryptoEthCurrency.GetLocalID());

    if (h1 <= genesisHID) {
        h1 = genesisHID + 1;
    }

    const size_t nMaxLacking = 30;

    auto minblk = headers.rbegin();     //HC：集合中块号最小的块

    for (int i = h1; i <= h2 && !g_isshutdown; ++i) {
        vector<T_PAYLOADADDR> vecPA;
        T_SHA256 thhash;
        if (hyperchainspace->GetLocalBlocksByHID(i, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                BlockHeader currheader;
                if (!CryptoEthCurrency::ResolveBlock(currheader, pa->payload)) {
                    LOG(g_loggerWarning)<< StringFormat("Fail to call ResolveBlock, Hyperblock Id: %d\n", i);
                    continue;
                }

                if (currheader.number() < minblk->number()) {
                    break;
                }

                int nPosIndex = 0;
                for (auto& header : headers) {
                    if (currheader.number() == header.number() && currheader.hash() == header.hash()) {
                        blktriaddr = pa->addr;
                        blktriaddr.hhash = thhash;
                        return nPosIndex;
                    }
                    ++nPosIndex;
                }
            }
        } else {
            vecHyperBlkIdLacking.push_back(i);
            if (vecHyperBlkIdLacking.size() >= nMaxLacking) {
                break;
            }
        }
    }

    return -1;
}


//HC: 寻找最后的已经在超块链上的块头
//HC: @param header 逆向扫描的开始块头.
//HC: @param onchainedblkheader 最后一个已经上超块链的块头
//HC: @returns False，表示超块缺失，无法正确计算出最后一个已经上链的子块

//HCE: Look for the last block that is already on the Hyperchain
//HCE: @param header The beginning block of the reverse scan.
//HCE: @param onchainedblkheader The last one has been on the Hyperchain
//HCE: @returns False indicates that the Hyperblock is missing and the last local block that has been chained cannot be calculated correctly
bool LatestBlockIndexOnChained(const BlockHeader& header, BlockHeader& onchainedblkheader)
{
    const BlockChain &bc = g_ptrWeb3->ethereum()->blockChain();

    using HyerBlkLoc = std::pair<uint32_t, T_SHA256>;
    using BlkHHash_HyerBlkLoc = std::pair<h256, HyerBlkLoc>;

    static boost::compute::detail::lru_cache<h256, HyerBlkLoc> blkheaderCache(50);

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    list<BlkHHash_HyerBlkLoc> lruHBL;

    uint64 latestHID = LatestHyperBlock::GetHID();
    BlockHeader headerCurr = header;

    while (!g_isshutdown) {

        if (headerCurr.number() == 0) {
            onchainedblkheader = headerCurr;
            break;
        }

        auto blkheaderhash = headerCurr.hash();
        if(blkheaderCache.contains(blkheaderhash)) {
            boost::optional<HyerBlkLoc> o_blkheader_pos = blkheaderCache.get(blkheaderhash);
            auto & inner_val = o_blkheader_pos.get();

            if (hyperchainspace->CheckHyperBlockHash(inner_val.first, inner_val.second)) {
                lruHBL.push_front(make_pair(blkheaderhash, inner_val));
                onchainedblkheader = headerCurr;
                break;
            }
        }

        //HC：超块链上寻找
        BLOCKTRIPLEADDRESS triaddr;
        vector<int> vecHyperBlkIdLacking;
        std::vector<BlockHeader> headers;

        auto headerprevHID = headerCurr.prevHID();
        BlockHeader headerPrev = bc.info(headerCurr.parentHash());

        headers.emplace_back(std::move(headerCurr));
        for (;(bool)(headerPrev);) {
            if (headerprevHID != headerPrev.prevHID())
                break;
            headers.emplace_back(std::move(headerPrev));
            headerPrev = bc.info(headers.rbegin()->parentHash());
        }

        int nIdx = ForwardFindBlockInMain(headers, headerprevHID + 1, latestHID, triaddr, vecHyperBlkIdLacking);
        if (nIdx >= 0) {
            HyerBlkLoc loc;
            loc.first = triaddr.hid;
            loc.second = triaddr.hhash;
            onchainedblkheader = headers[nIdx];
            lruHBL.push_front(make_pair(headers[nIdx].hash(), loc));
            break;
        } else if(vecHyperBlkIdLacking.size() > 0) {
            //HC：本地超块缺失
            auto n = vecHyperBlkIdLacking.size();
            RSyncRemotePullHyperBlock(vecHyperBlkIdLacking[0], vecHyperBlkIdLacking[n - 1] + 1);
            goto err;
        }

        auto rbgheader = headers.rbegin();

        //HC: change the Hyperblock range of scanning
        headerCurr = bc.info(rbgheader->parentHash());
        latestHID = rbgheader->prevHID();
    }

    for (auto & elm : lruHBL) {
        blkheaderCache.insert(elm.first, elm.second);
    }

    if (g_isshutdown)
        goto err;

    return true;

err:
    return false;
}

//HC: 子链最新块切回到高度更小的块
//HCE: The latest block of the solo chain switches back to the block with a smaller height
bool SwitchChainTo(const BlockHeader& pindexBlock)
{
    eth::Client *cli = g_ptrWeb3->ethereum();

    cli->rewindSyncNotReset(pindexBlock.number());
    cli->completeSync();
    return true;
}

//HC: 提交本模块子链到共识层与其他子链一起参与全局共识
//HCE: Submit the solo chain of this module to the consensus layer to participate in the global consensus with other sub-chains
bool CommitChainToConsensus(deque<PostingBlock>& deqblock, string& requestid, string& errmsg)
{
    UNUSED(requestid);
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();

    vector<string> vecMTRootHash;
    vector<CUInt128> vecNodeId;

    uint32_t hid = g_cryptoEthCurrency.GetHID();
    uint16 chainnum = g_cryptoEthCurrency.GetChainNum();
    uint16 localid = g_cryptoEthCurrency.GetLocalID();

    if (consensuseng) {
        vector<PostingBlock> postingchain;
        size_t num = deqblock.size();
        for (size_t i = 0; i < num; ++i) {
            PostingBlock &blk = deqblock[i];
            postingchain.push_back(std::move(blk));
        }

        auto number = consensuseng->AddChainEx(T_APPTYPE(APPTYPE::ethereum, hid, chainnum, localid), postingchain);
        LOG(g_logger) << StringFormat("Add a ethereum chain to consensus layer: %u\n", number);
        return true;
    } else {
        errmsg = "Cannot commit chain to consensus, Consensus engine is stopped\n";
    }
    return false;
}

bool CommitGenesisToConsensus(const bytes& block, string& requestid, string& errmsg)
{
        ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {

        SubmitData data;
        data.app = T_APPTYPE(APPTYPE::ethereum, 0, 0, 0);
        data.payload = string(block.begin(), block.end());
        data.MTRootHash = data.payload;

        uint32 nOrder;
        if (consensuseng->AddNewBlockEx(data, requestid, nOrder, errmsg)) {
            LOG(g_logger) << StringFormat("Add a ethereum genesis block to consensus layer, requestid: %s\n", requestid);
            return true;
        }
        return false;
    } else {
        errmsg = "Cannot commit consensus, Consensus engine is stopped\n";
    }
    return false;
}

//HC: 进入共识全局阶段时，共识引擎会回调本函数，以便提交子链到共识层，参与全局共识
//HCE: When entering the consensus global stage, the consensus engine will call back this function to submit the solo chain to the consensus layer to participate in the global consensus
bool PutChainCb()
{
    deque<PostingBlock> deqblock;
    h256 hhash;

    bool isSwithBestToValid = false;
    BlockHeader pindexValidStarting;

    if (!g_ptrWeb3) {
        return false;
    }
    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = g_ptrWeb3->ethereum()->blockChain();
    const ChainParams &chainparas = cli->chainParams();

    //setThreadName(StringFormat("CB-%d", std::this_thread::get_id()));

    LOG(g_logger) << "Prepare for committing ethereum blocks to global consensus...";

    const CUInt128& mynodeid = getMyNodeID();

    ////FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        if (!cli->wouldSeal()) {
            LOG(g_logger) << "Cannot commit ethereum solo chain when it isn't mining.";
            return false;
        }

        uint64 nHID = LatestHyperBlock::GetHID(&hhash);

        BlockHeader headerStart;

        if (!LatestBlockIndexOnChained(bc.info(), headerStart)) {
            cli->suspendSealing();
            LOG(g_logger) << "Cannot commit ethereum solo chain because cannot confirm the latest block on the Hyper chain";
            return false;
        }
        cli->resumeSealing();

        headerStart = bc.pnext(headerStart);

        if (!headerStart) {
            return false;
        }

        LOG(g_logger) << StringFormat("Committing ethereum blocks from: %d (HID: %d %s)", headerStart.number(),
            headerStart.prevHID(), headerStart.prevHyperBlkHash().hex());

        BlockHeader headerEnd = headerStart;
        BlockHeader headerPrev;
        while (headerEnd && headerEnd.prevHID() == nHID && headerEnd.prevHyperBlkHash() == hhash) {

            if (headerPrev) {
                if (headerEnd.number() != headerPrev.number() + 1 || headerEnd.parentHash() != headerPrev.hash()) {
                    LOG(g_loggerWarning) << StringFormat("Committing ethereum blocks hash error %d %s",
                        headerEnd.number(), headerEnd.prevHyperBlkHash().hex());
                    break;
                }
            }

            bytes blockdata = bc.block(headerEnd.hash());
            PostingBlock postingblk;
            if (headerEnd.author() == chainparas.author || headerEnd.author() == cli->author()) {
                postingblk.nodeid = mynodeid;
            }

            postingblk.hashMTRoot = headerEnd.transactionsRoot().hex();
            postingblk.vecMT = bc.transactionsVS(headerEnd.hash());

            postingblk.payload = CryptoEthCurrency::MakePayload(blockdata);
            deqblock.push_back(postingblk);

            headerPrev = headerEnd;
            headerEnd = bc.pnext(headerEnd);
        }

        auto nWillCommitBlocks = deqblock.size();
        if (nWillCommitBlocks < 2) {
            isSwithBestToValid = true;
            pindexValidStarting = (nWillCommitBlocks == 0 ? bc.pprev(headerStart) : headerStart);
            LOG(g_logger) << StringFormat("Committing ethereum blocks too less: %d, and chain will switch to %d",
                        deqblock.size(), pindexValidStarting.number());
        }

        if (isSwithBestToValid) {
            SwitchChainTo(pindexValidStarting);
            return false;
        }
    }

    //HC: 等待超块上链再恢复挖矿
    //HCE: Wait for the Hyperblock to be on the chain before resuming mining
    cli->suspendSealing();

    auto deqiter = deqblock.end();
    auto tail_block = --deqiter;

    auto tail_second_block = --tail_block;
    ++tail_block;


    if (!tail_block->nodeid.operator==(mynodeid) &&
        !tail_second_block->nodeid.operator==(mynodeid)) {
        LOG(g_logger) << StringFormat("Cannot commit ethereum chain(len:%d) because the owner of latest two blocks isn't me.(me: %s, %s %s)",
            deqblock.size(), mynodeid.ToHexString().c_str(),
            tail_second_block->nodeid.ToHexString().c_str(),
            tail_block->nodeid.ToHexString().c_str());
        return false;
    }
    tail_block->nodeid = mynodeid;

    string requestid, errmsg;
    if (!CommitChainToConsensus(deqblock, requestid, errmsg)) {
        LOG(g_loggerWarning) << StringFormat("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

    LOG(g_logger) << StringFormat("Committed ethereum chain(len:%d) for global consensus.", deqblock.size());


    return true;
}

bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    UNUSED(vecPA);
    return true;
}

bool AcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    CHAINCBDATA cbdata(mapPayload, hidFork, hid, thhash, isLatest);
    LOG(g_logger) << StringFormat("AcceptChainCb: a new hyper block has reached: %d", hid);
    hyperblockMsgs.insert(std::move(cbdata));
    hyperblockMsgs.process();
    return true;
}

//HC: 共识引擎回调本函数，检查子链的合法性
//HCE: The consensus engine calls back this function to check the legitimacy of the solo chain
bool CheckChainCbWhenOnChaining(vector<T_PAYLOADADDR>& vecPA, uint32_t prevhid, T_SHA256& tprevhhash)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<BlockHeader> vecBlock;
    for (auto b : vecPA) {
        BlockHeader block;
        if (!CryptoEthCurrency::ResolveBlock(block, b.payload)) {
            LOG(g_loggerWarning) << "CheckChainCbWhenOnChaining: Failed to call ResolveBlock";

            return false;
        }
        vecBlock.push_back(std::move(block));
    }

    h256 prevhhash = h256(tprevhhash.toHexString());
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (vecBlock[i].prevHID() != prevhid ||
            vecBlock[i].prevHyperBlkHash() != prevhhash) {
            LOG(g_loggerWarning) << StringFormat("CheckChainCbWhenOnChaining: previous Hyperblock of block %d error", i);
            return false;
        }
        if (i > 0) {
            if (vecBlock[i].number() != vecBlock[i - 1].number() + 1 ||
                vecBlock[i].parentHash() != vecBlock[i - 1].hash()) {
                LOG(g_loggerWarning) << StringFormat("CheckChainCbWhenOnChaining: previous block of block %d error",
                    vecBlock[i].number());
                return false;
            }
        }
    }

    return true;
}

bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)
{
    UNUSED(sAddr);
    UNUSED(eAddr);
    UNUSED(vecVPath);
    return false;
}

bool GetNeighborNodes(list<string>& listNodes)
{
    UNUSED(listNodes);
    return false;

    /*
    eth::Client* cli = g_ptrWeb3->ethereum();

    for (auto& peer : g_ptrWeb3->peers()) {
        oss << "\t" << peer << endl;
    }


    CRITICAL_BLOCK(cs_vNodes)
        for (auto& n : vNodes) {
            listNodes.push_back(n->nodeid);
        }
    return true;
    */
}

//HC: 注册事件回调函数
//HCE: Register event callback functions
void initializeCallbackFunctions()
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        CONSENSUSNOTIFY ethereumCallback =
            std::make_tuple(nullptr, nullptr,
                PutChainCb,
                nullptr,
                nullptr,
                CheckChainCb,
                AcceptChainCb,
                CheckChainCbWhenOnChaining,
                nullptr,
                GetVPath,
                GetNeighborNodes);
        consensuseng->RegisterAppCallback(
            T_APPTYPE(APPTYPE::ethereum, g_cryptoEthCurrency.GetHID(),
                g_cryptoEthCurrency.GetChainNum(),
                g_cryptoEthCurrency.GetLocalID()),
                ethereumCallback);
    }
}

void uninitializeCallbackFunctions()
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::ethereum,
            g_cryptoEthCurrency.GetHID(), g_cryptoEthCurrency.GetChainNum(), g_cryptoEthCurrency.GetLocalID()));
    }
    cout << "\taleth: UnregisterAppCallback\n";
}


//HC: 用传入的参数，启动以太坊子链
//HCE：With the passed parameters, start the Ethereum solo chain
void async_start_module(char* cmdline, string &datadir)
{
    map<string, string> mapArgs;

    char psz[10000] = { 0 };
    strlcpy(psz, cmdline, sizeof(psz));
    g_aleth_argv = psz;
    char* pszValue = (char*)"";
    if (strchr(psz, '=')) {
        pszValue = strchr(psz, '=');
        *pszValue++ = '\0';
    }

    LoadAlethSettings(pszValue, mapArgs, map_Aleth_MultiArgs);

    setDataDir(fs::path(datadir) / "built-in");

    bool isBuiltIn = false;
    if (!g_cryptoEthCurrency.LoadCryptoCurrency(isBuiltIn)) {
        cerr << "load incorrectly ethereum currency settings";
        return;
    }

    auto currency_data_path = fs::path(datadir) / g_cryptoEthCurrency.GetCurrencyConfigPath();

    auto fn = [&mapArgs, &currency_data_path](map<string, vector<std::pair<string, string>>> &map_MultiArgs, const string &key) {
        if (!map_MultiArgs.count(key)) {
            mapArgs[key] = currency_data_path.string();
            map_MultiArgs[key].push_back(make_pair(key, currency_data_path.string()));
        }
    };

    fn(map_Aleth_MultiArgs, "--data-dir");
    fn(map_Aleth_MultiArgs, "--db-path");

    std::shared_ptr<char*> app_argv(new char*[map_Aleth_MultiArgs.size() * 2 + 1]);

    char **p = app_argv.get();
    char moduleName[6] = { "aleth" };
    p[0] = moduleName;

    int app_argc = 1;
    for (auto &key : mapArgs) {
        for (auto &value : map_Aleth_MultiArgs[key.first]) {
            p[app_argc++] = &value.first[0];
            if (!value.second.empty()) {
                p[app_argc++] = &value.second[0];
            }
        }
    }

    g_aleth_future = std::async(std::launch::async, [app_argc, app_argv]() -> bool {
        cout << StringFormat("Aleth module is running in ThreadID : %d \n", std::this_thread::get_id());

        g_isshutdown = false;
        setThreadName("aleth");
        for (int i = 0; i < app_argc; i++) {
            if (string(app_argv.get()[i]) == "--data-dir" && i + 1 < app_argc) {
                //auto datadir = fs::path(string(app_argv.get()[i + 1])) / g_cryptoEthCurrency.GetCurrencyConfigPath();
                setDataDir(string(app_argv.get()[i + 1]));
                break;
            }
        }

        int ret = plugin_main(app_argc, app_argv.get());
        if (ret != AlethErrors::Success) {
            cerr << "Error: Module aleth exit!!!!, return value is " << ret << endl;
            return false;
        }
        return true;
        });

}

bool StartApplication(PluginContext* context)
{
    context->SetPluginContext();

    g_aleth_argv = "";

    int nIdxRun = -1;
    for (int i = 0; i < context->pc_argc; i++) {
            if (string(context->pc_argv[i]).find("-aleth-cmdline") == 0) {
                nIdxRun = i;
        }
    }

    if (nIdxRun >= 0) {
        AppParseParameters(context->pc_argc, context->pc_argv);

        string strDataDir = CreateChildDir("aleth");
        async_start_module(context->pc_argv[nIdxRun], strDataDir);
    } else {
        cerr << "Warning: cannot load module aleth, please specify 'aleth-cmdline' option!!!\n";
        return false;
    }

    return true;
}

void StopApplication(bool isFirst)
{
    if (isFirst) {
        g_isshutdown = true;
        return;
    }
    g_isshutdown = true;

    uninitializeCallbackFunctions();
    g_sys_interrupted = 1; //HC: 模块unregistered后，才能stop MQ
    ExitHandler::exitHandler(0);
    g_aleth_future.wait();
}

bool IsStopped()
{
    //std::future_status status;
    //status = aleth_future.wait_for(std::chrono::milliseconds(10));
    //return (status == std::future_status::ready);

    return g_isshutdown || !ExitHandler::isrunning();
}

string& moveRight(string &strMessage)
{
    strMessage.insert(strMessage.begin(), '\t');
    auto findpos = strMessage.begin();
    for (; findpos != strMessage.end(); ++findpos) {
        if (*findpos == '\n') {
            findpos = strMessage.insert(findpos + 1, '\t');
        }
    }
    return strMessage;
}

//HC: 控制台rs命令无参数响应函数
//HCE: The console 'rs' command response function
void AppInfo(string& info)
{
    if (!g_ptrWeb3) {
        info = "web3 interface uninitialized";
        return;
    }

    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = cli->blockChain();

    try {
        string latestblockinfo;
        ResolveHeight(bc.number(), latestblockinfo);
        info = StringFormat("Aleth module lastest block number: %d %s...\n%s\n",
            bc.number(),
            bc.currentHash().hex().substr(0, 16),
            latestblockinfo);

        //oss.str("");
        //oss << toJson(bc.info());
        //info += oss.str();
    }
    catch (std::exception& e) {
        info = StringFormat("An exception occurs: %s\n", e.what());
    }
    catch (...) {
        info = StringFormat("An exception occurs calling %s\n", __FUNCTION__);
    }
}

void AppRunningArg(int &app_argc, string &app_argv)
{
    app_argc = 2;
    app_argv = g_aleth_argv;
}

bool ResolveHeight(int nheight, string& info)
{
    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = cli->blockChain();

    ostringstream oss;

    try {
        auto h = bc.numberHash(nheight);
        oss << toJson(bc.info(h));
        info += oss.str();
    }
    catch (std::exception& e) {
        info = StringFormat("An exception occurs: %s\n", e.what());
    }
    catch (...) {
        info = StringFormat("An exception occurs calling %s\n", __FUNCTION__);
    }

    return true;
}

bool ResolvePayload(const string& payload, string& info)
{
    BlockHeader currheader;
    if (!CryptoEthCurrency::ResolveBlock(currheader, payload)) {
        info = "Fail to call ResolveBlock for ethereum block data";
    }

    info = ToString(currheader);
    return true;
}

void executecmd(const char *command, const list<string>& childcmds)
{
    list<string> newchildcmds = childcmds;

    std::shared_ptr<const char*> app_argv(new const char*[newchildcmds.size() + 2]);

    const char **p = app_argv.get();
    p[0] = "aleth";
    p[1] = command;
    int app_argc = 2;
    for (auto &cmd : newchildcmds) {
        p[app_argc++] = &cmd[0];
    }

    AccountManager accountm;
    accountm.execute(app_argc, app_argv.get());
}

string ToString(const strings &v)
{
    ostringstream oss;
    oss << v;
    return oss.str();
}

string ToString(const BlockHeader &header)
{
    ostringstream oss;

    oss << "Block header details : { "
        << "\n\tnumber: " << header.number()
        << "\n\tauthor: " << header.author()
        << "\n\thash: " << header.hash()
        << "\n\tparentHash: " << header.parentHash()
        << "\n\tdifficulty: " << header.difficulty()
        << "\n\tgasLimit: " << header.gasLimit()
        << "\n\tgasUsed: " << header.gasUsed()
        << "\n\ttimestamp: " << header.timestamp()
        << "\n\tprevious hyper block ID: " << header.prevHID()
        << "\n\tprevious hyper block hash: " << header.prevHyperBlkHash()
        << "\n}";
    return oss.str();
}





template<typename... Args>
string callWeb3RPC(const string& rpcmethodname, Json::Value& output, const Args&... args)
{
    if (!g_jsonrpcIpcServer) {
        output = "Json rpc Server object is nullptr";
    } else {
        Json::Value input(Json::arrayValue);

        std::initializer_list<int>{([&] {
            input.append(args);
            }(), 0)...};

        jsonrpc::Procedure proc;
        proc.SetProcedureName(rpcmethodname);
        g_jsonrpcIpcServer->HandleMethodCall(proc, input, output);
    }
    Json::FastWriter fastWriter;
    ostringstream oss;
    oss << fastWriter.write(output) << std::flush;
    return oss.str();
}

//HC: 通过区块头，查找该区块在超块链上的三元组地址
//HCE: Through the block header, find the triplet address of the block on the Hyperchain
std::string SearchTriAddrInHyperchain(const BlockHeader &blkhead)
{
    eth::Client* cli = g_ptrWeb3->ethereum();
    const BlockChain& bc = cli->blockChain();

    BLOCKTRIPLEADDRESS tripleaddr;

    int64_t latestHID = LatestHyperBlock::GetHID();
    int64_t nStartHID = blkhead.prevHID() + 1;
    if (nStartHID > latestHID)
        nStartHID = latestHID;

    BLOCKTRIPLEADDRESS triaddr;
    vector<int> vecHyperBlkIdLacking;

    int64_t nEndHID = latestHID;
    BlockHeader hnext = bc.pnext(blkhead);
    while (hnext) {
        if (hnext.prevHID() > blkhead.prevHID()) {
            nEndHID = hnext.prevHID();
            break;
        }
        hnext = bc.pnext(hnext);
    }

    if (nStartHID + 100 < nEndHID) {

        cout << StringFormat("To get block triple address, need to scan Hyperblock: [%d...%d], do you want to scan(y/n, default:n)?",
            nStartHID, nEndHID);
        char c_action;
        cin >> std::noskipws >> c_action;
        if (c_action != 'y' && c_action != 'Y') {
            return "skipped by user";
        }
    }

    string rc;
    std::vector<BlockHeader> headers;
    headers.emplace_back(std::move(blkhead));

    if (ForwardFindBlockInMain(headers, nStartHID, nEndHID, triaddr, vecHyperBlkIdLacking) >= 0) {

        rc = StringFormat("[%d,%d,%d(%s)]",
            triaddr.hid, triaddr.chainnum, triaddr.id, triaddr.hhash.toHexString().substr(0,10));
        return rc;
    }

    if (vecHyperBlkIdLacking.size() > 0) {
        int endidx = vecHyperBlkIdLacking.size() - 1;
        rc = StringFormat("unknown, not Hyperblock: [%d...%d] in local storage", vecHyperBlkIdLacking[0],
            vecHyperBlkIdLacking[endidx]);
    } else {
        rc = StringFormat("unknown, Hyperblock scanned: [%d...%d]", nStartHID, nEndHID);
    }
    return rc;
}

string showEthUsage()
{
    ostringstream oss;
    oss << "Usage: eth ls                                           : list all local imported coins \n";
    oss << "       eth ll [NO.]                                     : display the default/specified coin details \n";
    oss << "       eth df [NO.]                                     : query or set the default coin, after restarting ethereum module, it takes effect\n";
    oss << "       eth iss [...]                                    : issue a coin, 'eth iss' for help\n";
    oss << "       eth imp <hid chainid localid>                    : import a coin\n";

    oss << "       eth acc: \n";
    AccountManager::streamAccountHelp(oss, "       ");
    oss << "\n";
    oss << "       eth wallet: \n";
    AccountManager::streamWalletHelp(oss, "       ");
    oss << "       eth log                                          : show or change log level\n";

    oss << "       eth logch                                        : show or change log channels\n";
    oss << "       \t\tlogch include\n";
    oss << "       \t\tlogch exclude\n";
    oss << "       \t\tlogch clear\n";

    oss << "       eth nodeid                                       : show Node ID\n";
    oss << "       eth block [height]                               : show a specified block\n";
    oss << "       eth peers                                        : show peers\n";
    oss << "       eth ba                                           : query balance for a address\n";
    oss << "       eth sendfrom <fromaccount> <toaddress> <n>       : transfer, unit is wei\n";
    oss << "       eth sendtoaddr <address> <n> [gas] [gasPrice]    : transfer, unit is wei\n";
    oss << "       eth miner <n>                                    : show or change the number of CPU miners\n";
    oss << "       eth s                                            : query running status\n";
    oss << "       eth e                                            : enable mining\n";
    oss << "       eth d                                            : disable mining\n";
    oss << "       eth a                                            : show or set author\n";
    oss << "       eth tx <txid>                                    : get detailed information about <txid>\n";
    oss << "       eth lock <address>                               : lock account\n";
    oss << "       eth unlock <address> <duration> [password]       : unlock account, <duration> is the length of time in seconds\n";
    return oss.str();
}

//HC: 处理控制台以太坊子命令
//HCE: Process console Ethereum subcommands
//HCE: @param cmdline The command arguments passed in
//HCE: @param info Command response results
//HCE: @param savingcommand Command save form for historical review
//HCE: @returns true if the command has handled.
bool ConsoleCmd(const list<string>& cmdlist, string& info, string& savingcommand)
{
    UNUSED(savingcommand);

    if (cmdlist.size() == 1) {
        info = showEthUsage();
        return true;
    }

    if (IsStopped()) {
        info = "app has stopped";
        return true;
    }

    if (!g_ptrWeb3) {
        info = "Web3 object has not been ready.";
        return true;
    }

    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = cli->blockChain();
    ChainParams const& chainpara = cli->chainParams();


    std::unordered_map<string, std::function<string(const list<string>&, bool)>> mapcmds = {

        {"ls",[](const list<string>&, bool) ->string {
            vector<CryptoEthCurrency> coins;
            CryptoEthCurrency::GetAllCoins(coins);

            auto currhash = g_cryptoEthCurrency.GetHashGenesisBlock();

            ostringstream oss;
            size_t i = 0;
            for (auto& t : coins) {
                bool iscurrcoin = false;
                if (currhash == t.GetHashGenesisBlock()) {
                    iscurrcoin = true;
                }
                oss << StringFormat("%c %d\t%s\t[%u,%u,%u]\n",
                    iscurrcoin ? '*' : ' ',
                    i++,
                    t.GetHashPrefixOfGenesis().c_str(),
                    t.GetHID(), t.GetChainNum(), t.GetLocalID());
            }

            if (coins.size() == 0) {
                oss << "Not find any coin, use 'eth imp' or 'eth iss' to get one\n";
            } else 
                oss << "use 'eth ll [NO.]' for coin details\n";
            return oss.str();
        } },

        {"ll",[](const list<string>& l, bool) ->string {
            if (l.size() < 1) {
                return g_cryptoEthCurrency.ToString();
            }

            size_t i = std::atoi(l.begin()->c_str());

            vector<CryptoEthCurrency> coins;
            CryptoEthCurrency::GetAllCoins(coins);
            if (i >= coins.size()) {
                return "out of range";
            }

            auto& t = coins[i];
            return t.ToString();
        } },

        {"df",[](const list<string>& l, bool) ->string {
            if (l.size() < 1) {
                return StringFormat("current coin: %s\n",
                    g_cryptoEthCurrency.GetHashPrefixOfGenesis());
            }

            size_t i = std::atoi(l.begin()->c_str());

            vector<CryptoEthCurrency> coins;
            CryptoEthCurrency::GetAllCoins(coins);
            if (i + 1 > coins.size()) {
                return "out of range";
            }

            auto& t = coins[i];

            CApplicationSettings appini;
            appini.WriteDefaultApp(t.GetHashPrefixOfGenesis());

            return StringFormat("set '%s' as current coin, please restart aleth module\n", t.GetHashPrefixOfGenesis());
        } },

        {"iss",[](const list<string>& l, bool) ->string {
            //return doAction(issuecoin, l, fhelp, false);
            if (l.size() < 1) {
                return StringFormat("eth iss <filename>\n");
            }

            string configfile = *l.begin();
            g_cryptoEthCurrency.RsyncMiningGenesiBlock(configfile);
            return "";
        } },

        {"imp",[](const list<string>& l, bool) ->string {
            if (l.size() < 3)
                throw runtime_error("imp <hyperblockId> <chainNumber> <localId> \n");

            auto it = l.begin();
            int hid = std::atoi(it->c_str()); ++it;
            int chainid = std::atoi(it->c_str()); ++it;
            int id = std::atoi(it->c_str());

            T_LOCALBLOCKADDRESS addr;
            addr.set(hid, chainid, id);

            bytes genesisBlock;
            if (!ReadBlockFromChainSpace(addr, genesisBlock))
                return "Failed to read block data from chainspace";

            CryptoEthCurrency newcurrency;
            if (!newcurrency.ParseCoin(genesisBlock)) {
                return "Failed to parse local block data, maybe not genesis block";
            }

            newcurrency.SetGenesisAddr(addr.hid, addr.chainnum, addr.id);
            return "Imported successfully";
        } },

        {"acc", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            executecmd("account", childcmds);
            return "";
        } },

        {"wallet", [](const list<string>& childcmds, bool) ->string {
            executecmd("wallet", childcmds);
            return "";
        } },

        {"nodeid", [](const list<string>&, bool) ->string {
            return StringFormat("Node ID: %s\n", g_ptrWeb3->enode());
        } },

        { "s", [&cli, &bc](const list<string>&, bool) ->string {
            if (!g_ptrWeb3) {
                return "web3 interface uninitialized";
            }
            eth::Client* cli = g_ptrWeb3->ethereum();
            const BlockChain& bc = cli->blockChain();

            ostringstream oss;
            size_t nPeers = g_ptrWeb3->peerCount();
            oss << "Aleth module's current coin hash: " << g_cryptoEthCurrency.GetHashPrefixOfGenesis() << endl
                << "Genesis block address: " << g_cryptoEthCurrency.GetHID() << " "
                << g_cryptoEthCurrency.GetChainNum() << " "
                << g_cryptoEthCurrency.GetLocalID() << endl
                << "Neighbor node amounts: " << nPeers << ", 'e peers' for details" << endl;


            auto* sealeng = cli->sealEngine();
            bool isAllowed = sealeng->isMining() && !!nPeers && !cli->isSuspendSealing(); //cli->wouldSeal();

            string reason = "SealEngine paused";
            if (nPeers <= 0) {
                reason = "Not any peers";
            }
            else if (cli->isSuspendSealing()) {
                reason = "Suspend temporarily";
            }

            oss << "Mining status: " << (isAllowed ? "mining" : string("stopped: ").append(reason)) << endl;

            oss << "Mining isSuspendSealing: " << (cli->isSuspendSealing() ? "Yes" : "No") << endl;

            oss << "Current sealer in use: " << cli->sealer() << endl;
            oss << "CPU miners of sealer in use: " << EthashCPUMiner::instances() << endl;
            size_t readySet;
            auto s = cli->blockQueueStatus(readySet);
            oss << "BlockQueue size of readySet: " << readySet << endl;

            ostringstream osstmp;
            osstmp << s;
            string blockqueuestatus = osstmp.str();

            oss << moveRight(blockqueuestatus) << endl;

            BlockHeader head = cli->working().info();
            oss << "Working: "
                << head.number() << " "
                << head.hash().hex().substr(0, 16) << "... "
                << head.parentHash().hex().substr(0, 16) << "... "
                << "prevHID: " << head.prevHID() << " "
                << head.prevHyperBlkHash().hex().substr(0, 16) << "..." << endl;
            oss << "Transaction queue: \n"
                << cli->transactionQueueStatusDetails() << endl;


            oss << "Are we updating the chain (syncing or importing a new block)? " << (cli->isSyncing() ? "Yes" : "No") << endl;
            //oss << "Are we syncing the chain? " << (cli->isMajorSyncing() ? "Yes" : "No") << endl;

            osstmp.str("");
            osstmp << cli->syncStatusNoLock();
            string syncstatus = osstmp.str();

            oss << "SyncStatus: \n" << moveRight(syncstatus) << endl;

            //if (!cli->wouldSeal()) {
            //    oss << "Block generate disabled, use command 'e e' to enable\n";
            //}
            try {
                oss << StringFormat("Lastest block number: %d %s...\n",
                    bc.number(),
                    bc.currentHash().hex().substr(0, 16));
            }
            catch (...) {
            }

            return oss.str();
        } },

        {"e", [&cli, &bc](const list<string>&, bool) ->string {
            if (cli->wouldSeal()) {
                return "Mining already started";
            }
            cli->startSealing();
            return cli->wouldSeal() ? "Mining started" :
                (loggingOptions.verbosity == 4 ? "Failed to start mining" :
                "Failed to start mining, use 'e log 4' to change log level for more information");
        } },

        {"d", [&cli, &bc](const list<string>&, bool) ->string {
            if (cli->wouldSeal()) {
                cli->stopSealing();
            }
            return cli->wouldSeal() ? "Mining started" : "Mining stopped";
        } },

        { "a", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() < 1) {
                return StringFormat("author is %s", cli->author().hex());
            }
            auto iter = childcmds.begin();
            Address author = Address(*iter);

            AccountManager accountm;
            if (!accountm.contain(author)) {
                cout << "Warning: The new author cannot be found in wallet!!!\n";
            }

            cli->setAuthor(author);
            fs::path configFile = g_cryptoEthCurrency.getConfigFile();
            writeFile(configFile, rlpList(author, author));

            return StringFormat("author has changed, new author is %s", cli->author().hex());
        } },

        { "debugtx", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() <= 0) {
                return "Input tx's hash";
            }

            string strHash = *childcmds.begin();
            Json::Value param = strHash;
            Json::Value output;
            return callWeb3RPC("debug_traceTransaction", output, param);
        } },

        { "tx", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() <= 0) {
                return "Input tx's hash";
            }

            string strHash = *childcmds.begin();

            h256 h(strHash);
            if (!cli->isKnownTransaction(h)) {
                for (Transaction const& pending : cli->pending()) {
                    if (h == pending.sha3()) {
                        Json::FastWriter fastWriter;
                        ostringstream oss;
                        oss << fastWriter.write(toJson(pending)) << std::flush;
                        cout << "It is in Transaction Queue, waiting for sealing:\n";
                        return oss.str();
                    }
                }
            }

            Json::Value param = toHexPrefixed(h);
            Json::Value output;
            return callWeb3RPC("eth_getTransactionByHash", output, param);
        } },

        { "sendfrom", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() < 3)
                throw runtime_error("sendfrom <fromaccount> <toaddress> <n> [gas] [gasPrice] \n");

            auto it = childcmds.begin();

            Json::Value param;
            param["from"] = *it; ++it;
            param["to"] = *it; ++it;
            param["value"] = *it; ++it;

            if (it != childcmds.end()) {
                param["gas"] = *it;
                ++it;
                if (it != childcmds.end()) {
                    param["gasPrice"] = *it;
                    ++it;
                }
            }
            Json::Value output;
            return callWeb3RPC("eth_sendTransaction", output, param);
        } },

        { "sendtoaddr", [&cli, &bc](const list<string>& childcmds, bool) ->string {

            if (childcmds.size() < 2)
                throw runtime_error("eth sendtoaddr <address> <n> [gas] [gasPrice]\n");

            auto it = childcmds.begin();

            Json::Value param;
            param["to"] = *it; ++it;
            param["value"] = *it; ++it;

            if (it != childcmds.end()) {
                param["gas"] = *it;
                ++it;
                if (it != childcmds.end()) {
                    param["gasPrice"] = *it;
                    ++it;
                }
            }

            Json::Value output;
            return callWeb3RPC("eth_sendTransaction", output, param);
        } },

        { "miner", [&cli, &bc](const list<string>& childcmds, bool) ->string {

            if (childcmds.size() <= 0) {
                return StringFormat("Number of CPU miner is %d\n", EthashCPUMiner::instances());
            }
            auto iter = childcmds.begin();
            int n = std::atoi(iter->c_str());

            EthashCPUMiner::setNumInstances(n);
            return "ok!\n";
        } },

        { "bucket", [&cli, &bc](const list<string>&, bool) ->string {
            auto nodetable = g_ptrWeb3->host().nodeTable();
            ostringstream oss;
            oss << *nodetable.get(); //libp2p\NodeTable.h std::ostream& operator<<()
            return oss.str();
        } },

        { "checkchain", [&cli, &bc](const list<string>& childcmds, bool) ->string {

            BlockHeader blkhead = bc.info();

            int64_t blocknum = blkhead.number();
            int64_t amount = 1000;

            if (childcmds.size() > 0) {
                auto it = childcmds.begin();
                int n = std::atoi(it->c_str());
                if (n < blocknum) {
                    blocknum = n;
                }

                if (++it != childcmds.end()) {
                    amount = std::atoi(it->c_str());
                }

                blkhead = bc.info(bc.numberHash(blocknum));
            }

            int nCount = 0;

            BlockHeader prevblkhead = bc.pprev(blkhead);
            cout << "Usage: e checkchain [height] [amount]\n";
            cout << StringFormat("Scanning chain from block %d to %d\n", blkhead.number(), blkhead.number() - amount);

            CommadLineProgress progress;
            progress.Start();
            do
            {
                if (!prevblkhead) {
                    break;
                }
                if (prevblkhead.number() + 1 != blkhead.number() ||
                    prevblkhead.hash() != blkhead.parentHash()) {
                    cout << StringFormat("Chain error occurs in the following two blocks: %d %d", prevblkhead.number(), blkhead.number()) << endl;
                    cout << toJson(prevblkhead);
                    cout << toJson(blkhead);
                    break;
                }
                blkhead = prevblkhead;
                prevblkhead = bc.pprev(blkhead);

                nCount++;
                if (nCount % 100 == 0) {
                    progress.PrintStatus(100, StringFormat("scanned: %d, left: %d", nCount, amount));
                }

            } while (--amount);

            progress.PrintStatus(1, StringFormat("scanned: %d [%d %s]\n", nCount, blkhead.number(), blkhead.hash().hex()));
            return "Scan completed!";
        } },


        {"ba", [&cli, &bc](const list<string>& childcmds, bool) ->string {
            ostringstream oss;

            Address addr;   // = cli->author();
            BlockNumber num = LatestBlock;

            if (childcmds.size() > 0) {
                auto iter = childcmds.begin();
                addr = Address(*iter);

                ++iter;
                if (iter != childcmds.end()) {
                    num = std::atoi(iter->c_str());
                }
                oss << addr << ": " << formatBalance(cli->balanceAt(addr, num));
            }
            else {
                //HC: 查看钱包里所有账户地址
                AccountManager accountm;
                auto alladdr = accountm.addresses();
                for (auto & elm: alladdr) {
                    oss << elm << ": " << formatBalance(cli->balanceAt(elm, num)) << endl;
                }
                oss << "RewardDistribute(" << CrossChainRecvAndRewardDistributeAddress << "): "
                    << formatBalance(cli->balanceAt(CrossChainRecvAndRewardDistributeAddress, num));
            }

            return oss.str();
        } },

        {"lock", [&cli, &bc](const list<string> &childcmds, bool) ->string {
            if (childcmds.size() < 1) {
                return StringFormat("eth lock <address>\n");
            }

            auto iter = childcmds.begin();
            std::string address = *iter++;

            Address addr = Address(fromHex(address, WhenError::Throw));
            if (!g_accountHolder->isRealAccount(addr))
                return "Invalid or nonexistent address";

            //HC: 如果选项unsafe-transactions启用，那么加锁无效
            g_accountHolder->unlockAccount(addr, "", 0); //HC: '0' mean lock the account right now
            return "ok!";
        } },


        {"unlock", [&cli, &bc](const list<string> &childcmds, bool) ->string {

            if (childcmds.size() < 2) {
                return StringFormat("eth unlock <address> <duration> [password]");
            }

            auto iter = childcmds.begin();
            std::string address = *iter++;

            int duration = std::atoi(iter->c_str());

            std::string password;
            if(++iter != childcmds.end())
                password = *iter;

            Address addr = Address(fromHex(address, WhenError::Throw));
            if (!g_accountHolder->isRealAccount(addr))
                return "Invalid or nonexistent address";

            if (!g_accountHolder->unlockAccount(addr, password, duration)) {
                return "Invalid password";
            }

            return "ok!";

            //HC: alternative solution
            //Json::Value output;
            //callWeb3RPC("personal_unlockAccount", output, address, password, duration);
        } },

        {"peers", [&cli, &bc](const list<string>&, bool) ->string {
            ostringstream oss;
            oss << "Active peer count: " << g_ptrWeb3->peerCount() << endl;
            oss << "Peers:\n";
            for (auto & peer : g_ptrWeb3->peers()) {
                oss << "\t" << peer << endl;
            }
            return oss.str();
        } },

        {"block", [&cli, &bc, &chainpara](const list<string>& childcmds, bool) ->string {

            //or callWeb3RPC("eth_getBlockByHash", output, strHash, false);

            ostringstream oss;
            oss << "Genesis block hash: " << bc.genesisHash() << endl;
            oss << "Difficulty: 0x"<< std::hex << chainpara.difficulty << endl;
            oss << "minimumDifficulty: 0x" << std::hex <<  chainpara.minimumDifficulty << endl;
            oss << "chainID: " << std::dec <<  chainpara.chainID << endl;
            oss << "networkID: " <<  chainpara.networkID << endl;
            oss << "sealEngine: " <<  chainpara.sealEngineName << endl;

            oss << "block: ";
            BlockHeader blkhead;
            if (childcmds.size() > 0) {
                int blocknum = std::atoi(childcmds.begin()->c_str());
                blkhead = bc.info(bc.numberHash(blocknum));
                oss << toJson(blkhead);
            } else {
                blkhead = bc.info();
                oss << "Last block number: " << bc.number() <<"\n";
                oss << toJson(bc.info());
            }

            oss << "\nTxs: {\n";
            TransactionHashes hashs = bc.transactionHashes(blkhead.hash());
            for (auto h : hashs) {
                oss << "    " << h.hex() << endl;
            }
            oss << "}\n";

            oss << "\nTriple addr: " << SearchTriAddrInHyperchain(blkhead) << endl;
            return oss.str();
        } },

        {"log", [](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() <= 0) {
                return StringFormat("Current log level: %d, valid value is <0 ~ 4>, isToFile: %d\n",
                    loggingOptions.verbosity, loggingOptions.isToFile);
            }
            loggingOptions.verbosity = std::atoi(childcmds.begin()->c_str());;
            setupLogging(loggingOptions);
            return "Log level of ethereum has changed";
        } },

        { "logf", [](const list<string>& childcmds, bool) ->string {
            string usage = "Usage: e logf [on | off]\n";
            if (childcmds.size() <= 0) {
                return StringFormat("%sCurrent log are outputted into file: \'%s\', file name: %s\n",
                    usage,
                    (loggingOptions.isToFile ? "Yes" : "No"),
                    (!loggingOptions.isToFile ? "null" :
                        loggingOptions.outputPath + "/" +
                        loggingOptions.outputFile));
            }

            auto cmd = childcmds.begin();
            string childcmd = *cmd;

            if (childcmd == "on") {
                loggingOptions.outputPath = GetHyperChainDataDirInApp();
                loggingOptions.isToFile = true;
            } else if (childcmd == "off") {
                loggingOptions.isToFile = false;
            } else {
                return usage;
            }

            setupLogging(loggingOptions);
            return "Log file of ethereum has changed";
        } },


        {"logch", [](const list<string>& childcmds, bool) ->string {
            if (childcmds.size() <= 0) {
                return StringFormat("Current log channels include: %s\nexclude: %s\nAll channels: %s\n",
                        ToString(loggingOptions.includeChannels),
                        ToString(loggingOptions.excludeChannels), logChannels);
            }

            bool isChanged = false;
            auto iter = childcmds.begin();

            auto fnChange = [&childcmds, &isChanged, &iter](strings &includechannels, strings &excludechannels) {
                ++iter;
                for (; iter != childcmds.end(); ++iter) {
                    auto iter_in_exclude = std::find(std::begin(excludechannels), std::end(excludechannels), *iter);
                    if (iter_in_exclude != excludechannels.end()) {
                        excludechannels.erase(iter_in_exclude);
                        isChanged = true;
                    }

                    if (contains(includechannels, *iter)) {
                        continue;
                    }
                    includechannels.push_back(*iter);
                    isChanged = true;
                }
            };

            if (*iter == "include") {
                fnChange(loggingOptions.includeChannels, loggingOptions.excludeChannels);
            } else if (*iter == "exclude") {
                fnChange(loggingOptions.excludeChannels, loggingOptions.includeChannels);
            } else if (*iter == "clear") {
                loggingOptions.includeChannels.clear();
                loggingOptions.excludeChannels.clear();
                isChanged = true;
            } else {
                return "invalid command format";
            }

            if (!isChanged) {
                return "Nothing has changed for logChannels";
            }
            setupLogging(loggingOptions);
            return "logChannels has changed";
        } },

    };

    list<string> cpycmdlist;
    cpycmdlist = cmdlist;
    auto cmd = ++cpycmdlist.begin();
    string childcmd = *cmd;
    cpycmdlist.pop_front();
    cpycmdlist.pop_front();

    if (childcmd == "v") {
        for (auto& cmd : mapcmds) {
            info += StringFormat("%s\n", cmd.first);
        }
        return true;
    }

    //bool isMQStopper = paramsghandler.isstopped();
    //bool isCenterStopper = paramqcenter.GetMsgHandler().isstopped();
    //if (isMQStopper || isCenterStopper) {
    //    info = strprintf("Para MQ handler(center) is %s(%s), please restart Para module\n",
    //        isMQStopper ? "stopped" : "started",
    //        isCenterStopper ? "stopped" : "started");
    //    return true;
    //}

    if (mapcmds.count(childcmd)) {
        info = mapcmds[childcmd](cpycmdlist, false);
        return true;
    }
    info = StringFormat("Child command '%s' doesn't exist\n", childcmd.c_str());
    return true;
}


extern "C" BOOST_SYMBOL_EXPORT
bool TurnOnOffDebugOutput(const string & onoff, string & ret)
{
    UNUSED(onoff);
    UNUSED(ret);
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
std::string GetGenesisBlock(string & payload)
{
    UNUSED(payload);
    return std::string("");
}

extern "C" BOOST_SYMBOL_EXPORT void getrewarddistributeaddress(string & rewardaddress)
{
    rewardaddress = CrossChainRecvAndRewardDistributeAddress.hex();
}

//HC: 跨链交易转入收款交易
extern "C" BOOST_SYMBOL_EXPORT bool recvfromchain(const map<string, string> &mapparams, string &txhash, string &strError)
{
    Json::Value _json;

    if (mapparams.count("to")) {
        _json["to"] = mapparams.at("to");
    } else {
        _json["to"] = CrossChainRecvAndRewardDistributeAddress.hex();
    }

    string value = UnitConversionToEth(mapparams.at("amount"));
    _json["value"] = value;

    //HC: 跨链操作中，存放Para链上对应转出交易的 （hash, hid, chainid, localid) 信息

    RLPStream additiondata(4); //HC：准备压入带4个元素的List
    additiondata.append(mapparams.at("paratxhash"));
    additiondata.append(std::atol(mapparams.at("para_tx_hid").c_str()));
    additiondata.append(std::atol(mapparams.at("para_tx_chainid").c_str()));
    additiondata.append(std::atol(mapparams.at("para_tx_localid").c_str()));

    bytes addition;
    additiondata.swapOut(addition);
    _json["data"] = toHex(addition);

    try {
        if (!mapparams.count("senderprikey")) {
            throw std::invalid_argument("Please provide 'senderprikey' parameter");
        }

        _json["senderprikey"] = mapparams.at("senderprikey");
        Json::Value output;
        callWeb3RPC("eth_recvCrossChainTransaction", output, _json);
        txhash = output["hash"].asString();

        return true;
    } catch (std::exception const& ex) {
        strError = ex.what();
    }
    return false;
}

//HC: 跨链交易转出交易，转账到Para某个地址
extern "C" BOOST_SYMBOL_EXPORT bool sendtochain(const map<string, string>&mapparams,
    string & txhash,
    string & publickey,
    uint32_t &genesishid,
    uint16_t &genesischainid,
    uint16_t &genesislocalid,
    string & gensishash,
    string & strError)
{
    if (!g_ptrWeb3) {
        //HC: web3对象未初始化，不能创建交易
        strError = "The web3 object is not initialized, cannot create transaction";
        return false;
    }

    Json::Value _json;

    _json["from"] = mapparams.at("from");
    _json["to"] = ZeroAddress.hex();

    string value = UnitConversionToEth(mapparams.at("amount"));

    _json["value"] = value;
    _json["data"] = mapparams.at("para_recv_script");

    const BlockChain &bc = g_ptrWeb3->ethereum()->blockChain();
    gensishash = bc.genesisHash().hex();

    try {
        Json::Value output;
        callWeb3RPC("eth_sendCrossChainTransaction", output, _json);

        txhash = output["hash"].asString();
        publickey = output["publickey"].asString();

        genesishid = g_cryptoEthCurrency.GetHID();
        genesischainid = g_cryptoEthCurrency.GetChainNum();
        genesislocalid = g_cryptoEthCurrency.GetLocalID();

        return true;
    }
    catch (std::exception const& ex) {
        strError = ex.what();
    }
    return false;
}

extern "C" BOOST_SYMBOL_EXPORT
bool GetBlockHash(const unsigned char* blockdata, int blockdatalen, unsigned char hash[32])
{
    BlockHeader currheader;
    if (!CryptoEthCurrency::ResolveBlock(currheader, string(reinterpret_cast<const char*>(blockdata), blockdatalen))) {
        //info = "Fail to call ResolveBlock for ethereum block data";
        return false;
    }

    std::memcpy(hash, currheader.hash().data(), 32);
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
bool GetTxState(const string &txhash, int &blocknum, int64_t &blockstamp,
    int &blockmaturity,
    int64_t &hyperId,
    int64_t &chainId,
    int64_t &localId,
    string &desc,
    string &strError)
{
    if (!g_ptrWeb3) {
        strError = "The web3 object is not initialized, cannot create transaction";
        return false;
    }

    auto cli = g_ptrWeb3->ethereum();
    const BlockChain& bc = cli->blockChain();

    blocknum = -1;
    blockmaturity = -1;

    hyperId = -1;
    chainId = 0;
    localId = 0;

    try {

        h256 h(txhash);
        if (!cli->isKnownTransaction(h)) {
            for (Transaction const& pending : cli->pending()) {
                if (h == pending.sha3()) {
                    //It is in Transaction Queue, waiting for sealing
                    Json::FastWriter fastWriter;
                    ostringstream oss;
                    oss << fastWriter.write(toJson(pending)) << std::flush;
                    desc = oss.str();
                    return true;
                }
            }
        }

        //toJson(client()->localisedTransaction(h));
        //refer to eth_getTransactionByHash
        auto localisedt = cli->localisedTransaction(h);
        blocknum = localisedt.blockNumber();

        blockstamp = 0; //HC: 上层无需用到

        blockmaturity = bc.number() - blocknum;

        //HC：超块链上寻找
        BlockHeader header = bc.info(localisedt.blockHash());

        int64_t start_hid = header.prevHID() + 1;
        int64_t end_hid = header.prevHID() + 2;

        BLOCKTRIPLEADDRESS triaddr;
        vector<int> vecHyperBlkIdLacking;

        std::vector<BlockHeader> headers;
        headers.emplace_back(std::move(header));
        if (ForwardFindBlockInMain(headers, start_hid, end_hid, triaddr, vecHyperBlkIdLacking) >=0) {
            hyperId = triaddr.hid;
            chainId = triaddr.chainnum;
            localId = triaddr.id;
        }

        return true;

    } catch (dev::Exception const& _e) {
        // Something else went wrong - drop it.
        strError = _e.what();
    }

    return false;
}

extern "C" BOOST_SYMBOL_EXPORT
bool GetTxDetails(const string &strhash, std::map<string, string> &mapparams, string &strError)
{
    if (!g_ptrWeb3) {
        strError = "The web3 object is not initialized, cannot get transaction";
        return false;
    }

    auto cli = g_ptrWeb3->ethereum();
    bool fFound = false;

    try {

        h256 h(strhash);
        Transaction tx;
        if (!cli->isKnownTransaction(h)) {
            for (Transaction const& pending : cli->pending()) {
                //It is in Transaction Queue, waiting for sealing
                if (h == pending.sha3()) {
                    tx = pending;
                    fFound = true;
                    break;
                }
            }
            if (!fFound) {
                strError = "Failed to get raw transaction";
                return false;
            }
        } else {
            tx = cli->transaction(h);
        }

        mapparams["amount"] = UnitConversionToPara(toString(tx.value()));
        mapparams["from"] = tx.sender().hex();
        mapparams["para_recv_script"] = toHex(tx.data());

        //HC: 定位交易所在链的区块位置
        const BlockChain& bc = g_ptrWeb3->ethereum()->blockChain();

        auto localisedt = cli->localisedTransaction(h);
        BlockHeader header = bc.info(localisedt.blockHash());

        int64_t start_hid = header.prevHID() + 1;
        int64_t end_hid = header.prevHID() + 2;
        BLOCKTRIPLEADDRESS triaddr;
        vector<int> vecHyperBlkIdLacking;

        std::vector<BlockHeader> headers;
        headers.emplace_back(std::move(header));

        if (ForwardFindBlockInMain(headers, start_hid, end_hid, triaddr, vecHyperBlkIdLacking) < 0) {
            strError = "Transaction cannot be found on the chain";
            return false;
        }

        mapparams["eth_tx_hid"] = StringFormat("%d", triaddr.hid);
        mapparams["eth_tx_chainid"] = StringFormat("%d", triaddr.chainnum);
        mapparams["eth_tx_localid"] = StringFormat("%d", triaddr.id);

        mapparams["genesis_block_hash"] = bc.genesisHash().hex();

        TransactionSkeleton t;
        t.from = tx.sender();

        //HC: 通过交易签名和hash提取公钥
        Public pubkey = dev::recover(tx.signature(), tx.sha3(WithoutSignature)); 
        mapparams["eth_tx_publickey"] = toJS(pubkey);

    } catch (dev::Exception const& e) {
        strError = e.what();
        return false;
    }

    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
bool VerifyTx(const string &genesispayload,     //交易所在链创世块
    const string &genesishash,
    const string &payload,                      //要验证的交易所在块
    const string &hextxhash,
    //const std::vector<unsigned char> &sendersignature,
    const string &senderpublickey,
    const string &amount, string &errinfo)
{
    //HC：1.验证链创世块是否一致
    BlockHeader genesisheader;
    bytes genesisblk = CryptoEthCurrency::ExtractBlock(genesispayload);
    try {
        genesisheader = BlockHeader(genesisblk);
        h256 h = genesisheader.hash();

        if (h.hex() != genesishash) {
            errinfo = "genesis block unmatched";
            return false;
        }
    } catch (Exception& ex) {
        errinfo = ex.what();
        return false;
    }


    //HC: how to extract transactions from block, refer to BlockChain::verifyBlock
    BlockHeader currheader;
    bytes blk = CryptoEthCurrency::ExtractBlock(payload);

    BlockHeader blkheader;
    try {
        blkheader = BlockHeader(blk);
    } catch (Exception& ex) {
        errinfo = ex.what();
        return false;
    }

    h256 txhash(hextxhash);

    //HC: 2. 验证交易合法性
    dev::Public pub(senderpublickey);
    string strValue = UnitConversionToEth(amount);

    u256 value = jsToU256(strValue);

    RLP r(blk);
    for (RLP const& tr : r[1]) {
        bytesConstRef d = tr.data();
        try {
            Transaction t(d, CheckTransaction::None);
            if (t.sha3() == txhash) {
                //HC: 对应的交易在块里找到了，提取公钥
                auto pk = recover(t.signature(), t.sha3(WithoutSignature));
                //HC: 3. 验证交易的转账金额以及公钥是否一致
                if (t.value() == value && pub == pk)
                    return true;
                break;
            }
        } catch (Exception&) {
            //ex << errinfo_phase(1);
            //ex << errinfo_transactionIndex(i);
            //ex << errinfo_transaction(d.toBytes());
            break;
        }
    }

    errinfo = "invalid transaction";
    return false;
}


#ifdef WIN32

BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#endif
