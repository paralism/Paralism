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

#include "alethapi.h"
#include "cryptoethcurrency.h"
#include "blocktriaddr.h"
#include "hyperblockmsgs.h"

#include "wnd/common.h"
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

#include <libethereum/hyperchaininfo.h>
#include <libweb3jsonrpc/Eth.h>
#include <libweb3jsonrpc/ModularServer.h>
#include <libweb3jsonrpc/JsonHelper.h>





using namespace std;
using namespace dev;
using namespace dev::eth;

namespace fs = boost::filesystem;
namespace pod = boost::program_options::detail;
namespace po = boost::program_options;


std::future<bool> g_aleth_future;
string g_aleth_argv;

map<string, vector<std::pair<string, string>>> map_Aleth_MultiArgs;

std::map<std::string, std::string> mapArgs;
std::map<std::string, std::vector<std::string> > mapMultiArgs;

Logger g_logger{ createLogger(VerbosityInfo, "hc") };


extern dev::WebThreeDirect *g_ptrWeb3;
extern unique_ptr<ModularServer<>> g_jsonrpcIpcServer;
extern string logChannels;
extern LoggingOptions loggingOptions;

extern void dev::setupLogging(LoggingOptions const& _options);

extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern int plugin_main(int argc, char** argv);

string ToString(const BlockHeader &header);

struct PluginContext;


bool RegisterTask(void* objFac)
{
    return true;
}

void UnregisterTask(void* objFac)
{
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


string GetHyperChainDataDir()
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
    string log_path = GetHyperChainDataDir();
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

bool ForwardFindBlockInMain(const BlockHeader &header, int h1, int h2, BLOCKTRIPLEADDRESS &blktriaddr, vector<int> &vecHyperBlkIdLacking)
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    int genesisHID = g_cryptoEthCurrency.GetHID();
    T_APPTYPE app(APPTYPE::ethereum, genesisHID, g_cryptoEthCurrency.GetChainNum(), g_cryptoEthCurrency.GetLocalID());

    if (h1 <= genesisHID) {
        h1 = genesisHID + 1;
    }

    for (int i = h1; i <= h2; ++i) {
        vector<T_PAYLOADADDR> vecPA;
        T_SHA256 thhash;
        if (hyperchainspace->GetLocalBlocksByHID(i, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                BlockHeader currheader;
                if (!CryptoEthCurrency::ResolveBlock(currheader, pa->payload)) {
                    LOG(g_logger)<< StringFormat("Fail to call ResolveBlock, Hyperblock Id: %d\n", i);
                    continue;
                }

                //HC: skip some hyper block
                if (currheader.number() < header.number()) {
                    break;
                }

                if (currheader.number() == header.number() && currheader.hash() == header.hash()) {
                    blktriaddr = pa->addr;
                    blktriaddr.hhash = thhash;
                    return true;
                }
            }
        } else {
            vecHyperBlkIdLacking.push_back(i);
        }
    }
    return false;
}


//HC: 从最大高度反向寻找未上超块链的第一个ethereum区块
//HC: 如何判断ethereum块在超块链上, 最可靠的办法是hash比对
void LatestBlockIndexOnChained(BlockHeader& onchainedblkheader)
{
    const BlockChain &bc = g_ptrWeb3->ethereum()->blockChain();

    using HyerBlkLoc = std::pair<uint32_t, T_SHA256>;
    using BlkHHash_HyerBlkLoc = std::pair<h256, HyerBlkLoc>;

    static boost::compute::detail::lru_cache<h256, HyerBlkLoc> blkheaderCache(50);

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    BlockHeader header = bc.info();

    list<BlkHHash_HyerBlkLoc> lruHBL;

    uint64 latestHID = LatestHyperBlock::GetHID();

    while (true) {
        auto blkheaderhash = header.hash();
        if(blkheaderCache.contains(blkheaderhash)) {
            //HC: cache命中, 在其中寻找
            boost::optional<HyerBlkLoc> o_blkheader_pos = blkheaderCache.get(blkheaderhash);
            auto & inner_val = o_blkheader_pos.get();

            if (hyperchainspace->CheckHyperBlockHash(inner_val.first, inner_val.second)) {
                lruHBL.push_front(make_pair(blkheaderhash, inner_val));
                break;
            }
        }

        //超块链上寻找
        BLOCKTRIPLEADDRESS triaddr;
        vector<int> vecHyperBlkIdLacking;
        if (ForwardFindBlockInMain(header, header.prevHID() + 1, latestHID, triaddr, vecHyperBlkIdLacking)) {
            HyerBlkLoc loc;
            loc.first = triaddr.hid;
            loc.second = triaddr.hhash;
            lruHBL.push_front(make_pair(blkheaderhash, loc));
            break;
        } else {
            //HC: 也许是没有超块，那么要去拉取超块, 拉取第一个缺少的块
            if (vecHyperBlkIdLacking.size() > 0) {
                RSyncRemotePullHyperBlock((uint32_t)vecHyperBlkIdLacking[0]);
            }
        }

        if (header.number() == 0)
            break;
        latestHID = header.prevHID();
        header = bc.info(header.parentHash());
    }

    for (auto & elm : lruHBL) {
        //HC: 排下区块的LRU顺序 让高度越大的块越最近被访问
        blkheaderCache.insert(elm.first, elm.second);
    }

    onchainedblkheader = header;
}

bool SwitchChainTo(const BlockHeader& pindexBlock)
{
    eth::Client *cli = g_ptrWeb3->ethereum();

    cli->rewind(pindexBlock.number());
    cli->completeSync();

    return true;
}

bool CommitChainToConsensus(deque<PostingBlock>& deqblock, string& requestid, string& errmsg)
{
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
    //HC: Just submit transaction data to buddy consensus layer.
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


bool PutChainCb()
{
    deque<PostingBlock> deqblock;
    h256 hhash;

    bool isSwithBestToValid = false;
    BlockHeader pindexValidStarting;

    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = g_ptrWeb3->ethereum()->blockChain();
    const ChainParams &chainparas = cli->chainParams();

    setThreadName(StringFormat("CB-%d", std::this_thread::get_id()));

    LOG(g_logger) << "Prepare for committing ethereum blocks to global consensus...";

    const CUInt128& mynodeid = getMyNodeID();

    ////FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        if (!cli->wouldSeal()) {
            LOG(g_logger) << "Cannot commit ethereum child chain when it isn't mining.";
            return false;
        }

        uint64 nHID = LatestHyperBlock::GetHID(&hhash);

        //HC: Select blocks to do consensus
        BlockHeader headerStart;
        LatestBlockIndexOnChained(headerStart);
        headerStart = bc.pnext(headerStart);

        if (!headerStart) {
            //HC: no any block need to commit
            return false;
        }

        LOG(g_logger) << StringFormat("Committing ethereum blocks from: %d (HID: %d %s)", headerStart.number(),
            headerStart.prevHID(), headerStart.prevHyperBlkHash().hex());

        //HC: Get blocks need to commit
        BlockHeader headerEnd = headerStart;
        while (headerEnd && headerEnd.prevHID() == nHID && headerEnd.prevHyperBlkHash() == hhash) {

            bytes blockdata = bc.block(headerEnd.hash());
            PostingBlock postingblk;
            if (headerEnd.author() == chainparas.author ||
                headerEnd.author() == cli->author()) {
                //HC: the block belongs to me
                postingblk.nodeid = mynodeid;
            }

            //HC: to do
            postingblk.hashMTRoot = headerEnd.transactionsRoot().hex();
            postingblk.vecMT = bc.transactionsVS(headerEnd.hash());

            postingblk.payload = CryptoEthCurrency::MakePayload(blockdata);
            deqblock.push_back(postingblk);
            headerEnd = bc.pnext(headerEnd);
        }

        auto nWillCommitBlocks = deqblock.size();
        if (nWillCommitBlocks < 2) {
            //HC: The blocks starting from 'pStart' is stale
            //HC: 有时候会出现nWillCommitBlocks == 1，而aleth未上超块子链数大于1的情况，所以进行链回退
            //HC: 紧邻的后一个块的前向超块ID值小于当前最新超块ID，就会出现这样的问题
            //HC: 当前实现里新增aleth块时没有对新块的超块合法性进行判断, 就会导致这样的问题，参见 resetCurrent populateFromParent
            isSwithBestToValid = true;
            pindexValidStarting = (nWillCommitBlocks == 0 ? bc.pprev(headerStart) : headerStart);
            LOG(g_logger) << StringFormat("Committing ethereum blocks too less: %d, and chain will switch to %d",
                        deqblock.size(), pindexValidStarting.number());
        }

        //HC: Switch chain to valid and return
        if (isSwithBestToValid) {
            SwitchChainTo(pindexValidStarting);
            return false;
        }
    }

    //HC: Commit blocks to hyper chain's consensus layer
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
    //HC: force owner of last block is me.
    tail_block->nodeid = mynodeid;

    string requestid, errmsg;
    if (!CommitChainToConsensus(deqblock, requestid, errmsg)) {
        LOG(g_logger) << StringFormat("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

    LOG(g_logger) << StringFormat("Committed ethereum chain(len:%d) for global consensus.", deqblock.size());
    return true;
}

bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    return true;
}

//HC: Accept a validated hyper block or multiple hyper blocks
bool AcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    CHAINCBDATA cbdata(mapPayload, hidFork, hid, thhash, isLatest);
    LOG(g_logger) << StringFormat("AcceptChainCb: a new hyper block has reached: %d", hid);
    hyperblockMsgs.insert(std::move(cbdata));
    hyperblockMsgs.process();
    return true;
}

//HC: 创建超块回调检查子链是否合法，如果不合法不会纳入超块链中
bool CheckChainCbWhenOnChaining(vector<T_PAYLOADADDR>& vecPA, uint32_t prevhid, T_SHA256& tprevhhash)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<BlockHeader> vecBlock;
    for (auto b : vecPA) {
        BlockHeader block;
        if (!CryptoEthCurrency::ResolveBlock(block, b.payload)) {
            return false; //ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    h256 prevhhash = h256(tprevhhash.toHexString());
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (vecBlock[i].prevHID() != prevhid ||
            vecBlock[i].prevHyperBlkHash() != prevhhash) {
            return false;
        }
        if (i > 0) {
            if (vecBlock[i].number() != vecBlock[i - 1].number() + 1 ||
                vecBlock[i].parentHash() != vecBlock[i - 1].hash() )
                return false;
        }
    }

    return true;
}

bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)
{

    return false;
}

bool GetNeighborNodes(list<string>& listNodes)
{

    return false;
}

void initializeCallbackFunctions()
{
    //HC: Register application callbacks,for example when a new block become onchained,one of callbacks is called.
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
}

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

    //HC: 货币数据目录加上创世块hash名的子目录，以便隔离发行的各种数字货币
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
    p[0] = "aleth";

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

        setThreadName("aleth"); //HC: for log output thread name, see BOOST_LOG_ATTRIBUTE_KEYWORD

        //HC: before calling plugin_main, firstly specify the data dir
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
    bool fRet = false;
    context->SetPluginContext();

    g_aleth_argv = "";

    int nIdxRun = -1;
    for (int i = 0; i < context->pc_argc; i++) {
        //HC: skip non-module options
        if (string(context->pc_argv[i]).find("-aleth-cmdline") == 0) {
            nIdxRun = i;
        }
    }

    if (nIdxRun >= 0) {
        AppParseParameters(context->pc_argc, context->pc_argv);

        string strDataDir = CreateChildDir("aleth");
        async_start_module(context->pc_argv[nIdxRun], strDataDir);
    }

    return true;
}

void StopApplication()
{
    uninitializeCallbackFunctions();
    g_sys_interrupted = 1;
    ExitHandler::exitHandler(0);
    g_aleth_future.wait();
}

bool IsStopped()
{
    //std::future_status status;
    //status = aleth_future.wait_for(std::chrono::milliseconds(10));
    //return (status == std::future_status::ready);

    return !ExitHandler::isrunning();
}

void AppInfo(string& info)
{
    if (!g_ptrWeb3) {
        return;
    }
    eth::Client *cli = g_ptrWeb3->ethereum();
    const BlockChain &bc = cli->blockChain();

    ostringstream oss;
    oss << "Aleth module's current coin hash: " << g_cryptoEthCurrency.GetHashPrefixOfGenesis() << endl
        << "Genesis block address: " << g_cryptoEthCurrency.GetHID() << " "
        << g_cryptoEthCurrency.GetChainNum() << " "
        << g_cryptoEthCurrency.GetLocalID() << endl
        << "Neighbor node amounts: " << g_ptrWeb3->peers().size() << ", 'e peers' for details" << endl;


    auto *sealeng = cli->sealEngine();
    bool isAllowed = sealeng->isMining(); //cli->wouldSeal();

    bool isSync = cli->isSyncing();

    oss << "Mining status: " << (isAllowed ? "mining" : "stopped") << endl;

    oss << "Current sealer in use: " << cli->sealer() << endl;
    oss << "CPU miners of sealer in use: " << EthashCPUMiner::instances() << endl;
    size_t readySet;
    auto s = cli->blockQueueStatus(readySet);
    oss << "BlockQueue size of readyset: " << readySet << endl;
    oss << "BlockQueue size of verifying: " << s.verifying << endl;
    BlockHeader head = cli->working().info();
    oss << "Working: "
        << head.number() << " "
        << head.hash().hex().substr(0,16) << "... "
        << head.parentHash().hex().substr(0, 16) << "... "
        << "prevHID: " << head.prevHID() << " "
        << head.prevHyperBlkHash().hex().substr(0, 16) << "..." << endl;
    oss << "Transaction queue: "
        << cli->transactionQueueStatus() << endl;


    oss << "Are we updating the chain (syncing or importing a new block)? " << (cli->isSyncing() ? "Yes":"No") << endl;
    oss << "Are we syncing the chain? " << (cli->isMajorSyncing() ? "Yes" : "No") << endl;

    if (!isAllowed) {
        oss << "Block generate disabled, use command 'e e' to enable\n";
    }

    info = oss.str();

    try {
        info += StringFormat("Last block number: %d %s...\n", bc.number(), bc.currentHash().hex().substr(0, 16));
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
        oss << toJson(bc.info(bc.numberHash(nheight)));
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

void executecmd(char *command, const list<string>& childcmds)
{
    list<string> newchildcmds = childcmds;

    std::shared_ptr<char*> app_argv(new char*[newchildcmds.size() + 2]);

    char **p = app_argv.get();
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

string callWeb3RPC(const string& rpcmethodname, const Json::Value& param)
{
    Json::Value output;
    if (!g_jsonrpcIpcServer) {
        output = "Json rpc Server object is nullptr";
    } else {
        Json::Value input(Json::arrayValue);
        input.append(param);

        jsonrpc::Procedure proc;
        proc.SetProcedureName(rpcmethodname);
        g_jsonrpcIpcServer->HandleMethodCall(proc, input, output);
    }
    Json::FastWriter fastWriter;
    ostringstream oss;
    oss << fastWriter.write(output) << std::flush;
    return oss.str();
}


std::string SearchTriAddrInHyperchain(const BlockHeader &blkhead)
{
    eth::Client* cli = g_ptrWeb3->ethereum();
    const BlockChain& bc = cli->blockChain();

    BLOCKTRIPLEADDRESS tripleaddr;

    int64_t latestHID = LatestHyperBlock::GetHID();
    int64_t nStartHID = blkhead.prevHID() + 1;
    if(nStartHID > latestHID)
        nStartHID = latestHID;

    //HC: 超块链上寻找
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

        cout << StringFormat("To get block triple address, need to scan Hyperblock: [%d...%d], do you want to continue(y/n, default:n)?",
            nStartHID, nEndHID);
        char c_action;
        cin >> std::noskipws >> c_action;
        if (c_action != 'y' && c_action != 'Y') {
            return "skipped by user";
        }
    }

    string rc;
    if (ForwardFindBlockInMain(blkhead, nStartHID, nEndHID, triaddr, vecHyperBlkIdLacking)) {

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

    oss << "       eth nodeid                                       : show Node ID\n";
    oss << "       eth chain                                        : show chain or query hash of a specified block\n";
    oss << "       eth peers                                        : show peers\n";
    oss << "       eth ba                                           : query balance for a address\n";
    oss << "       eth sendfrom <fromaccount> <toaddress> <n>       : transfer, unit is wei\n";
    oss << "       eth sendtoaddr <address> <n> [gas] [gasPrice]    : transfer, unit is wei\n";
    oss << "       eth miner <n>                                    : show or change the number of CPU miners\n";
    oss << "       eth e                                            : enable mining\n";
    oss << "       eth d                                            : disable mining\n";
    oss << "       eth a                                            : show or set author\n";
    oss << "       eth tx <txid>                                    : get detailed information about <txid>\n";


    return oss.str();
}

bool ConsoleCmd(const list<string>& cmdlist, string& info, string& savingcommand)
{
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

         {"ls",[](const list<string>&, bool fhelp) ->string {
                vector<CryptoEthCurrency> coins;
                CryptoEthCurrency::GetAllCoins(coins);

                auto currhash = g_cryptoEthCurrency.GetHashGenesisBlock();

                ostringstream oss;
                size_t i = 0;
                for (auto& t : coins) {
                    bool iscurrcoin = false;
                    if (currhash == t.GetHashGenesisBlock()) {
                        //HC: current using coin
                        iscurrcoin = true;
                    }
                    oss << StringFormat("%c %d\t%s\t[%u,%u,%u]\n",
                        iscurrcoin ? '*' : ' ',
                        i++,
                        t.GetHashPrefixOfGenesis().c_str(),
                        t.GetHID(), t.GetChainNum(), t.GetLocalID());
                }
                oss << "use 'coin ll [NO.]' for coin details\n";
                return oss.str();
            } },

        {"ll",[](const list<string>& l, bool fhelp) ->string {
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

        {"df",[](const list<string>& l, bool fhelp) ->string {
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

        //HC: iss
        {"iss",[](const list<string>& l, bool fhelp) ->string {
            //return doAction(issuecoin, l, fhelp, false);
            if (l.size() < 1) {
                return StringFormat("eth iss <filename>\n");
            }

            string configfile = *l.begin();
            g_cryptoEthCurrency.RsyncMiningGenesiBlock(configfile);
            return "";
        } },

        {"imp",[](const list<string>& l, bool fhelp) ->string {
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

        {"acc", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            executecmd("account", childcmds);
            return "";
        } },

        {"wallet", [](const list<string>& childcmds, bool fhelp) ->string {
            executecmd("wallet", childcmds);
            return "";
        } },

        {"nodeid", [](const list<string>& childcmds, bool fhelp) ->string {
            return StringFormat("Node ID: %s\n", g_ptrWeb3->enode());
        } },

        {"e", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            if (!cli->wouldSeal()) {
                cli->startSealing();
            }
            return cli->wouldSeal() ? "Mining started" :
                (loggingOptions.verbosity == 4 ? "Failed to start mining" :
                "Failed to start mining, use 'e log 4' to change log level for more information");
        } },

        {"d", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            if (cli->wouldSeal()) {
                cli->stopSealing();
            }
            return cli->wouldSeal() ? "Mining started" : "Mining stopped";
        } },

        { "a", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
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
            //eth_getTransactionByHash

        { "tx", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            if (childcmds.size() <= 0) {
                return "Input tx's hash";
            }

            string strHash = *childcmds.begin();

            Json::Value param = strHash;
            return callWeb3RPC("eth_getTransactionByHash", param);
        } },

        { "sendfrom", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
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
            return callWeb3RPC("eth_sendTransaction", param);
        } },

        { "sendtoaddr", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {

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

            return callWeb3RPC("eth_sendTransaction", param);
        } },

        { "miner", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {

            if (childcmds.size() <= 0) {
                return StringFormat("Number of CPU miner is %d\n", EthashCPUMiner::instances());
            }
            auto iter = childcmds.begin();
            int n = std::atoi(iter->c_str());

            EthashCPUMiner::setNumInstances(n);
            return "ok!\n";
        } },


        {"ba", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            ostringstream oss;

            Address addr = cli->author(); //HC: 当前挖矿地址
            BlockNumber num = LatestBlock;

            if (childcmds.size() > 0) {
                auto iter = childcmds.begin();
                addr = Address(*iter);

                //++iter;
                //if (iter != childcmds.end()) {
                //    num = std::atoi(iter->c_str());
                //}
            }
            oss << addr << ": " << formatBalance(cli->balanceAt(addr, num));
            return oss.str();
        } },

        {"peers", [&cli, &bc](const list<string>& childcmds, bool fhelp) ->string {
            //HC: node as a peer candidate. Node is added if discovery ping is successful and table has capacity.
            ostringstream oss;
            oss << "Active peer count: " << g_ptrWeb3->peerCount() << endl;
            oss << "Peers:\n";
            for (auto & peer : g_ptrWeb3->peers()) {
                oss << "\t" << peer << endl;
            }
            return oss.str();
        } },

        {"chain", [&cli, &bc, &chainpara](const list<string>& childcmds, bool fhelp) ->string {
            ostringstream oss;
            oss << "Genesis block hash: " << bc.genesisHash() << endl;
            oss << "Difficulty: 0x"<< std::hex << chainpara.difficulty << endl;
            oss << "minimumDifficulty: 0x" << std::hex <<  chainpara.minimumDifficulty << endl;
            oss << "chainID: " << std::dec <<  chainpara.chainID << endl;
            oss << "networkID: " <<  chainpara.networkID << endl;
            oss << "sealEngine: " <<  chainpara.sealEngineName << endl;


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

            oss << "\nTriple addr: " << SearchTriAddrInHyperchain(blkhead) << endl;

            return oss.str();
        } },

        {"log", [](const list<string>& childcmds, bool fhelp) ->string {
            if (childcmds.size() <= 0) {
                return StringFormat("Current log level: %d, valid value is <0 ~ 4>\n", loggingOptions.verbosity);
            }
            loggingOptions.verbosity = std::atoi(childcmds.begin()->c_str());;
            setupLogging(loggingOptions);
            return "Log level of ethereum has changed";
        } },

        {"logch", [](const list<string>& childcmds, bool fhelp) ->string {
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
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
std::string GetGenesisBlock(string & payload)
{
    return std::string("");
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
