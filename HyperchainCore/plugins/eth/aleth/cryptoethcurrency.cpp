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

#include "headers/inter_public.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"

#include "cryptoethcurrency.h"

#include <libethereum/ChainParams.h>

using namespace dev;
using namespace dev::eth;



#include <map>
#include <vector>
#include <string>
using namespace std;

#define GENESISBLOCK_VIN_COUNT 1

#include <libdevcore/FileSystem.h>

#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

namespace fs = boost::filesystem;
namespace pod = boost::program_options::detail;


CryptoEthCurrency g_cryptoEthCurrency;

extern bool ResolveBlock(BlockHeader& block, const string& payload);
extern bool CommitGenesisToConsensus(const bytes& block, string& requestid, string& errmsg);

extern std::map<std::string, std::string> mapArgs;


extern string GetHyperChainDataDir();

string CreateDataChildDir(const string& childdir)
{
    //HC: in parent directory
    fs::path logpath(getDataDir(".."));

    logpath /= childdir;
    if (!fs::exists(logpath)) {
        fs::create_directories(logpath);
    }
    return logpath.string();
}



CApplicationSettings::CApplicationSettings() {
    _configfile = GetHyperChainDataDir();
    _configfile += "/";
    _configfile += "hc.ini";
}

void CApplicationSettings::ReadDefaultApp(string& hash)
{
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::ini_parser::read_ini(_configfile, pt);
        hash = pt.get<std::string>(_key);
        return;
    }
    catch (std::exception e) {

    }
    hash = CryptoEthCurrency::GetHashPrefixOfSysGenesis();
}

bytes CreateGenesisBlock(const string& configJSON)
{
    auto chainParams = ChainParams{ configJSON };
    return chainParams.genesisBlock();
}


string CurrencyConfigPath(const string& shorthash)
{
    if (shorthash.empty()) {
        return "built-in";
    }
    return shorthash;
}

//HC: Here should be change to pull application block in the future
static std::map<uint32_t, time_t> mapPullingHyperBlock;
static std::mutex cs_pullingHyperBlock;
void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "")
{
    {
        std::lock_guard l(cs_pullingHyperBlock);
        time_t now = time(nullptr);
        if (mapPullingHyperBlock.count(hid) == 0) {
            mapPullingHyperBlock.insert({ hid, now });
        } else {
            if (now - mapPullingHyperBlock[hid] < 60) {
                //HC: already pulled
                return;
            } else {
                mapPullingHyperBlock[hid] = now;
            }
        }
        auto bg = mapPullingHyperBlock.begin();
        for (; bg != mapPullingHyperBlock.end();) {
            if (bg->second + 300 < now) {
                bg = mapPullingHyperBlock.erase(bg);
            } else {
                ++bg;
            }
        }
    }
    std::thread t([hid, nodeid]() {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        if (hyperchainspace) {
            if (nodeid.empty()) {
                hyperchainspace->GetRemoteHyperBlockByID(hid);
                //INFO_FL("GetRemoteHyperBlockByID: %d", hid);
            } else {
                hyperchainspace->GetRemoteHyperBlockByID(hid, nodeid);
                //INFO_FL("GetRemoteHyperBlockByID: %d, from node: %s", hid, nodeid.c_str());
            }
        }
        });
    t.detach();
}


string CryptoEthCurrency::GetCurrencyConfigPath()
{
    return CurrencyConfigPath(GetHashPrefixOfGenesis());
}

fs::path CryptoEthCurrency::GetCurrencyRootPath()
{
    fs::path pathRoot = getDataDir(".");
    return pathRoot;
}

string CryptoEthCurrency::GetCurrencyConfigFile(const string& shorthash)
{
    fs::path pathConfig;

    if (shorthash.empty()) {
        pathConfig = GetCurrencyRootPath() / "coin.json";
        return pathConfig.string();
    }

    std::string relpath = CurrencyConfigPath(shorthash);
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(getDataDir("..")) / pathConfig / "coin.json";
    return pathConfig.string();
}

bool CryptoEthCurrency::ParseTimestamp(const bytes& genesis)
{
    /*   if (genesis.vtx[0].vin.size() != GENESISBLOCK_VIN_COUNT) {
           return false;
       }

       const CScript& scriptSig = genesis.vtx[0].vin[0].scriptSig;
       opcodetype opcode;
       vector<unsigned char> vch;

       auto script_iter = scriptSig.cbegin();
       if (!scriptSig.GetOp(script_iter, opcode, vch)) {
           return false;
       }
       mapSettings["name"] = string(vch.begin(), vch.end());

       vch.clear();
       if (!scriptSig.GetOp(script_iter, opcode, vch)) {
           return false;
       }
       mapSettings["description"] = string(vch.begin(), vch.end());

       vch.clear();
       if (!scriptSig.GetOp(script_iter, opcode, vch)) {
           return false;
       }
       mapSettings["model"] = string(vch.begin(), vch.end());

       vch.clear();
       if (!scriptSig.GetOp(script_iter, opcode, vch)) {
           return false;
       }
       mapSettings["logo"] = string(vch.begin(), vch.end());*/

    return true;
}

bool CryptoEthCurrency::ParseCoin(const bytes& payload)
{
    GENESIS_ACC ga;
    if (!ga.from(payload)) {
        cerr << "ParseCoin: extract genesis block FAILED";
        return false;
    }

    BlockHeader header(ga.genesis);

    mapSettings["hashgenesisblock"] = header.hash().hex();

    /*  mapSettings["time"] = std::to_string(genesis.nTime);
      mapSettings["version"] = std::to_string(genesis.nVersion);

      try {
          if (!ParseTimestamp(genesis))
              return false;

          mapSettings["reward"] = std::to_string(genesis.vtx[0].vout[0].nValue / COIN);

          std::ostringstream oss;
          oss << "0x" << std::hex << genesis.nNonce;
          mapSettings["nonce"] = oss.str();

          oss.str("");
          oss << "0x" << std::hex << genesis.nBits;
          mapSettings["genesisbits"] = oss.str();

          vector<unsigned char> vecMix(genesis.nSolution.size());
          std::reverse_copy(std::begin(genesis.nSolution), std::end(genesis.nSolution), vecMix.begin());

          uint256 mixhash(vecMix);
          mapSettings["hashmix"] = mixhash.ToString();

          mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
          mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
      }
      catch (std::exception & e) {
          std::printf("%s Failed %s\n", __FUNCTION__, e.what());
          return false;
      }*/

    return true;
}


//HC: if shorthash is empty,then find one
bool CryptoEthCurrency::ReadCoinFile(const string& shorthash, string& errormsg)
{
    string datapath = CurrencyConfigPath(shorthash);

    boost::filesystem::path p = getDataDir("..");
    if (!fs::exists(p)) {
        return false;
    }

    fs::directory_iterator item_begin(p);
    fs::directory_iterator item_end;

    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            if (item_begin->path().filename().string() == datapath) {

                fs::ifstream streamConfig(GetCurrencyConfigFile(shorthash));
                if (!streamConfig.good()) {
                    errormsg = "cannot open coin configuration file";
                    return false;
                }

                set<string> setOptions;
                setOptions.insert("*");

                for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
                    mapSettings[it->string_key] = it->value[0];
                }


                //string strJsonconfig = mapSettings["config"];
                //while (true) {
                //    string strLine;
                //    std::getline(streamConfig, strLine);
                //    strJsonconfig += strLine;
                //    if (!streamConfig.good()) {
                //        break;
                //    }
                //}
                //m_spChainParams = make_shared<ChainParams>(strJsonconfig);
                return true;
            }
        }
    }
    errormsg = "cannot find the coin";
    return false;
}

std::string CryptoEthCurrency::ToString()
{
    ostringstream oss;
    for (auto& elm : mapSettings) {
        oss << StringFormat("%-28s %s\n", elm.first.c_str(), elm.second);
    }

    return oss.str();
}

bool CryptoEthCurrency::GetAllCoins(vector<CryptoEthCurrency>& coins)
{
    fs::directory_iterator item_begin(getDataDir(".."));
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            string shorthash = item_begin->path().filename().string();

            CryptoEthCurrency cc;
            string errmsg;
            if (cc.ReadCoinFile(shorthash, errmsg)) {
                coins.push_back(cc);
            }
        }
    }

    return true;
}

bool CryptoEthCurrency::SearchCoinByTriple(uint32_t hid, uint16 chainnum, uint16 localid,
    string& coinname, string& coinshorthash)
{
    fs::directory_iterator item_begin(getDataDir(".."));
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            string shorthash = item_begin->path().filename().string();

            CryptoEthCurrency cc;
            string errmsg;
            if (cc.ReadCoinFile(shorthash, errmsg)) {
                if (cc.IsCurrencySame(hid, chainnum, localid)) {
                    coinshorthash = cc.GetHashPrefixOfGenesis();
                    return true;
                }
            }
        }
    }

    return false;
}

bool CryptoEthCurrency::WriteCoinFile()
{
    CreateDataChildDir(GetCurrencyConfigPath());
    fs::ofstream streamConfig(GetCurrencyConfigFile(GetHashPrefixOfGenesis()));
    if (!streamConfig.good())
        return false;

    for (auto& optional : mapSettings) {
        streamConfig << optional.first << " = " << optional.second << endl;
    }
    return true;
}


bytes CryptoEthCurrency::GetPanGuGenesisBlock()
{
    return CreateGenesisBlock(GetPanGuSettings());
}

bytes CryptoEthCurrency::GetGenesisBlock()
{
    return m_spChainParams->genesisBlock(); //CreateBlockByConfig(mapSettings);
}

bool CryptoEthCurrency::ContainCurrency(const string& currencyhash)
{
    bool isDefaultCoin = (currencyhash == GetHashPrefixOfSysGenesis());

    CryptoEthCurrency currency;
    //currency.SelectNetWorkParas();

    string coinhash = currencyhash;
    string errmsg;

    if (!isDefaultCoin && !currency.ReadCoinFile(coinhash, errmsg)) {
        return false;
    }

    if (!currency.CheckGenesisBlock()) {
        return false;
    }

    return true;
}

bool CryptoEthCurrency::ResolveBlock(BlockHeader& blockheader, const string& payload)
{
    try {
        RLP rlp(payload);
        if (!rlp[0].isList())
            return false;

        blockheader = BlockHeader(rlp[0][0].toBytes());
        return true;
    }
    catch (std::exception &e) {
        cerr <<  StringFormat("Error %s: %s", __FUNCTION__, e.what());
    }
    return false;
}


bytes CryptoEthCurrency::ExtractBlock(const string& payload)
{
    bytes block;
    try {
        RLP rlp(payload);
        if (rlp[0].isList())
            block = rlp[0][0].toBytes();
    }
    catch (std::exception &e) {
        cerr << StringFormat("Error %s: %s", __FUNCTION__, e.what());
    }
    return block;
}


std::string CryptoEthCurrency::MakePayload(const bytes& blk)
{
    RLPStream block(1); //HC：准备压入1个List
    block.appendList(1) //HC: 此list后跟1个元素, 如果n个那么这里就是n
        << blk;
    const bytes &b = block.out();
    return string(b.begin(), b.end());
}

bool CryptoEthCurrency::CheckGenesisBlock()
{
    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stol(mapSettings["hid"]),
        std::stol(mapSettings["chainnum"]),
        std::stol(mapSettings["localid"]));

    if (!addr.isValid()) {
        cerr << "CheckGenesisBlock: The genesis block address of CryptoEthCurrency is invalid";
        return false;
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {

        RSyncRemotePullHyperBlock(addr.hid);
        cerr << StringFormat("CheckGenesisBlock: The genesis block of CryptoEthCurrency: %s not exists...", addr.tostring());
        return false;
    }

    GENESIS_ACC ga;
    if (!ga.from(bytes(payload.begin(), payload.end()))) {
        cerr << "CheckGenesisBlock: extract genesis block FAILED";
        return false;
    }

    //HC：从创世块解析出链参数
    m_spChainParams = make_shared<ChainParams>(ga.jsonconfig, ga.genesis, ga.accmap);

    //m_spChainParams->populateFromGenesisWithoutCalc(bytes(payload.begin(), payload.end()));

    BlockHeader genesis = BlockHeader(ga.genesis);

    h256 hashGenesis = genesis.hash();
    h256 hashG = h256(mapSettings["hashgenesisblock"].c_str());
    if (hashGenesis != hashG) {
        cerr << "CheckGenesisBlock: hashGenesis FAILED";
        return false;
    }
    return true;
}

string CryptoEthCurrency::GetHashPrefixOfSysGenesis()
{
    CryptoEthCurrency cc;
    cc.SelectNetWorkParas();
    return cc.GetHashPrefixOfGenesis();
}

bool CryptoEthCurrency::RsyncMiningGenesiBlock(const string& configfile)
{
    string errmsg;
    fs::ifstream streamConfig(configfile);
    if (!streamConfig.good()) {
        errmsg = StringFormat("Error: cannot open file : %s", configfile);
        cerr << errmsg;
        return false;
    }

    string strJsonconfig;
    while (true) {
        string strLine;
        std::getline(streamConfig, strLine);
        strJsonconfig += strLine;
        if (!streamConfig.good()) {
            break;
        }
    }

    ChainParams test(strJsonconfig);

    GENESIS_ACC ga;
    ga.genesis = test.genesisBlock();
    ga.accmap = test.genesisState; //HC: 账户信息
    ga.jsonconfig = strJsonconfig;

    BlockHeader header(ga.genesis);
    if (ReadCoinFile(header.hash().hex(), errmsg)) {
        cerr << "The CryptoCoin already existed";
        return false;
    }

    string requestid;
    if (!CommitGenesisToConsensus(ga.to(), requestid, errmsg)) {
        string tmp = string("CommitGenesisToConsensus failed: ") + errmsg;
        cerr << StringFormat("%s", tmp);
        return false;
    }
    cout << "Genesis block has committed, requestId: " << requestid << endl;
    return true;
}

//HC: What is Pan Gu, creator of the universe in Chinese mythology
//HC: ethereum genesis block address is [1 1 x]
std::string CryptoEthCurrency::GetPanGuSettings()
{
    string jsonconfig = {
        R"({
          "sealEngine": "Ethash",
          "params" : {
            "accountStartNonce": "0x00",
            "maximumExtraDataSize" : "0x20",
            "homesteadForkBlock" : "0x00",
            "daoHardforkBlock" : "0x00",
            "EIP150ForkBlock" : "0x00",
            "EIP158ForkBlock" : "0x00",
            "byzantiumForkBlock" : "0x00",
            "constantinopleForkBlock" : "0x00",
            "constantinopleFixForkBlock" : "0x00",
            "istanbulForkBlock" : "0x00",
            "minGasLimit" : "0x5208",
            "maxGasLimit" : "0x7fffffffffffffff",
            "tieBreakingGas" : false,
            "gasLimitBoundDivisor" : "0x0400",
            "minimumDifficulty" : "0x100000",
            "difficultyBoundDivisor" : "0x0800",
            "durationLimit" : "0x0d",
            "blockReward" : "0x4563918244F40000",
            "networkID" : "0x1",
            "chainID" : "0x1",
            "allowFutureBlocks" : false
          },
          "genesis": {
            "nonce": "0x0000000000000068",
            "difficulty" : "0x200000",
            "mixHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
            "author" : "0x0000000000000000000000000000000000000001",
            "timestamp" : "0x62EB346B",
            "parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
            "extraData" : "0x655741534d2074657374206e6574776f726b2030",
            "gasLimit" : "0x989680",
            "previousHID" : 0,
            "previousHHash" : "0x7ba6ba2d20d407737d531cf2e8417b1567ddde85d6ba355145714166e9da3fe4"
          },
            "accounts": { }
        }
        )"
        //62EB346B: 2022-08-04 10:52:27
        //HC: 可以预写账户，格式如下：
        //"accounts": {
        //      "003d122ebc2585327bd415c686c0525777227cca" : {
        //      "balance" : "0x100000000000000000000000000000000000000000000000000000000000000"
        //  },
        //      "00abd65de23279941e63d58638d6ac9d3c11d08d" : {
        //      "balance" : "0x200000000000000000000000000000000000000000000000000000000000000"
        //  }
        //}
    };
    return jsonconfig;
}


std::string CryptoEthCurrency::GetInformalNetSettings()
{
    string jsonconfig = {
        R"({
          "sealEngine": "Ethash",
          "params" : {
            "accountStartNonce": "0x00",
            "maximumExtraDataSize" : "0x20",
            "homesteadForkBlock" : "0x00",
            "daoHardforkBlock" : "0x00",
            "EIP150ForkBlock" : "0x00",
            "EIP158ForkBlock" : "0x00",
            "byzantiumForkBlock" : "0x00",
            "constantinopleForkBlock" : "0x00",
            "constantinopleFixForkBlock" : "0x00",
            "istanbulForkBlock" : "0x00",
            "minGasLimit" : "0x5208",
            "maxGasLimit" : "0x7fffffffffffffff",
            "tieBreakingGas" : false,
            "gasLimitBoundDivisor" : "0x0400",
            "minimumDifficulty" : "0x100000",
            "difficultyBoundDivisor" : "0x0800",
            "durationLimit" : "0x0d",
            "blockReward" : "0x4563918244F40000",
            "networkID" : "0x2",
            "chainID" : "0x2",
            "allowFutureBlocks" : false
          },
          "genesis": {
            "nonce": "0x0000000000000069",
            "difficulty" : "0x200000",
            "mixHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
            "author" : "0x0000000000000000000000000000000000000001",
            "timestamp" : "0x62EB35BD",
            "parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
            "extraData" : "0x655741534d2074657374206e6574776f726b2030",
            "gasLimit" : "0x989680",
            "previousHID" : 0,
            "previousHHash" : "0x7ba6ba2d20d407737d531cf2e8417b1567ddde85d6ba355145714166e9da3fe4"
          },
        }
        )"
        //HC：62EB35BD: 2022-08-04 10:58:05
        //HC：previousHID and previousHHash 需要适当调整
    };
    return jsonconfig;
}


void CryptoEthCurrency::SetDefaultParas()
{
    //HC: sandbox，这里可以调整，采用不同的设置
    //m_spChainParams = make_shared<ChainParams>(GetPanGuSettings());
}

void CryptoEthCurrency::SelectNetWorkParas()
{
    if (mapArgs.count("-pangu")) {
        //m_spChainParams = make_shared<ChainParams>(GetPanGuSettings());
        return;
    }

    string model = "sandbox";
    if (mapArgs.count("-model")) {
        model = mapArgs["-model"];
        if (model == "informal" || model == "formal") {
            //m_spChainParams = make_shared<ChainParams>(GetInformalNetSettings());
            return;
        }
    }

    //HC: sandbox
    SetDefaultParas();
}


bool CryptoEthCurrency::LoadCryptoCurrency(bool &isBuiltIn)
{
    //HC: which coin will be used?
    CApplicationSettings appini;
    string defaultAppHash;
    appini.ReadDefaultApp(defaultAppHash);

    isBuiltIn = false;
    string errmsg;
    string coinhash = defaultAppHash;

    if (coinhash.empty()) {
        goto emptycoin;
    }

    //HC: load currency
    if (!ReadCoinFile(coinhash, errmsg)) {
        cerr << StringFormat("Not found cryptocurrency: %s\n", coinhash);
        goto emptycoin;
    }

    if (!CheckGenesisBlock()) {
        goto emptycoin;
    }

    if (defaultAppHash != coinhash) {
        appini.WriteDefaultApp(coinhash);
    }

    cout << StringFormat("Current coin for aleth module : %s [%u,%u,%u]\n",
        GetHashPrefixOfGenesis(),
        GetHID(), GetChainNum(), GetLocalID());
    return true;

emptycoin:
    m_spChainParams = make_shared<ChainParams>(GetPanGuSettings());
    mapSettings["hid"] = "0";
    mapSettings["chainnum"] = "0";
    mapSettings["localid"] = "0";
    cout << "****************************************************************************************************\n";
    cout << "* Warning: cannot find any currency for aleth module, use command to import or issue a new one !!! *\n";
    cout << "****************************************************************************************************\n";
    isBuiltIn = true;
    return true;

}

CryptoEthCurrency g_CryptoEthCurrency;
