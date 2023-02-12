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

#include "headers/gen_int.h"

#include <libdevcore/FixedHash.h>
#include <libethereum/ChainParams.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>


#include <map>
#include <vector>
#include <string>
#include <iterator>
using namespace dev;
using namespace dev::eth;

typedef struct _tagGENESIS_ACC {
public:
    bytes genesis;              AccountMap accmap;          std::string jsonconfig;      
    bytes to() {
        RLPStream block(3); //HC：准备压入2个List
        block.appendList(1)             << genesis;

                        block.appendList(1)             << jsonconfig;

        int s = accmap.size();
        block.appendList(1 + s * 3);
        block.append(s);
        for (auto & elm : accmap) {
            block.append(elm.first);
            block.append(elm.second.nonce());
            block.append(elm.second.balance());
        }
        return block.out();
    }

    bool from(const bytes &blk)
    {
        RLP rlp(blk);
        if(!rlp[0].isList())
            return false;

        genesis = rlp[0][0].toBytes();
        jsonconfig = rlp[1][0].toString();

        int nList = 2;
        if(!rlp[nList].isList())
            return false;

        int s = rlp[nList][0].toInt<uint32_t>();
        accmap.clear();
        for (int i = 0; i < s; i++) {
            Address addr = rlp[nList][i * 3 + 1].toHash<h160>();
            u256 nonce = rlp[nList][i * 3 + 2].toInt<u256>();
            u256 balance = rlp[nList][i * 3 + 3].toInt<u256>();

            accmap.insert(std::make_pair<Address, Account>(std::move(addr), Account(nonce, balance)));
        }
        return true;
    }

} GENESIS_ACC;



class CApplicationSettings {
public:
    CApplicationSettings();

private:
    CApplicationSettings(const CApplicationSettings&);
    void operator=(const CApplicationSettings&);

public:

    void WriteDefaultApp(const std::string& hash)
    {
        boost::property_tree::ptree pt;
        pt.put(_key, hash);
        boost::property_tree::ini_parser::write_ini(_configfile, pt);
    }

    void ReadDefaultApp(string& hash);

private:
    std::string _configfile;
    const std::string _key = "App.ethcoinhash";
};


//HC:
//HC: @brief Ethereum兼容的加密数字货币类 
//HC: 加载并提供加密货币的基本参数及其他辅助功能

//HCE:
//HCE: @brief Ethereum-compatible cryptocurrencies
//HCE: Load and provide basic parameters and other auxiliary features of cryptocurrencies
//HCE:
class CryptoEthCurrency
{
public:
    CryptoEthCurrency()
    { }
    typedef std::map<std::string, std::string>::iterator iterator;
    typedef std::map<std::string, std::string>::const_iterator const_iterator;
    iterator begin() { return mapSettings.begin(); }
    iterator end() { return mapSettings.end(); }

    const_iterator begin() const { return mapSettings.begin(); }
    const_iterator end() const { return mapSettings.end(); }

    static bool ResolveBlock(BlockHeader& blockheader, const std::string& payload);
    static bytes ExtractBlock(const std::string& payload);       static std::string MakePayload(const bytes& blk);        
    bool LoadCryptoCurrency(bool &isBuiltIn);

    bool isNullCurrency()
    {
        return GetChainNum() == 0;
    }

    //HC: 返回加密货币创世块所在超块高度
    //HCE: Get the Hyperblock height where the cryptocurrency genesis block is located
    uint32_t GetHID() {
        return std::stoul(mapSettings["hid"]);
    }

    //HC: 返回加密货币创世块所在超块的子链号
    //HCE: Get the subchain number of the Hyperblock where the cryptocurrency genesis block is located
    uint16_t GetChainNum() {
        return std::stoul(mapSettings["chainnum"]);
    }

    //HC: 返回加密货币创世块所在超块子链的块号
    //HCE: Get the block number of subchain of the Hyperblock where the cryptocurrency genesis block is located
    uint16_t GetLocalID() { return std::stoul(mapSettings["localid"]); }

    h256 GetHashGenesisBlock() { return h256(mapSettings["hashgenesisblock"]); }
    std::string GetHashPrefixOfGenesis() { return mapSettings["hashgenesisblock"]; }

    static boost::filesystem::path GetCurrencyRootPath();

    boost::filesystem::path getConfigFile()
    {
        return GetCurrencyRootPath() / boost::filesystem::path("config.rlp");
    }


    static std::string GetHashPrefixOfSysGenesis();
    static bool ContainCurrency(const std::string& currencyhash);

    void SetName(const std::string& appname) { mapSettings["name"] = appname; }
    void SetParas(const std::map<std::string, std::string>& settings)
    {
        for (auto& optional : mapSettings) {
            if (settings.count(optional.first)) {
                optional.second = settings.at(optional.first);
            }
        }
    }

    bool SetGenesisAddr(uint32_t hid, uint16_t chainnum, uint16_t localid)
    {
        mapSettings["hid"] = std::to_string(hid);
        mapSettings["chainnum"] = std::to_string(chainnum);
        mapSettings["localid"] = std::to_string(localid);
        return WriteCoinFile();
    }

    bool ParseCoin(const bytes &payload);

    bool IsCurrencySame(uint32_t hid, uint16_t chainnum, uint16_t localid) {
        return GetHID() == hid && GetChainNum() == chainnum && GetLocalID() == localid;
    }

        bool ReadCoinFile(const std::string& shorthash, std::string& errormsg);
    bool WriteCoinFile();

    static bool GetAllCoins(vector<CryptoEthCurrency>& coins);

    static bool SearchCoinByTriple(uint32_t hid, uint16 chainnum, uint16 localid, std::string& coinname, std::string& coinshorthash);

    bool CheckGenesisBlock();

    bytes GetPanGuGenesisBlock();
    bytes GetGenesisBlock();

    void clear() {
        for (auto& optional : mapSettings) {
            if (optional.first != "bits" &&
                optional.first != "version" &&
                optional.first != "reward" &&
                optional.first != "model" &&
                optional.first != "genesisbits" &&
                optional.first != "time") {
                optional.second = "";
            }
        }
        mapSettings["hid"] = "0";
        mapSettings["chainnum"] = "0";
        mapSettings["localid"] = "0";
    }

    void SetDefaultParas();
    void SelectNetWorkParas();
    std::string GetCurrencyConfigPath();

    bool RsyncMiningGenesiBlock(const std::string& configfile);

    static std::string GetCurrencyConfigFile(const std::string& shorthash);

    std::string ToString();

    static std::string GetPanGuSettings();

    void SetChainParams(std::shared_ptr<ChainParams> sp)
    {
        m_spChainParams = sp;
    }

    std::shared_ptr<ChainParams> GetChainParams()
    {
        return m_spChainParams;
    }



private:

    bool ParseTimestamp(const bytes& genesis);
    std::string GetInformalNetSettings();

private:
    std::map<std::string, std::string> mapSettings;
    std::shared_ptr<ChainParams> m_spChainParams;

};

extern CryptoEthCurrency g_cryptoEthCurrency;
