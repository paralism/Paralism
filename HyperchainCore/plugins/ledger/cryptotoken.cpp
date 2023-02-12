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


#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"

#include "headers.h"
#include "util.h"
#include "plshared.h"
#include "cryptotoken.h"
#include "key_io.h"

#include <assert.h>

#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <map>
#include <vector>
#include <string>
using namespace std;

#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
namespace fs = boost::filesystem;
namespace pod = boost::program_options::detail;

#define GENESISBLOCK_VIN_COUNT 1
#define GEN_BLK_PUBKEY "gbpublickey"

extern string CreateChildDir(const string& childdir);
extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");

string GetKeyConfigFile()
{
    fs::path pathConfig;

    pathConfig = fs::path(GetHyperChainDataDir()) / "key.db";
    return pathConfig.string();
}

bool ReadKeyFromFile(CKey& key)
{
    //fs::ifstream streamConfig(GetKeyConfigFile("ledger"), std::ios::out | std::ios::binary);
    fs::ifstream streamConfig(GetKeyConfigFile());
    if (!streamConfig.good())
        return false;

    set<string> setOptions;
    setOptions.insert("*");

    std::map<std::string, std::string> mapKey;
    for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        mapKey[it->string_key] = it->value[0];
    }
    auto& k = mapKey["publickey"];
    std::vector<unsigned char> vchPubKey = ParseHex(k);
    key.SetPubKey(vchPubKey);

    auto& strkey = mapKey["privatekey"];
    auto vchPriKey = ParseHex(strkey);
    CPrivKey privkey;
    privkey.resize(vchPriKey.size());
    std::copy(vchPriKey.begin(), vchPriKey.end(), privkey.begin());

    key.SetPrivKey(privkey);
    return true;
}

bool WriteKeyToFile(const CKey& key)
{
    fs::ofstream streamConfig(GetKeyConfigFile());
    if (!streamConfig.good())
        return false;

    std::vector<unsigned char> vecPub = key.GetPubKey();
    string pubkey = HexStr(vecPub);
    streamConfig << "publickey" << " = " << pubkey << endl;

    CPrivKey vecPriv = key.GetPrivKey();
    string prikey = HexStr(vecPriv.begin(), vecPriv.end());
    streamConfig << "privatekey" << " = " << prikey << endl;

    return true;
}


CBlock CreateGenesisBlock(const string& name, const string& desc, vector<unsigned char> logo,
    const CScript& genesisOutputScript, uint32_t nTime,
    int32_t nVersion, const int64_t& genesisSupply, const GBPUBKEYS& vpubkeygenblk)
{
    CTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(GENESISBLOCK_VIN_COUNT);
    txNew.vout.resize(1);
    //HCE: 486604799 ==> 1d00ffff Which is Bitcoin's nBits
    //txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4)
    txNew.vin[0].scriptSig = CScript()
        << std::vector<unsigned char>((const unsigned char*)(&name[0]), (const unsigned char*)(&name[0]) + name.size());

    txNew.vin[0].scriptSig
        << std::vector<unsigned char>((const unsigned char*)(&desc[0]), (const unsigned char*)(&desc[0]) + desc.size());

    unsigned short n = vpubkeygenblk.size();
    txNew.vin[0].scriptSig
        << std::vector<unsigned char>((const unsigned char*)(&n), (const unsigned char*)(&n) + sizeof(n));


    unsigned short i = 0;
    for (auto &key : vpubkeygenblk) {
        txNew.vin[0].scriptSig
            << std::vector<unsigned char>((const unsigned char*)(&key[0]), (const unsigned char*)(&key[0]) + key.size());
        if (++i == n) {
            break;
        }
    }

    txNew.vin[0].scriptSig << logo;

    txNew.vout[0].nValue = genesisSupply;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}



/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

CBlock CreateGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion,
    const int64_t& genesisSupply, const GBPUBKEYS& vpubkeygenblk, const std::vector<unsigned char>& newPublicKey)
{
    //const CScript genesisOutputScript = CScript()
    //    << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;

    //HCE: Here public key, will change to use Bitcoin address
    const CScript genesisOutputScript = CScript() << newPublicKey << OP_CHECKSIG;

    return CreateGenesisBlock(name, desc, logo, genesisOutputScript, nTime, nVersion, genesisSupply, vpubkeygenblk);
}

CBlock SearchGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion, const int64_t& genesisReward,
    const GBPUBKEYS& vpubkeygenblk,
    const CKey& newKey)
{
    CBlock genesis;
    genesis = CreateGenesisBlock(nTime, name, desc, logo, nVersion, genesisReward, vpubkeygenblk, newKey.GetPubKey());

    return genesis;
}

//HCE: Use the following function to mine a new genesis block.
void NewGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion, const int64_t& genesisSupply,
    const GBPUBKEYS& vpubkeygenblk, CKey& newKey)
{
    CBlock genesis = SearchGenesisBlock(nTime, name, desc, logo, nVersion, genesisSupply, vpubkeygenblk, newKey);

    string strhash;
    string strMerkleRoothash;

    uint256 hashGenesis = genesis.GetHash();
    strhash = hashGenesis.ToString();

    uint256 hashMerkleRoot = genesis.hashMerkleRoot;
    strMerkleRoothash = hashMerkleRoot.ToString();

    vector<unsigned char> newPublicKey = newKey.GetPubKey();
    CBitcoinAddress address(newPublicKey);

    string pubkey(newPublicKey.begin(), newPublicKey.end());


#undef printf
    std::printf("%s:\nPublicKey: %s \nAddress: %s \nBlock Hash: %s\nMerkleRootHash: %s\n",
        __FUNCTION__,
        pubkey.c_str(),
        address.ToString().c_str(),
        strhash.c_str(),
        strMerkleRoothash.c_str());
    std::printf(" nTime: %d\n", nTime);
}

string GetTokenWalletFile(const string& name)
{
    fs::path pathConfig;
    pathConfig.append(name);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "wallet.dat";
    return pathConfig.string();
}

string TokenConfigPath(const string& shorthash)
{
    string relpath = StringFormat("%s", shorthash);
    return relpath;
}

string CryptoToken::GetTokenConfigPath()
{
    return TokenConfigPath(GetHashPrefixOfGenesis());
}

string CryptoToken::GetTokenConfigFile(const string& shorthash)
{
    fs::path pathConfig;

    std::string relpath = TokenConfigPath(shorthash);
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "token.ini";
    return pathConfig.string();
}

string CryptoToken::GetTokenConfigFile()
{
    fs::path pathConfig;

    std::string relpath = GetTokenConfigPath();
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "token.ini";
    return pathConfig.string();
}

bool CryptoToken::SearchPublicKeyIdx()
{
    int curr_pkidx = _npkidx;

    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        int i = 0;
        for (auto& keystr : _vpublickeygenblk) {

            CPubKey publickey = CPubKey::NewPubKey(keystr, true);
            CTxDestination address = GetDestinationForKey(publickey, DEFAULT_ADDRESS_TYPE);

            if (IsValidDestination(address)) {
                CKey keyPair;
                string error;
                if (pwalletMain->GetKeyFromDestination(address, keyPair, error).IsValid()) {
                    _npkidx = i;
                    break;
                }
            }
            i++;
        }
    }

    if (_npkidx != curr_pkidx) {
        //HCE: pkidx has changed
        return true;
    }
    return false;
}


std::string CryptoToken::ToString()
{
    ostringstream oss;
    for (auto &elm : _mapSettings) {
        oss << strprintf("%-28s %s\n",elm.first.c_str(), elm.second.c_str());
    }

    oss << strprintf("%-28s %u\n", "number of gbpublickeys", _vpublickeygenblk.size());
    return oss.str();
}

bool CryptoToken::ParseTimestamp(const CBlock& genesis)
{
    if (genesis.vtx[0].vin.size() != GENESISBLOCK_VIN_COUNT) {
        return false;
    }

    const CScript& scriptSig = genesis.vtx[0].vin[0].scriptSig;
    opcodetype opcode;
    vector<unsigned char> vch;
    auto script_iter = scriptSig.cbegin();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    _mapSettings["name"] = string(vch.begin(), vch.end());

    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    _mapSettings["description"] = string(vch.begin(), vch.end());

    //HCE: public key
    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }

    assert(vch.size() == sizeof(unsigned short));
    unsigned short n = 0;
    memcpy(&n, vch.data(), sizeof(n));

    unsigned short i = 0;
    for (; i < n; i++) {
        vch.clear();
        if (!scriptSig.GetOp(script_iter, opcode, vch)) {
            return false;
        }
        _vpublickeygenblk.push_back(vch);
    }

    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    _mapSettings["logo"] = string(vch.begin(), vch.end());

    return true;
}

bool CryptoToken::ParseToken(const CBlock& genesis)
{
    _mapSettings["time"] = std::to_string(genesis.nTime);
    _mapSettings["version"] = std::to_string(genesis.nVersion);

    try {
        if (!ParseTimestamp(genesis))
            return false;

        _mapSettings["supply"] = std::to_string(genesis.vtx[0].vout[0].nValue / COIN);

        opcodetype opcode;
        vector<unsigned char> vch;
        CScript scriptSig = genesis.vtx[0].vout[0].scriptPubKey;
        auto script_iter = scriptSig.cbegin();
        if (!scriptSig.GetOp(script_iter, opcode, vch)) {
            return false;
        }

        _mapSettings["publickey"] = HexStr(vch);

        std::vector<unsigned char> ownerPublicKey(vch.begin(), vch.end());

        CBitcoinAddress addr(ownerPublicKey);
        _mapSettings["address"] = addr.ToString();

        _mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
        _mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
    }
    catch (std::exception & e) {
        std::printf("%s Failed %s\n", __FUNCTION__, e.what());
        return false;
    }

    return true;
}

bool CryptoToken::IsSysToken(const string& shorthash)
{
    return shorthash == GetHashPrefixOfSysGenesis();
}

//HCE: if shorthash is empty,then find one
bool CryptoToken::ReadTokenFile(const string& name, string& shorthash, string& errormsg)
{
    if (shorthash.empty() && !name.empty()) {
        if (!SearchTokenByName(name, shorthash, errormsg)) {
            return false;
        }
    }

    string datapath = TokenConfigPath(shorthash);

    if (IsSysToken(shorthash)) {
        SelectNetWorkParas();
        return true;
    }
    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            if (item_begin->path().filename().string() == datapath) {

                fs::ifstream streamConfig(GetTokenConfigFile(shorthash));
                if (!streamConfig.good()) {
                    errormsg = "cannot open token configuration file";
                    return false;
                }

                set<string> setOptions;
                setOptions.insert("*");

                for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
                    if (it->string_key == GEN_BLK_PUBKEY) {
                        _vpublickeygenblk.push_back(ParseHex(it->value[0]));
                        continue;
                    }
                    _mapSettings[it->string_key] = it->value[0];
                }
                return true;
            }
        }
    }
    errormsg = "cannot find the token named " + name;
    return false;
}


bool CryptoToken::ReadIssCfg(const string& cfgfile, map<string, string>& mapGenenisBlkParams, vector<string>& vpublickey, string& errormsg)
{
    fs::path pathConfig;

    fs::ifstream streamConfig(cfgfile);
    if (!streamConfig.good()) {
        pathConfig = fs::path(GetHyperChainDataDir()) / cfgfile;
        streamConfig.open(pathConfig);
        if (!streamConfig.good()) {
            errormsg = strprintf("Cannot open file '%s'", cfgfile.c_str());
            return false;
        }
    }

    set<string> setOptions;
    setOptions.insert("*");

    for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        if (it->string_key == GEN_BLK_PUBKEY) {
            vpublickey.push_back(it->value[0]);
        }
        else {
            mapGenenisBlkParams[it->string_key] = it->value[0];
        }
    }

    if (!mapGenenisBlkParams.count("name")) {
        errormsg = "Token name cannot be empty";
        return false;
    }

    if (vpublickey.size() < 2) {
        errormsg = "Too few the public key provided ";
        return false;
    }

    return true;
}

bool CryptoToken::GetAllTokens(vector<CryptoToken>& tokens)
{
    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            string shorthash = item_begin->path().filename().string();
            if (IsSysToken(shorthash)) {
                continue;
            }
            CryptoToken cc;
            string errmsg;
            if (cc.ReadTokenFile("", shorthash, errmsg)) {
                tokens.push_back(cc);
            }
        }
    }

    return true;
}

bool CryptoToken::SearchTokenByTriple(uint32_t hid, uint16 chainnum, uint16 localid,
    string& coinname, string& coinshorthash)
{
    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            string shorthash = item_begin->path().filename().string();

            CryptoToken cc;
            string errmsg;
            if (cc.ReadTokenFile("", shorthash, errmsg)) {
                if (cc.IsTokenSame(hid, chainnum, localid)) {
                    coinname = cc.GetName();
                    coinshorthash = cc.GetHashPrefixOfGenesis();
                    return true;
                }
            }
        }
    }

    return false;
}

bool CryptoToken::SearchTokenByName(const string& tokenname, string& tokenshorthash, string& errormsg)
{
    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {

            string currpath = item_begin->path().filename().string();
            CryptoToken t;
            if (t.ReadTokenFile("", currpath, errormsg)) {
                if (t.GetName() == tokenname) {
                    listPath.push_back(currpath);
                }
            }
        }
    }

    if (listPath.size() == 0 || listPath.size() > 1) {
        //I don't know read which one
        listPath.size() > 1 ? (errormsg = "found multiple token named " + tokenname) :
            (errormsg = "cannot find token named " + tokenname);
        return false;
    }

    tokenshorthash = *listPath.begin();
    return true;
}

bool CryptoToken::WriteTokenFile()
{
    CreateChildDir(GetTokenConfigPath());
    fs::ofstream streamConfig(GetTokenConfigFile());
    if (!streamConfig.good())
        return false;

    for (auto& optional : _mapSettings) {
        streamConfig << optional.first << " = " << optional.second << endl;
    }

    for (auto& optional : _vpublickeygenblk) {
        streamConfig << GEN_BLK_PUBKEY << " = " << HexStr(optional) << endl;
    }

    return true;
}

CBlock CryptoToken::GetGenesisBlock()
{
    string& logo = _mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    vector<unsigned char> pubkey = ParseHex(_mapSettings["publickey"]);

    return CreateGenesisBlock(std::stol(_mapSettings["time"]),
        _mapSettings["name"],
        _mapSettings["description"],
        veclogo,
        std::stoi(_mapSettings["version"]),
        std::stoll(_mapSettings["supply"]) * COIN, _vpublickeygenblk, pubkey);
}


//HCE: Use the following function to mine a new genesis block.
CBlock CryptoToken::MineGenesisBlock(const CKey& newKey)
{
    string& logo = _mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    CBlock genesis = SearchGenesisBlock(
        std::stol(_mapSettings["time"]),
        _mapSettings["name"],
        _mapSettings["description"],
        veclogo,
        std::stoi(_mapSettings["version"]),
        std::stoll(_mapSettings["supply"]) * COIN, _vpublickeygenblk, newKey);

    string strhash;
    string strMerkleRoothash;

    _mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
    strhash = _mapSettings["hashgenesisblock"];

    _mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
    strMerkleRoothash = _mapSettings["hashmerkleroot"];

    std::vector<unsigned char> newPublicKey = newKey.GetPubKey();
    CBitcoinAddress address(newPublicKey);

    string pubkey = HexStr(newPublicKey);
    _mapSettings["publickey"] = pubkey;
    _mapSettings["address"] = address.ToString();

    (std::printf)("\nPrivate key(WIF-compressed): %s \nAddress: %s \nBlock Hash: %s\nMerkleRootHash: %s\n",
        PrKey2WIF(newKey.GetPrivKey(), true).c_str(),
        address.ToString().c_str(),
        strhash.c_str(),
        strMerkleRoothash.c_str());

    return genesis;
}

bool CryptoToken::AddKeyToWallet(const CKey& newKey)
{
    //HCE: write key into new application's wallet
    string strWallet = GetTokenWalletFile(GetTokenConfigPath());
    {
        CWallet wallet(strWallet.c_str());
        {
            CWalletDB db(wallet.strWalletFile, "cr+");
        }
        std::vector<unsigned char> vchDefaultKey = newKey.GetPubKey();

        CPubKey publickey = CPubKey::NewPubKey(vchDefaultKey, true);

        std::vector<unsigned char> vch_short;
        vch_short.insert(vch_short.end(), publickey.begin(), publickey.end());

        LegacyScriptPubKeyMan* pman = wallet.GetOrCreateLegacyScriptPubKeyMan();
        if (!pman) {
            return false;
        }

        //HCE: Add uncompressed key
        if (!wallet.AddKey(vchDefaultKey, newKey)) {
            return false;
        }

        //HCE: Add compressed key
        if (!wallet.AddKey(vch_short, newKey)) {
            return false;
        }

        if (wallet.SetDefaultKey(vch_short)) {

            CTxDestination dest = GetDestinationForKey(publickey, DEFAULT_ADDRESS_TYPE);
            return wallet.SetAddressBookName(dest, "");
        }
        return false;
    }

    return true;
}

bool CryptoToken::ContainToken(const string& tokenhash)
{
    bool isDefaultCoin = (tokenhash == GetHashPrefixOfSysGenesis());

    if (isDefaultCoin) {
        return true;
    }

    CryptoToken currency(isDefaultCoin);
    currency.SelectNetWorkParas();

    string tknhash = tokenhash;
    string errmsg;
    if (!isDefaultCoin && !currency.ReadTokenFile("", tknhash, errmsg)) {
        return false;
    }

    if (!currency.CheckGenesisBlock()) {
        return false;
    }

    return true;
}

bool CryptoToken::CheckGenesisBlock()
{
    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stol(_mapSettings["hid"]),
        std::stol(_mapSettings["chainnum"]),
        std::stol(_mapSettings["localid"]));

    if (!addr.isValid()) {
        return ERROR_FL("The genesis block address of cryptotoken is invalid");
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
        RSyncRemotePullHyperBlock(addr.hid);
        return ERROR_FL("The genesis block of cryptotoken: %s not exists...", addr.tostring().c_str());
    }

    CBlock genesis;
    if (!ResolveBlock(genesis, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    uint256 hashGenesis = genesis.GetHash();
    uint256 hashG = uint256S(_mapSettings["hashgenesisblock"].c_str());
    if (hashGenesis != hashG) {
        return ERROR_FL("hashGenesis FAILED");
    }
    return true;
}


string CryptoToken::GetPath()
{
    string apppath = (fs::path(GetHyperChainDataDir()) / GetTokenConfigPath()).string();
    return apppath;
}

string CryptoToken::GetHashPrefixOfSysGenesis()
{
    CryptoToken cc;
    cc.SelectNetWorkParas();
    return cc.GetHashPrefixOfGenesis();
}

string CryptoToken::GetNameOfSysGenesis() {
    CryptoToken cc;
    cc.SelectNetWorkParas();
    return cc.GetName();

};

void CryptoToken::SetDefaultParas()
{
    _mapSettings = { {"name", "ledger"},
                       {"description","www.hyperchain.net"},
                       {"logo",""},
                       {"version","2"},
                       {"supply","100000000"},   //HCE: Initial Supply
                       {"time","1568277586"},
                       {"address","1CJmHdwaCvzkoY4vGJTM9v8CCA9Ge1kLmw"}, //HCE: Initial Supply's owner address, it is uint160.tostring(), CBitcoinAddress address(publickey)
                       {"publickey","04ad943c2f812817b188e65b3ce7ee8c808ba14e146044ee8abf5926e371560807f37f28c84906e0779b3552425e9d804c068173154ca35c7a33e5579fab381307"},
                       {"hashgenesisblock","f3cf23f0f7b4633aa5765cd79b8a50e8098ee31b338a4cb70ff4e6d0d83ad614"},
                       {"hashmerkleroot","d57bbb366497bd47c38ac2038bf3d8f4852e547d1d5438e6abc1b7751f50325c"},
                       {"hid","0"},
                       {"chainnum","1"},         //HCE: any value, but don't set 0
                       {"localid","0"},          //HCE: any value
    };
}

void CryptoToken::SelectNetWorkParas()
{
    string model = "sandbox";
    if (mapArgs.count("-model")) {
        model = mapArgs["-model"];
        if (model == "informal" || model == "formal") {
            _mapSettings = { {"name", "ledger"},
                      {"description","www.hyperchain.net"},
                      {"logo",""},
                      {"version","2"},
                      {"supply","100000000"},                           //HCE: Initial Supply
                      {"time","1572531412"},
                      {"address","1Ao8Rk36otR5uksWQffCgcvQ6Y5YNkDB8J"}, //HCE: Initial Supply's owner address, it is uint160.tostring(), CBitcoinAddress address(publickey)
                      {"publickey","040b29eb299db9348698e3bad3fa0532e98a4ceccf4d55786ea97222647ad0bf3327fca5cfef0809638bb67c5f9ca0b5badad32ff78203408eef64b75702990ba8"},
                      {"hashgenesisblock","ffba651f664db75948190eaf9234a4b6646a1c6b98e5cbc74deda4a4668fb3aa"},
                      {"hashmerkleroot","bb076e94df2fc651e7040d2e7ba0232fc37b9b2bb511b33f967ce1d5b9cee4cd"},
                      {"hid","22030"},
                      //{"chainnum","1"}, //HCE: because no built-in ledger chain, so change into a invalid chainnum and localid
                      {"chainnum","0"},
                      {"localid","0"},
            };
            return;
        }
    }
    //HCE: sandbox
    SetDefaultParas();
}

uint256 CryptoToken::GetBlocksHash(const std::vector<CBlock>& vblock)
{
    uint256 hash;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto& blk : vblock) {
        auto h = blk.GetHash();
        SHA256_Update(&ctx, &h, sizeof(h));
    }
    SHA256_Final((unsigned char*)&hash, &ctx);
    return hash;
}


bool CryptoToken::SignBlocks(std::vector<CBlock>& vblock, vector<unsigned char>& vchSig)
{
    uint256 hash;
    hash = GetBlocksHash(vblock);
    return GetSign(&hash, &hash, vchSig);
}

bool CryptoToken::VerifyBlocks(int pkidx, const vector<unsigned char>& vchSig, const std::vector<CBlock>& vblock)
{
    if (pkidx < 0 || pkidx >= (int)(_vpublickeygenblk.size())) {
        return false;
    }

    uint256 h;
    h = GetBlocksHash(vblock);
    return Verify(pkidx, vchSig, &h, &h);
}


CryptoToken g_cryptoToken;
