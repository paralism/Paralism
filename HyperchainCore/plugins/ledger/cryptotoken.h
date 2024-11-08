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

#include "block.h"

#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#else
#include <stdint.h>
#endif

#include <map>
#include <vector>
#include <string>
#include <iterator>
using namespace std;

using GBPUBKEYS =std::vector<std::vector<unsigned char>>;

extern CWallet* pwalletMain;

string GetKeyConfigFile();
bool ReadKeyFromFile(CKey& key);
bool WriteKeyToFile(const CKey& key);

CBlock CreateGenesisBlock(uint32_t nTime, const char* pszTimestamp, uint64 nNonce,
    const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const int64_t& genesisSupply, const GBPUBKEYS& vpubkeygenblk);

class CryptoToken
{
public:
    CryptoToken(bool isParacoin = true)
    {
        SetDefaultParas();
        if (!isParacoin) {
            clear();
        }
    }
    typedef std::map<std::string, std::string>::iterator iterator;
    typedef std::map<std::string, std::string>::const_iterator const_iterator;
    iterator begin() { return _mapSettings.begin(); }
    iterator end() { return _mapSettings.end(); }

    const_iterator begin() const { return _mapSettings.begin(); }
    const_iterator end() const { return _mapSettings.end(); }


    uint32_t GetHID() { return std::stoul(_mapSettings["hid"]); }
    uint16_t GetChainNum() { return std::stoul(_mapSettings["chainnum"]); }
    uint16_t GetLocalID() { return std::stoul(_mapSettings["localid"]); }

    std::string GetName() { return _mapSettings["name"]; }
    std::string GetDesc() { return _mapSettings["description"]; }
    std::string GetLogo() { return _mapSettings["logo"]; }
    std::string GetPublickey() { return _mapSettings["publickey"]; }
    std::string GetAddress() { return _mapSettings["address"]; }
    string GetPath();

    int64_t GetSupply() { return std::stoull(_mapSettings["supply"]); }

    uint256 GetHashGenesisBlock() { return uint256S(_mapSettings["hashgenesisblock"]); }
    string GetHashPrefixOfGenesis() { return _mapSettings["hashgenesisblock"]; }

    static string GetHashPrefixOfSysGenesis();
    static string GetNameOfSysGenesis();

    static bool ContainToken(const string& tokenhash);

    bool AddKeyToWallet(const CKey& newKey);

    void SetName(const std::string& appname) { _mapSettings["name"] = appname; }

    void SetGenBlkPubKeys(GBPUBKEYS&& keys) { _vpublickeygenblk = std::move(keys); }

    void SetParas(const std::map<string, string>& settings)
    {
        for (auto& optional : _mapSettings) {
            if (settings.count(optional.first)) {
                optional.second = settings.at(optional.first);
            }
        }
    }

    bool SetGenesisAddr(uint32_t hid, uint16_t chainnum, uint16_t localid)
    {
        _mapSettings["hid"] = std::to_string(hid);
        _mapSettings["chainnum"] = std::to_string(chainnum);
        _mapSettings["localid"] = std::to_string(localid);
        return WriteTokenFile();
    }

    bool ParseToken(const CBlock& genesis);

    bool IsSysToken()
    {
        return GetHashPrefixOfGenesis() == GetHashPrefixOfSysGenesis();
    }

    static bool IsSysToken(const string& shorthash);

    bool IsTokenSame(uint32_t hid, uint16_t chainnum, uint16_t localid) {
        return GetHID() == hid && GetChainNum() == chainnum && GetLocalID() == localid;
    }
    //HCE: if shorthash is empty, will scan the directory and find one
    bool ReadTokenFile(const string& name, string& shorthash, string& errormsg);

    static bool ReadIssCfg(const string& cfgfile, map<string, string>& mapGenenisBlkParams, vector<string>& vpublickey, string& errormsg);

    static bool GetAllTokens(vector<CryptoToken> &tokens);

    static bool SearchTokenByName(const string& coinname, string& coinshorthash, string& errormsg);
    static bool SearchTokenByTriple(uint32_t hid, uint16 chainnum, uint16 localid, string& coinname, string& coinshorthash);
    bool WriteTokenFile();
    bool CheckGenesisBlock();

    CBlock MineGenesisBlock(const CKey& key);
    CBlock GetGenesisBlock();

    void clear() {
        for (auto& optional : _mapSettings) {
            if (optional.first != "version" &&
                optional.first != "supply" &&
                optional.first != "time") {
                optional.second = "";
            }
        }
        _mapSettings["hid"] = "0";
        _mapSettings["chainnum"] = "0";
        _mapSettings["localid"] = "0";
    }

    void SetDefaultParas();
    void SelectNetWorkParas();
    string GetTokenConfigPath();

    static string GetTokenConfigFile(const string& shorthash);

    bool SearchPublicKeyIdx();

    inline bool AmIConsensusNode()
    {
        if (_npkidx < 0 || _npkidx >= (int)(_vpublickeygenblk.size())) {
            return false;
        }
        return true;
    }

    size_t GetNumbersOfConsensusNodes()
    {
        return _vpublickeygenblk.size();
    }

    int GetPKIdx() {
        return _npkidx;
    }

    template<typename T1, typename T2>
    bool GetSign(const T1 pbegin, const T2 pend, vector<unsigned char> &vchSig)
    {
        if (!AmIConsensusNode()) {
            return false;
        }

        CKey key;

        CRITICAL_BLOCK(cs_main)
            CRITICAL_BLOCK(pwalletMain->cs_wallet)
        {
            CPubKey publickey = CPubKey::NewPubKey(_vpublickeygenblk[_npkidx], true);
            CTxDestination address = GetDestinationForKey(publickey, DEFAULT_ADDRESS_TYPE);

            string error;
            if (!pwalletMain->GetKeyFromDestination(address, key, error).IsValid()) {
                return false;
            }
        }

        uint256 h = Hash(pbegin, pend);
        return key.Sign(h, vchSig);
    }

    template<typename T1, typename T2>
    bool Verify(int pkidx, const vector<unsigned char>& vchSig, const T1 pbegin, const T2 pend)
    {
        if (pkidx < 0 ||
            pkidx >= (int)(_vpublickeygenblk.size()) ||
            vchSig.size() == 0 ) {
            return false;
        }

        CKey key;
        key.SetPubKey(_vpublickeygenblk[pkidx]);

        uint256 h = Hash(pbegin, pend);
        return key.Verify(h, vchSig);
    }

    bool SignBlocks(std::vector<CBlock>& vblock, vector<unsigned char>& vchSig);
    bool VerifyBlocks(int pkidx, const vector<unsigned char>& vchSig, const std::vector<CBlock>& vblock);

    string ToString();

private:
    bool ParseTimestamp(const CBlock& genesis);
    string GetTokenConfigFile();

    uint256 GetBlocksHash(const std::vector<CBlock>& deqblock);


private:

    std::map<std::string, std::string> _mapSettings;
    GBPUBKEYS _vpublickeygenblk;  //HCE: public key, their owners can generate block

    int _npkidx = -1;                    //HCE: public key index which belong to me in _vpublickeygenblk

    CKey _key;
};

extern CryptoToken g_cryptoToken;
