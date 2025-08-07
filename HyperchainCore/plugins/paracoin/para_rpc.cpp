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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include "cryptopp/sha.h"
#include "headers.h"
#include "util/threadname.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "cryptocurrency.h"
#include "paratask.h"
#include "db/dbmgr.h"
#include "para_rpc.h"
#include "key_io.h"
#include "consensus/consensus_engine.h"
#include "sysexceptions.h"

#include "../AppPlugins.h"

#undef printf
#include <boost/asio.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> SSLStream;
#endif
#define printf OutputDebugStringF
// MinGW 3.4.5 gets "fatal error: had to relocate PCH" if the json headers are
// precompiled in headers.h.  The problem might be when the pch file goes over
// a certain size around 145MB.  If we need access to json_spirit outside this
// file, we could use the compiled json_spirit option.

using namespace std;
using namespace boost;
using namespace boost::asio;

void ThreadRPCServer2(void* parg);
typedef Value(*rpcfn_type)(const Array& params, bool fHelp);
extern map<string, rpcfn_type> mapCallTable;

static int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::list<std::shared_ptr<boost::asio::io_service>> rpcServerList;

extern "C" BOOST_SYMBOL_EXPORT
bool GetTxState(const string& txhash, int& blocknum, int64_t& blockstamp, int& blockmaturity,
    int64_t& hyperId,
    int64_t& chainId,
    int64_t& localId,
    string& desc,
    string& strError);

extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

extern map<uint256, CTransaction> mapTransactions;
extern CCriticalSection cs_mapTransactions;
extern ParaMQCenter paramqcenter;

Value issuecoin(const Array& params, bool fHelp);
Value gid2rid(const Array& params, bool fHelp);
Value commitcoin(const Array& params, bool fHelp);
Value querygenesisblock(const Array& params, bool fHelp);
Value getcoininfo(const Array& params, bool fHelp);
Value importcoin(const Array& params, bool fHelp);
//Value startmining(const Array& params, bool fHelp);
//Value stopmining(const Array& params, bool fHelp);
Value queryminingstatus(const Array& params, bool fHelp);

Object JSONRPCReplyObject(const Value& result, const Value& error, const Value& id);
string JSONRPCReply(const Value& result, const Value& error, const Value& id);
Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}


void PrintConsole(const char* format, ...)
{
    char buffer[50000];
    int limit = sizeof(buffer);
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit - 1] = 0;
    }
    fprintf(stdout, "%s", buffer);
}


int64 AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 210000000.0)
        throw JSONRPCError(-3, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(-3, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(int64 amount)
{
    return (double)amount / (double)COIN;
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    entry.push_back(Pair("confirmations", wtx.GetDepthInMainChain()));
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    //entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    entry.push_back(Pair("time", strprintf("%lld(UTC:%s)", wtx.GetTxTime(),
                        DateTimeStrFormat("%x %H:%M:%S", wtx.GetTxTime()).c_str())));
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(-11, "Invalid account name");
    return strAccount;
}



///
/// Note: This interface may still be subject to change.
///


Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "help [command]\n"
            "List commands, or get help for a command.");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    string strRet;
    set<rpcfn_type> setDone;
    for (map<string, rpcfn_type>::iterator mi = mapCallTable.begin(); mi != mapCallTable.end(); ++mi)
    {
        string strMethod = (*mi).first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod == "getamountreceived" ||
            strMethod == "getallreceived" ||
            (strMethod.find("label") != string::npos))
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        try
        {
            Array params;
            rpcfn_type pfn = (*mi).second;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != -1)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "stop\n"
            "Stop Paracoin server.");

    // Shutdown will take long enough that the response should get back
    PrintConsole("Para: executing RPC stop command...unload Para module\n");

    hc::CreateThread("ParaStopShutdown", Shutdown, NULL);
    return "Server is stopping";
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight; //Let SPV decide the current maximum height

    //if (nBestHeight > BLOCK_MATURITY)
    //    return nBestHeight - BLOCK_MATURITY;
    //return 0;
}


Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw runtime_error(
            "getblockhash\n"
            "Returns the hash of a block in the longest block chain.");

    int nIdx = params.size() - 1;
    int height = params[nIdx].get_array()[0].get_int();
    Value id = params[nIdx].get_array()[1];

    Array arrResult;
    if (height > nBestHeight) {
        throw JSONRPCError(-1, "Error: block height too large");
        //int i = nIdx;
        //for (; i >= 0; i--) {
        //    if (params[nIdx].get_array()[0].get_int() > nBestHeight) {
        //        auto obj = JSONRPCError(-1, "Error: block height too large");
        //        arrResult.push_back(obj);
        //    }
        //    else
        //        break;
        //}
        //nIdx = i;
        //height = params[nIdx].get_array()[0].get_int();
    }

    //HCE: make calling mapBlockIndex::pprev rapidly: avoid db open and close repeatedly
    CTxDB_Wrapper txdb;

    uint256 hashbegin;
    uint256 hashend;
    height = params[0].get_array()[0].get_int();
    if (!paramqcenter.MTC_GetRange(height, hashbegin, hashend)) {
        throw JSONRPCError(-1, strprintf("The block(height %d) cannot be found in main chain\n", height));
    }

    CBlockIndexSP p = mapBlockIndex[hashbegin];
    CBlockIndexSP pNext;
    nIdx = 0;
    while (p) {
        if (p->nHeight == height) {
            Object result = JSONRPCReplyObject(p->GetBlockHash().ToString(), Value::null, id);
            arrResult.push_back(result);
            if (++nIdx >= params.size())
                break;
            height = params[nIdx].get_array()[0].get_int();
            id = params[nIdx].get_array()[1];
        }
        pNext = p->pnext();
        if (!pNext && p->nHeight < nBestHeight) {
            PrintConsole("RPC getblockhash: Next block index of a Para block(%d %s) is empty, please try to run: 'c checkchain %d' to fix it.\n",
                p->nHeight, p->GetBlockHash().ToPreViewString().c_str(),
                p->nHeight - 10);
        }
        p = pNext;
    }

    if (arrResult.size() != params.size()) {

        throw JSONRPCError(-1, "Some blocks cannot be found in main chain\n");
        //int i = nIdx;
        //for (; i >= 0; i--) {
        //    if (params[nIdx].get_array()[0].get_int() > nBestHeight) {
        //        auto obj = JSONRPCError(-1, "Error: the block cannot be found in main chain");
        //        arrResult.push_back(obj);
        //    }
        //}
    }

    return arrResult;
}

Object get_a_rawtransaction(const Array& params)
{
    uint256 hashtx(params[0].get_str());

    int verbosity = 0;
    if (params.size() > 1) {
        if (params[1].type() == str_type)
            verbosity = std::atoi(params[1].get_str().c_str()); //HCE: for command line
        else
            verbosity = params[1].get_int();
    }
    //int height = params[2].get_int();

    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    CTransaction tx;
    bool fFound = txdb.ReadTxIndex(hashtx, txindex);

    auto fngettx = [](const CTransaction& tx, int verbo, int confirm, const CTxIndex &idx) -> Object {
        CDataStream ssTx;
        ssTx << (CTransaction)tx;
        std::string strHex = HexStr(ssTx.begin(), ssTx.end());

        Object obj;
        obj.push_back(Pair("hex", strHex));
        if (verbo > 0) {
            obj.push_back(Pair("in_active_chain", (bool)(confirm > 0 ? 1 : 0)));
            obj.push_back(Pair("confirmations", confirm));
            if (confirm > 0) {
                obj.push_back(Pair("txindex", idx.pos.ToString()));
            }
        }
        return obj;
    };

    if (fFound) {
        if (tx.ReadFromDisk(txindex.pos)) {
            if (tx.GetHash() == hashtx) {
                return fngettx(tx, verbosity, txindex.GetDepthInMainChain(), txindex);
            }
        }
    } else {
        CRITICAL_BLOCK(cs_mapTransactions)
            if (mapTransactions.count(hashtx)) {
                //already exist in transaction pool
                return fngettx(mapTransactions[hashtx], verbosity, 0, txindex);
            }
    }

    throw JSONRPCError(-6, "Failed to get raw transaction");
}

//HCE: This interface has two kinds usage
Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw runtime_error(
            "getrawtransaction [txid] [verbosity]\n"
            "Return the raw transaction data. If verbosity is 1, returns a index for the transaction");

    Array arrParam;
    if (params[0].type() == array_type) {
        Array arrResult;
        for (size_t i = 0; i < params.size(); i++) {
            const Array &arrParam = params[i].get_array();
            Object tx = get_a_rawtransaction(arrParam);
            Value id = arrParam[1];

            Object result = JSONRPCReplyObject(tx[0].value_, Value::null, id);
            arrResult.push_back(result);
        }
        return arrResult;
    }
    return get_a_rawtransaction(params);
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw runtime_error(
            "getblock\n"
            "\nIf verbosity is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n" );

    int nIdx = 0;
    uint256 hashblock(params[0].get_array()[0].get_str());
    bool verbosity = params[0].get_array()[1].get_bool();
    Value id = params[0].get_array()[2];

    Array arrResult;
    while (true) {
        CBlockIndexSP p = mapBlockIndex[hashblock];
        if (p) {
            CBlock block;
            if (block.ReadFromDisk(p)) {
                CDataStream ssBlock;
                ssBlock << block;
                std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());

                Object result = JSONRPCReplyObject(strHex, Value::null, id);
                arrResult.push_back(result);
            }
        } else {
                Object result = JSONRPCReplyObject("00", -1, id);
                arrResult.push_back(result);
        }

        if (++nIdx >= params.size())
            break;
        hashblock = uint256S(params[nIdx].get_array()[0].get_str());
        id = params[nIdx].get_array()[2];
    }

    return arrResult;
}

extern bool ProcessReceivedTx(CNode* pfrom, CTransaction& tx);
Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw runtime_error(
            "sendrawtransaction\n"
            "\nSubmit a raw transaction (serialized, hex-encoded) to local node and network.\n");

    CDataStream ssData;
    ssData << params[0].get_str();
    std::string strTx;
    ssData >> strTx;
    auto vecTx = ParseHex(strTx);

    CDataStream ssTx(vecTx);
    CTransaction tx;
    ssTx >> tx;

    //HCE: FeeRate, maybe use in the future
    //int64 nAmount = AmountFromValue(params[1]);

    //HCE: Broadcast
    if (!ProcessReceivedTx(nullptr, tx)) {
        throw JSONRPCError(-1, tx.m_strRunTimeErr);
    }

    uint256 h = tx.GetHash();
    return h.ToString();
}


Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "getrawmempool\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n");


    Array arrResult;
    CRITICAL_BLOCK(cs_mapTransactions)
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi) {
            CTransaction& tx = (*mi).second;
            arrResult.push_back(tx.GetHash().ToString());
        }

    return arrResult;
}

Value getblocknumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblocknumber\n"
            "Returns the block number of the latest block in the longest block chain.");

    return nBestHeight;
}


Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");

    return (int)vNodes.size();
}


double GetDifficulty()
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.

    if (pindexBest == NULL)
        return 1.0;
    int nShift = (pindexBest->nBits >> 24) & 0xff;

    double dDiff =
        //HCE: Here, bitcoin code is: (double)0x0000ffff / (double)(pindexBest->nBits & 0x00ffffff);
        (double)0x00000fff / (double)(pindexBest->nBits & 0x00ffffff);

    //HCE: while (nShift < 29), why 29? because block.nBits = 0x1d00ffff; 0x1d = 29
    while (nShift < 32)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 32)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    return (bool)fGenerateBitcoins;
}


Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    if (params.size() > 1)
    {
        int nGenProcLimit = params[1].get_int();
        fLimitProcessors = (nGenProcLimit != -1);
        WriteSetting("fLimitProcessors", fLimitProcessors);
        if (nGenProcLimit != -1)
            WriteSetting("nLimitProcessors", nLimitProcessors = nGenProcLimit);
        if (nGenProcLimit == 0)
            fGenerate = false;
    }

    GenerateBitcoins(fGenerate, pwalletMain);
    return Value::null;
}


Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 8000)
        return (boost::int64_t)0;
    return (boost::int64_t)dHashesPerSec;
}


Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    Object obj;
    obj.push_back(Pair("version", (int)VERSION));
    obj.push_back(Pair("balance", ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("blocks", (int)nBestHeight));
    obj.push_back(Pair("connections", (int)vNodes.size()));
    obj.push_back(Pair("proxy", (fUseProxy ? addrProxy.ToStringIPPort() : string())));
    obj.push_back(Pair("generate", (bool)fGenerateBitcoins));
    obj.push_back(Pair("genproclimit", (int)(fLimitProcessors ? nLimitProcessors : -1)));
    obj.push_back(Pair("difficulty", (double)GetDifficulty()));
    obj.push_back(Pair("hashespersec", gethashespersec(params, false)));
    obj.push_back(Pair("testnet", fTestNet));
    obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize", pwalletMain->GetKeyPoolSize()));
    obj.push_back(Pair("paytxfee", ValueFromAmount(nTransactionFee)));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", (boost::int64_t)nWalletUnlockTime));
    obj.push_back(Pair("errors", GetWarnings("statusbar")));
    return obj;
}


Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account] [address_type]\n"
            "Returns a new address for receiving payments.  "
            "address_type: The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    //if (!pwalletMain->IsLocked())
    //    pwalletMain->TopUpKeyPool();

    //// Generate a new key that is added to wallet
    OutputType output_type{ DEFAULT_ADDRESS_TYPE };
    if (params.size() > 1) {
        if (!ParseOutputType(params[1].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", params[1].get_str()));
        }
    }

    CTxDestination dest;
    std::vector<unsigned char> vecPubKey;
    std::string error;
    if (!pwalletMain->GetNewDestination(output_type, strAccount, vecPubKey, dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
    }
    pwalletMain->SetAddressBookName(dest, strAccount);

    return EncodeDestination(dest);
}

//HCE:
CTxDestination GetAccountAddress(string strAccount, bool bForceNew = false)
{
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (!account.address.empty())
    {
        return DecodeDestination(account.address);
        //CScript scriptPubKey;
        //scriptPubKey.SetBitcoinAddress(account.vchPubKey);
        //for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
        //    it != pwalletMain->mapWallet.end() && !account.vchPubKey.empty();
        //    ++it)
        //{
        //    const CWalletTx& wtx = (*it).second;
        //    BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        //        if (txout.scriptPubKey == scriptPubKey)
        //            bKeyUsed = true;
        //}
    }

    // Generate a new key

    OutputType output_type{ DEFAULT_ADDRESS_TYPE };
    CTxDestination address;
    std::vector<unsigned char> vchPubKey;
    std::string error;
    if (!pwalletMain->GetNewDestination(output_type, strAccount, vchPubKey, address, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
    }

    //std::vector<unsigned char> vchPubKey;
    //if (!pwalletMain->GetKeyFromPool(vchPubKey, false))
    //    throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");

    //CPubKey new_key = CPubKey::NewPubKeyCompressed(vchPubKey);
    //CTxDestination address = GetDestinationForKey(new_key, DEFAULT_ADDRESS_TYPE);
    //pwalletMain->SetAddressBookName(address, strAccount);

    account.address = EncodeDestination(address);
    walletdb.WriteAccount(strAccount, account);

    return address;
}

Value getaccountaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Object ret;
    ret.push_back(Pair(strAccount, EncodeDestination(GetAccountAddress(strAccount))));
    return ret;
}



Value setaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <address> <account>\n"
            "Sets the account associated with the given address.");

    //CBitcoinAddress address(params[0].get_str());
    CTxDestination address = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(address);
    if (!isValid)
        throw JSONRPCError(-5, "Invalid address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);
    //HCE: '*' reserves as a global account which represents all accounts.
    if (strAccount == "*") {
        throw JSONRPCError(-5, "Invalid account name");
    }

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    //HCE: do nothing
    //if (pwalletMain->mapAddressBook.count(address))
    //{
    //    string strOldAccount = pwalletMain->mapAddressBook[address];
    //    if (address == GetAccountAddress(strOldAccount))
    //        GetAccountAddress(strOldAccount, true);
    //}

    pwalletMain->SetAddressBookName(address, strAccount);

    return Value::null;
}


Value getaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount <address>\n"
            "Returns the account associated with the given address.");

    CTxDestination address = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(address);
    if (!isValid)
        throw JSONRPCError(-5, "Invalid address");

    string strAccount;
    map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address);
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(EncodeDestination(address));
    }
    return ret;
}

Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

uint160 right160(T_SHA256 const& _t)
{
    vector<unsigned char> hash(_t.pID.begin(), _t.pID.begin() + sizeof(uint160));
    return uint160(hash);
}

uint160 right160(uint256 const& _t)
{
    vector<unsigned char> hash(_t.begin(), _t.begin() + sizeof(uint160));
    return uint160(hash);
}

Value sendtoaddress(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendtoaddress <address> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendtoaddress <address> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    CTxDestination address = DecodeDestination(params[0].get_str());
    if (!IsValidDestination(address))
        throw JSONRPCError(-5, "Invalid address");

    // Amount
    int64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"] = params[3].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    CScript scriptPubKey = GetScriptForDestination(address);
    string strError = pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    Object ret;
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));

    return ret;
}


Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <address> [minconf=1]\n"
            "Returns the total amount received by <address> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");
    scriptPubKey.SetBitcoinAddress(address);
    if (!IsMine(*pwalletMain, scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(string strAccount, set<CTxDestination>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}


Value getreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys that have the label
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress;

    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


int64 GetAccountBalance(CWalletDB_Wrapper& walletdb, const string& strAccount, int nMinDepth, bool greatercompvalstop = false, int64 comparefund = 0)
{
    int64 nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        if (fShutdown)
            throw std::runtime_error("node is shutting down");

        const CWalletTx& wtx = (*it).second;
        if (!wtx.IsFinal())
            continue;

        int64 nFee;
        list<CWalletTx::DestReceived> listReceived;
        wtx.GetAmountsForBalance(listReceived, nFee, nMinDepth);

        for (const auto& r : listReceived) {
            auto& dest = std::get<CTxDestination>(r);
            auto nValue = std::get<int64>(r);
            auto fmature = std::get<bool>(r);

            if (fmature && pwalletMain->mapAddressBook[dest] == strAccount) {
                nBalance += nValue;
                //HC: 提前退出统计
                if (greatercompvalstop) {
                    if (nBalance >= comparefund) {
                        return nBalance;
                    }
                }
            }
        }
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64 GetAccountBalance(const string& strAccount, int nMinDepth)
{
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth);
}

bool AccountBalanceIsEnough(const string& strAccount, int nMinDepth, int64 comparefund)
{
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);
    int64 ba = GetAccountBalance(walletdb, strAccount, nMinDepth, true, comparefund);
    return ba >= comparefund;
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' should always return the same number.
        int64 nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsFinal())
                continue;

            int64 allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;
            string strSentAccount;
            list<pair<CTxDestination, int64> > listSent;
            list<pair<CTxDestination, int64> > listReceived;
            wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
                BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
                nBalance += r.second;
            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}


Value movecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64 nAmount = AmountFromValue(params[2]);
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);
    if(!walletdb.TxnBegin())
        return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);

    int64 nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    walletdb.TxnCommit();

    return true;
}


Value sendfrom(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 3 || params.size() > 6))
        throw runtime_error(
            "sendfrom <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 3 || params.size() > 6))
        throw runtime_error(
            "sendfrom <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    string strAccount = AccountFromValue(params[0]);

    CTxDestination address = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(address))
        throw JSONRPCError(-5, "Invalid address");

    int64 nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["to"] = params[5].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check funds
    if (!AccountBalanceIsEnough(strAccount, nMinDepth, nAmount))
        throw JSONRPCError(-6, "Account has insufficient funds");

    CScript scriptPubKey = GetScriptForDestination(address);
    string strError = pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    return wtx.GetHash().GetHex();
}


Value sendmany(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers");

    string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, int64> > vecSend;

    int64 totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(-5, string("Invalid address:") + s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ") + s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetBitcoinAddress(address);
        int64 nAmount = AmountFromValue(s.value_);
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check funds
    if (!AccountBalanceIsEnough(strAccount, nMinDepth, totalAmount))
        throw JSONRPCError(-6, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;

    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
    if (!fCreated)
    {
        if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
            throw JSONRPCError(-6, "Insufficient funds");
        throw JSONRPCError(-4, "Transaction creation failed");
    }

    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(-4, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}


struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = INT_MAX;
    }
};

Value ListReceived(const Array& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    // Tally
    map<CTxDestination, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address) || !IsValidDestination(address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strAccount = item.second;
        map<CTxDestination, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        int64 nAmount = 0;
        int nConf = INT_MAX;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts)
        {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
        }
        else
        {
            Object obj;
            obj.push_back(Pair("address", EncodeDestination(address)));
            obj.push_back(Pair("account", strAccount));
            obj.push_back(Pair("label", strAccount)); // deprecated
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            int64 nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("account", (*it).first));
            obj.push_back(Pair("label", (*it).first)); // deprecated
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, false);
}

Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, true);
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
    int64 nGeneratedImmature, nGeneratedMature, nFee;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

    bool fAllAccounts = (strAccount == string("*"));

    // Generated blocks assigned to account ""
    if ((nGeneratedMature + nGeneratedImmature) != 0 && (fAllAccounts || strAccount == "")) {
        Object entry;
        entry.push_back(Pair("account", string("")));
        if (nGeneratedImmature) {
            entry.push_back(Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
        }
        else {
            entry.push_back(Pair("category", "generate"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
        }
        if (fLong)
            WalletTxToJSON(wtx, entry);
        ret.push_back(entry);
    }

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64) & s, listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            entry.push_back(Pair("address", EncodeDestination(s.first)));
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64) & r, listReceived)
    {
        string account;
        if (pwalletMain->mapAddressBook.count(r.first))
            account = pwalletMain->mapAddressBook[r.first];
        if (fAllAccounts || (account == strAccount)) {
            Object entry;
            entry.push_back(Pair("account", account));
            entry.push_back(Pair("address", EncodeDestination(r.first)));
            entry.push_back(Pair("category", "receive"));
            entry.push_back(Pair("amount", ValueFromAmount(r.second)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey, Object &out, bool fIncludeHex)
{
    TxoutType type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey)));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired) || type == TxoutType::PUBKEY) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    for (const CTxDestination& addr : addresses) {
        a.push_back(EncodeDestination(addr));
    }
    out.push_back(Pair("addresses", a));
}

void GetTransactionsDetails(const CTransaction& tx, Array& ret)
{
    //Txin
    Array detailsvin;
    for (auto& txin : tx.vin) {
        Object entry;
        vector<unsigned char> sSig(txin.scriptSig.begin(), txin.scriptSig.end());
        if (tx.IsCoinBase()) {
            entry.push_back(Pair("coinbase", HexStr(sSig)));
        }
        else {
            entry.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            entry.push_back(Pair("vout", (int64_t)txin.prevout.n));

            Object objscriptSig;
            objscriptSig.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            objscriptSig.push_back(Pair("hex", HexStr(sSig)));

            CScript::const_iterator pc = txin.scriptSig.begin();
            opcodetype opcode;
            vector<unsigned char> vchPushValue;

            //HCE: To coinbase, cannot get address because only contains signature in scriptSig
            if (txin.scriptSig.GetOp(pc, opcode, vchPushValue)) {
                if (txin.scriptSig.GetOp(pc, opcode, vchPushValue)) {
                    //public key
                    CPubKey pk(vchPushValue);
                    CTxDestination address = GetDestinationForKey(pk, DEFAULT_ADDRESS_TYPE);
                    if (IsValidDestination(address)) {
                        objscriptSig.push_back(Pair("address", EncodeDestination(address)));
                    }
                }
            }
            entry.push_back(Pair("scriptSig", objscriptSig));
        }
        if (!txin.scriptWitness.IsNull()) {
            Array arrScriptwitness;
            for (const auto& item : txin.scriptWitness.stack) {
                arrScriptwitness.push_back(HexStr(item));
            }
            entry.push_back(Pair("txinwitness", arrScriptwitness));
        }
        entry.push_back(Pair("sequence", (int64_t)txin.nSequence));

        detailsvin.push_back(entry);
    }
    Object entryvin;
    entryvin.push_back(Pair("vin", detailsvin));
    ret.push_back(entryvin);

    //HCE: vout
    int64_t n = 0;
    Array detailsvout;
    for (auto& txout : tx.vout) {
        Object entry;
        vector<unsigned char> sPubkey(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
        entry.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        entry.push_back(Pair("n", n++));

        ScriptPubKeyToUniv(txout.scriptPubKey, entry, true);
        detailsvout.push_back(entry);
    }

    Object entryvout;
    entryvout.push_back(Pair("vout", detailsvout));
    ret.push_back(entryvout);
}


void ListTransactionsDetails(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
    int64 nGeneratedImmature, nGeneratedMature, nFee;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

    bool fAllAccounts = (strAccount == string("*"));

    GetTransactionsDetails(wtx, ret);

    Array detailssummary;
    // Generated blocks assigned to account ""
    if ((nGeneratedMature + nGeneratedImmature) != 0 && (fAllAccounts || strAccount == ""))
    {
        Object entry;
        entry.push_back(Pair("account", string("")));
        if (nGeneratedImmature)
        {
            entry.push_back(Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
        }
        else
        {
            entry.push_back(Pair("category", "generate"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
        }
        if (fLong)
            WalletTxToJSON(wtx, entry);
        detailssummary.push_back(entry);
    }

    //HCE: It seems that Sent and received has errors, so skip
    return;

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            entry.push_back(Pair("address", EncodeDestination(s.first)));
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            detailssummary.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
    {
        string account;
        if (pwalletMain->mapAddressBook.count(r.first))
            account = pwalletMain->mapAddressBook[r.first];
        if (fAllAccounts || (account == strAccount))
        {
            Object entry;
            entry.push_back(Pair("account", account));
            entry.push_back(Pair("address", EncodeDestination(r.first)));
            entry.push_back(Pair("category", "receive"));
            entry.push_back(Pair("amount", ValueFromAmount(r.second)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            detailssummary.push_back(entry);
        }
    }

    Object entrysummary;
    entrysummary.push_back(Pair("summary", detailssummary));
    ret.push_back(entrysummary);

}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    Array ret;
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);

    // Firs: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap:
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    // Now: iterate backwards until we have nCount items to return:
    TxItems::reverse_iterator it = txByTime.rbegin();
    if (txByTime.size() > nFrom) std::advance(it, nFrom);
    for (; it != txByTime.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if (ret.size() >= nCount) break;
    }
    // ret is now newest to oldest

    // Make sure we return only last nCount items (sends-to-self might give us an extra):
    if (ret.size() > nCount)
    {
        Array::iterator last = ret.begin();
        std::advance(last, nCount);
        ret.erase(last, ret.end());
    }
    std::reverse(ret.begin(), ret.end()); // oldest to newest

    return ret;
}

typedef struct tagBalance
{
    int64 nTotal = 0;
    int64 nGeneratedMature = 0;

    void operator +=(int64 nFee)
    {
        nTotal += nFee;
        nGeneratedMature += nFee;
    }
    void operator -=(int64 nFee)
    {
        nTotal -= nFee;
        nGeneratedMature -= nFee;
    }

    void Add(bool fmature, int64 value) {
        if (!fmature) {
            nTotal += value;
        } else {
            *this += value;
        }
    }

    Object ToObj() const
    {
        Object obj;
        obj.push_back(Pair("Total", ValueFromAmount(nTotal).get_real()));
        obj.push_back(Pair("Mature", ValueFromAmount(nGeneratedMature).get_real()));
        return obj;
    }
} Balances;

Value listaccounts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    int nMinDepth = 1;
    if (params.size() > 0) {
        auto para = params[0];
        ConvertTo<boost::int64_t>(para);
        nMinDepth = para.get_int();
    }

    map<string, Balances> mapAccountBalances;
    mapAccountBalances["*"] = Balances();
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
        //HCE: for SegWit, here cannot know if the address belongs to me or not
        //if (pwalletMain->HaveKey(entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = Balances();
    }

    PrintConsole("Tallying, there are %u transactions in the wallet...\n", pwalletMain->mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.GetDepthInMainChain() < nMinDepth)
            continue;

        int64 nFee;
        list<CWalletTx::DestReceived> listReceived;
        wtx.GetAmountsForBalance(listReceived, nFee, nMinDepth);
        //HCE: '*' means all accounts.
        //HCE: for computing balances, because statistics out value of tx, so skip nFee
        //mapAccountBalances["*"] -= nFee;

        for (const auto& r : listReceived) {
            auto & dest = std::get<CTxDestination>(r);
            auto nValue = std::get<int64>(r);
            auto fmature = std::get<bool>(r);

            mapAccountBalances["*"].Add(fmature, nValue);

            if (pwalletMain->mapAddressBook.count(dest))
                mapAccountBalances[pwalletMain->mapAddressBook[dest]].Add(fmature, nValue);
        }
    }

    list<CAccountingEntry> acentries;
    CWalletDB_Wrapper(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    Object ret;
    ret.push_back(Pair("*", mapAccountBalances["*"].ToObj()));
    ret.push_back(Pair("", mapAccountBalances[""].ToObj()));
    BOOST_FOREACH(const PAIRTYPE(string, Balances)& accountBalance, mapAccountBalances) {
        if (accountBalance.first != "*" && !accountBalance.first.empty()) {
            ret.push_back(Pair(accountBalance.first, accountBalance.second.ToObj()));
        }
    }

    return ret;
}


Value listaddrbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaddrbalance [address1] [address2]...\n"
            "Returns Object that has account address as keys, account balances as values.");

    std::set<string> mapQueryAddr;
    for (int i = 1; i < params.size(); i++) {
        mapQueryAddr.insert(params[i].get_str());
    }

    map<string, Balances> mapAddrsBalance;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        int64 nGeneratedImmature, nGeneratedMature, nFee;
        string strSentAccount;
        list<pair<CTxDestination, int64> > listReceived;
        list<pair<CTxDestination, int64> > listSent;
        bool isCoinbase;
        wtx.GetAmountsEx(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, isCoinbase);
        if (isCoinbase) {
            for (auto & elm : listReceived) {
                string straddress = EncodeDestination(elm.first);
                mapAddrsBalance[straddress].nTotal += nGeneratedImmature;
                mapAddrsBalance[straddress] += nGeneratedMature;
            }
        }
        else {
            for (auto& elm : listReceived) {
                string straddress = EncodeDestination(elm.first);
                mapAddrsBalance[straddress] += elm.second;
            }
        }
    }

    Object ret;
    for (auto& elm : mapAddrsBalance) {
        if(mapQueryAddr.size() == 0)
            ret.push_back(Pair(elm.first, elm.second.ToObj()));
        else if(mapQueryAddr.count(elm.first))
            ret.push_back(Pair(elm.first, elm.second.ToObj()));
    }
    return ret;
}

Value gettransactionaddr(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransactionaddr <txid>\n"
            "Get logical address about <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;

    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(-5, "Invalid or non-wallet transaction id");

    CTxIndex txindex;
    if (!CTxDB_Wrapper().ReadTxIndex(hash, txindex))
        throw JSONRPCError(-5, "Failed to read transaction");

    entry.push_back(Pair("address",txindex.pos.ToString()));

    return entry;
}

//HC: Transaction in wallet
//Value gettransaction(const Array& params, bool fHelp)
//{
//    if (fHelp || params.size() != 1)
//        throw runtime_error(
//            "gettransaction <txid>\n"
//            "Get detailed information about <txid>");
//
//    uint256 hash;
//    hash.SetHex(params[0].get_str());
//
//    Object entry;
//
//    if (!pwalletMain->mapWallet.count(hash))
//        throw JSONRPCError(-5, "Invalid or non-wallet transaction id");
//
//    
//    const CWalletTx& wtx = pwalletMain->mapWallet[hash];
//
//    int64 nCredit = wtx.GetCredit();
//    int64 nDebit = wtx.GetDebit();
//    int64 nNet = nCredit - nDebit;
//    int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);
//
//    entry.push_back(Pair("version", wtx.nVersion));
//    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
//    if (wtx.IsFromMe())
//        entry.push_back(Pair("fee", ValueFromAmount(nFee)));
//
//    WalletTxToJSON(wtx, entry);
//
//    Array details;
//    ListTransactionsDetails(wtx, "*", 0, false, details);
//    entry.push_back(Pair("details", details));
//
//    return entry;
//}

//HC: Any transaction in main chain
Value gettransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");

    uint256 hashtx;
    hashtx.SetHex(params[0].get_str());

    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    CTransaction tx;
    bool fFound = txdb.ReadTxIndex(hashtx, txindex);
    if (fFound) {
        if (tx.ReadFromDisk(txindex.pos)) {
            if (tx.GetHash() != hashtx) {
                throw JSONRPCError(-5, "The index of transaction has error");
            }
        }
    } else {
        CRITICAL_BLOCK(cs_mapTransactions)
            if (mapTransactions.count(hashtx)) {
                //already exist in transaction pool
                tx = mapTransactions[hashtx];
            } else {
                throw JSONRPCError(-5, "Transaction not existed");
            }
    }

    Object entry;
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));

    string desc;
    string strerr;

    int64_t hyperId = -1;
    int64_t chainId, localId;
    int blocknum;
    int64_t blockstamp;
    int blockmaturity;
    bool ret = GetTxState(hashtx.GetHex(), blocknum, blockstamp, blockmaturity,
            hyperId, chainId, localId,
            desc, strerr);

    entry.push_back(Pair("block height", blocknum));
    entry.push_back(Pair("block timestamp", blockstamp));
    entry.push_back(Pair("block ID", StringFormat("[%d, %d, %d]", hyperId, chainId, localId)));

    Array details;
    GetTransactionsDetails(tx, details);
    entry.push_back(Pair("details", details));

    return entry;
}

Value listnewtransactions(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listnewtransactions\n"
            "Returns up to 20 most recent transactions.");

    CBlock block;
    BLOCKTRIPLEADDRESS addrblock;
    char* pWhere = nullptr;
    CBlockIndexSP spBlkIdx = pindexBest;

    //HC：取1小时前的交易 6(个/5分钟) * 12 = 72
    int height = spBlkIdx->nHeight > 72 ? (spBlkIdx->nHeight - 72) : 0;
    while (spBlkIdx && spBlkIdx->nHeight != height) {
        spBlkIdx = spBlkIdx->pprev();
    }
    Array txs;
    int i = 0;
    while (spBlkIdx) {
        if (GetBlockData(spBlkIdx->GetBlockHash(), block, addrblock, &pWhere)) {
            auto it = block.vtx.rbegin();
            for (; it != block.vtx.rend(); ++it) {
                Object entry;
                entry.push_back(Pair("txid", it->GetHash().GetHex()));
                entry.push_back(Pair("time", (int64_t)block.nTime));
                txs.push_back(entry);
                if (++i == 20) {
                    return txs;
                }
            }
        }
        spBlkIdx = spBlkIdx->pprev();
    }
    return txs;
}

Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();

    string errmsg;
    if (!BackupWallet(*pwalletMain, strDest, errmsg)) {
        throw JSONRPCError(-1, errmsg);
    }

    Object entry;
    entry.push_back(Pair("hash", g_cryptoCurrency.GetHashPrefixOfGenesis()));

    return entry;
}


Value keypoolrefill(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() > 0))
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool, requires wallet passphrase to be set.");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() > 0))
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    pwalletMain->TopUpKeyPool();

    if (pwalletMain->GetKeyPoolSize() < GetArg("-keypool", 100))
        throw JSONRPCError(-4, "Error refreshing keypool.");

    return Value::null;
}


void ThreadTopUpKeyPool(void* parg)
{
    pwalletMain->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(void* parg)
{
    int64 nMyWakeTime = GetTime() + *((int*)parg);

    if (nWalletUnlockTime == 0)
    {
        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            nWalletUnlockTime = nMyWakeTime;
        }

        while (GetTime() < nWalletUnlockTime)
            Sleep(nWalletUnlockTime - GetTime());

        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
        }
    }
    else
    {
        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            if (nWalletUnlockTime < nMyWakeTime)
                nWalletUnlockTime = nMyWakeTime;
        }
        free(parg);
        return;
    }

    pwalletMain->Lock();

    delete (int*)parg;
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    if (fHelp || (pwalletMain->IsCrypted() && params.size() != 2))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!pwalletMain->IsLocked())
        throw JSONRPCError(-17, "Error: Wallet is already unlocked.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    string strWalletPass;
    strWalletPass.reserve(100);
    mlock(&strWalletPass[0], strWalletPass.capacity());
    strWalletPass = params[0].get_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
        {
            fill(strWalletPass.begin(), strWalletPass.end(), '\0');
            munlock(&strWalletPass[0], strWalletPass.capacity());
            throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");
        }
        fill(strWalletPass.begin(), strWalletPass.end(), '\0');
        munlock(&strWalletPass[0], strWalletPass.capacity());
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    hc::CreateThread("ParaTopUpKeyPool", ThreadTopUpKeyPool, NULL);

    int* pnSleepTime = new int(params[1].get_int());
    hc::CreateThread("ParaTopUpKeyPool", ThreadCleanWalletPassphrase, pnSleepTime);

    return Value::null;
}


Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    string strOldWalletPass;
    strOldWalletPass.reserve(100);
    mlock(&strOldWalletPass[0], strOldWalletPass.capacity());
    strOldWalletPass = params[0].get_str();

    string strNewWalletPass;
    strNewWalletPass.reserve(100);
    mlock(&strNewWalletPass[0], strNewWalletPass.capacity());
    strNewWalletPass = params[1].get_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
    {
        fill(strOldWalletPass.begin(), strOldWalletPass.end(), '\0');
        fill(strNewWalletPass.begin(), strNewWalletPass.end(), '\0');
        munlock(&strOldWalletPass[0], strOldWalletPass.capacity());
        munlock(&strNewWalletPass[0], strNewWalletPass.capacity());
        throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");
    }
    fill(strNewWalletPass.begin(), strNewWalletPass.end(), '\0');
    fill(strOldWalletPass.begin(), strOldWalletPass.end(), '\0');
    munlock(&strOldWalletPass[0], strOldWalletPass.capacity());
    munlock(&strNewWalletPass[0], strNewWalletPass.capacity());

    return Value::null;
}


Value walletlock(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletlock was called.");

    pwalletMain->Lock();
    CRITICAL_BLOCK(cs_nWalletUnlockTime)
    {
        nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an encrypted wallet, but encryptwallet was called.");

    string strWalletPass;
    strWalletPass.reserve(100);
    mlock(&strWalletPass[0], strWalletPass.capacity());
    strWalletPass = params[0].get_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
    {
        fill(strWalletPass.begin(), strWalletPass.end(), '\0');
        munlock(&strWalletPass[0], strWalletPass.capacity());
        throw JSONRPCError(-16, "Error: Failed to encrypt the wallet.");
    }
    fill(strWalletPass.begin(), strWalletPass.end(), '\0');
    munlock(&strWalletPass[0], strWalletPass.capacity());

    return Value::null;
}


Value validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <address>\n"
            "Return information about <address>.");

    //CBitcoinAddress address(params[0].get_str());
    CTxDestination address = DecodeDestination(params[0].get_str());
    bool isValid = IsValidDestination(address);

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        // Call Hash160ToAddress() so we always return current ADDRESSVERSION
        // version of the address:
        string currentAddress = params[0].get_str();   // address.ToString();
        ret.push_back(Pair("address", currentAddress));
        //HCE: address have three types, so cannot know
        //ret.push_back(Pair("ismine", (pwalletMain->HaveKey(address) > 0)));
        if (pwalletMain->mapAddressBook.count(address))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[address]));
    }
    return ret;
}

extern void ChangeCoinbaseIfExist(CBlock* pblock, unsigned int nExtraNonce);
extern MiningCondition g_miningCond;
//HCE: Change implementation into progpow algorithm
Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw runtime_error(
            "getwork <address>\n"
            "returns formatted hash data to work on:\n"
            "  \"height\" : block height\n"
            "  \"startnonce\" : block initialization nonce\n"
            "  \"headerhash\" : block header hash\n"
            "  \"target\" : little endian hash target\n"
            "getwork <headerhash> <nonce> <solution>\n"
            "tries to solve the block and returns null if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(-9, "Para chain is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Para chain is downloading blocks...");

    if(!g_miningCond.IsMining())
        throw JSONRPCError(-11, "Para node is not mining!");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static std::map<string, int> mapLightNodes;
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 1)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64 nStart;
        static CBlock* pblock;

        string lightnodeminingaddress = params[0].get_str();
        if (pindexPrev != pindexBest.get() ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest.get())
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                mapLightNodes.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = nTransactionsUpdated;
            pindexPrev = pindexBest.get();
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(reservekey, lightnodeminingaddress.c_str());
            if (!pblock)
                throw JSONRPCError(-7, "Out of memory");
            mapLightNodes[lightnodeminingaddress] = pblock->nHeight;
            vNewBlock.push_back(pblock);
        }
        else if(mapLightNodes.count(lightnodeminingaddress)) {
            throw JSONRPCError(-8, "Too many requests"); //Too many requests, Please try again later
        }

        // Update nTime
        pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

        //HCE: avoid coinbase conflict
        // Update nExtraNonce
        unsigned int nExtraNonce = 0;
        ChangeCoinbaseIfExist(pblock, nExtraNonce);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        ethash::hash256 target;
        std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

        ethash::hash256 header_hash = pblock->GetHeaderHash();

        // Save
        std::vector<unsigned char> vch(BEGIN(header_hash), END(header_hash));
        uint256 uheaderhash(vch);
        mapNewBlock[uheaderhash] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        Object result;
        result.push_back(Pair("height", (uint64)pblock->nHeight));
        result.push_back(Pair("startnonce", (uint64)pblock->nNonce));
        result.push_back(Pair("headerhash", HexStr(BEGIN(header_hash), END(header_hash))));
        result.push_back(Pair("target", HexStr(BEGIN(target.bytes), END(target.bytes))));
        return result;
    } else {
        // Parse parameters

        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 32)
            throw JSONRPCError(-2, "Invalid parameter");

        uint256 uheaderhash(vchData);
        // Get saved block
        if (!mapNewBlock.count(uheaderhash))
            throw JSONRPCError(-3, "unknown header hash");

        CBlock* pblock = mapNewBlock[uheaderhash].first;

        vchData = ParseHex(params[1].get_str());
        memcpy(&pblock->nNonce, &vchData[0], sizeof(pblock->nNonce));

        vchData = ParseHex(params[2].get_str());
        pblock->nSolution.resize(vchData.size());
        memcpy(pblock->nSolution.data(), &vchData[0], vchData.size());

        //pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        //pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if(!CheckWork(pblock, *pwalletMain, reservekey))
            throw JSONRPCError(-4, "Failed to check work");
        return Value::null;
    }
}











//
// Call Table
//

pair<string, rpcfn_type> pCallTable[] =
{
    make_pair("help",                   &help),
    make_pair("stop",                   &stop),
    make_pair("getblockcount",          &getblockcount),

    //HCE: new commands for spv
    make_pair("getblockhash",           &getblockhash),
    make_pair("getblock",               &getblock),
    make_pair("getrawmempool",          &getrawmempool),
    make_pair("getrawtransaction",      &getrawtransaction),
    make_pair("sendrawtransaction",     &sendrawtransaction),

    make_pair("getblocknumber",         &getblocknumber),
    make_pair("getconnectioncount",     &getconnectioncount),
    make_pair("getdifficulty",          &getdifficulty),
    make_pair("getgenerate",            &getgenerate),
    make_pair("setgenerate",            &setgenerate),
    make_pair("gethashespersec",        &gethashespersec),
    make_pair("getinfo",                &getinfo),
    make_pair("getnewaddress",          &getnewaddress),
    make_pair("getaccountaddress",      &getaccountaddress),
    make_pair("setaccount",             &setaccount),
    make_pair("getaccount",             &getaccount),
    make_pair("getaddressesbyaccount",  &getaddressesbyaccount),
    make_pair("sendtoaddress",          &sendtoaddress),
    make_pair("getreceivedbyaddress",   &getreceivedbyaddress),
    make_pair("getreceivedbyaccount",   &getreceivedbyaccount),
    make_pair("listreceivedbyaddress",  &listreceivedbyaddress),
    make_pair("listreceivedbyaccount",  &listreceivedbyaccount),
    make_pair("backupwallet",           &backupwallet),
    make_pair("keypoolrefill",          &keypoolrefill),
    make_pair("walletpassphrase",       &walletpassphrase),
    make_pair("walletpassphrasechange", &walletpassphrasechange),
    make_pair("walletlock",             &walletlock),
    make_pair("encryptwallet",          &encryptwallet),
    make_pair("validateaddress",        &validateaddress),
    make_pair("getbalance",             &getbalance),
    make_pair("move",                   &movecmd),
    make_pair("sendfrom",               &sendfrom),
    make_pair("sendmany",               &sendmany),
    make_pair("gettransaction",         &gettransaction),
    make_pair("gettransactionaddr",     &gettransactionaddr),
    make_pair("listtransactions",       &listtransactions),
    make_pair("listnewtransactions",    &listnewtransactions),
    make_pair("getwork",                &getwork),
    make_pair("listaccounts",           &listaccounts),
    make_pair("settxfee",               &settxfee),
    make_pair("issuecoin",              &issuecoin),
    //make_pair("gid2rid",                &gid2rid),
    //make_pair("commitcoin",             &commitcoin),
    make_pair("querygenesisblock",      &querygenesisblock),
    make_pair("getcoininfo",            &getcoininfo),
    make_pair("importcoin",             &importcoin),
    //make_pair("startmining",            &startmining),
    //make_pair("stopmining",             &stopmining),
    make_pair("queryminingstatus",      &queryminingstatus),
};

map<string, rpcfn_type> mapCallTable(pCallTable, pCallTable + sizeof(pCallTable) / sizeof(pCallTable[0]));

string pAllowInSafeMode[] =
{
    "help",
    "stop",
    "getblockcount",
    "getblocknumber",
    "getconnectioncount",
    "getdifficulty",
    "getgenerate",
    "setgenerate",
    "gethashespersec",
    "getinfo",
    "getnewaddress",
    "getaccountaddress",
    "getaccount",
    "getaddressesbyaccount",
    "backupwallet",
    "keypoolrefill",
    "walletpassphrase",
    "walletlock",
    "validateaddress",
    "getwork",
};
set<string> setAllowInSafeMode(pAllowInSafeMode, pAllowInSafeMode + sizeof(pAllowInSafeMode) / sizeof(pAllowInSafeMode[0]));




//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string, string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
        << "User-Agent: paracoin-json-rpc/" << FormatFullVersion() << "\r\n"
        << "Host: 127.0.0.1\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << strMsg.size() << "\r\n"
        << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want posix (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg)
{
    if (nStatus == 401)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: paracoin-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    string strStatus;
    if (nStatus == 200) strStatus = "OK";
    else if (nStatus == 400) strStatus = "Bad Request";
    else if (nStatus == 403) strStatus = "Forbidden";
    else if (nStatus == 404) strStatus = "Not Found";
    else if (nStatus == 500) strStatus = "Internal Server Error";
    return strprintf(
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/json\r\n"
        "Server: paracoin-json-rpc/%s\r\n"
        "\r\n"
        "%s",
        nStatus,
        strStatus.c_str(),
        rfc1123Time().c_str(),
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return 500;
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon + 1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nStatus = ReadHTTPStatus(stream);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > MAX_SIZE)
        return 500;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);

       /* int nReadLeft = nLen;
        while (!stream.eof()) {
            stream.readsome(&vch[nLen-nReadLeft], nReadLeft);
            nReadLeft -= stream.gcount();
            if (nReadLeft == 0) {
                break;
            }
        }*/
        strMessageRet = string(vch.begin(), vch.end());
    }

    return nStatus;
}

string EncodeBase64_(string s)
{
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, s.c_str(), s.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    string result(bptr->data, bptr->length);
    BIO_free_all(b64);

    return result;
}

string DecodeBase64_(string s)
{
    BIO *b64, *bmem;

    char* buffer = static_cast<char*>(calloc(s.size(), sizeof(char)));

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(const_cast<char*>(s.c_str()), s.size());
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, s.size());
    BIO_free_all(bmem);

    string result(buffer);
    free(buffer);
    return result;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64_(strUserPass64);
    string::size_type nColon = strUserPass.find(":");
    if (nColon == string::npos)
        return false;
    string strUser = strUserPass.substr(0, nColon);
    string strPassword = strUserPass.substr(nColon + 1);
    return (strUser == mapArgs["-rpcuser"] && strPassword == mapArgs["-rpcpassword"]);
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObject(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}


string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return write_string(Value(reply), false) + "\n";
}

string JSONRPCReply(const Array& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return write_string(Value(reply), false) + "\n";
}


void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = 500;
    int code = find_value(objError, "code").get_int();
    if (code == -32600) nStatus = 400;
    else if (code == -32601) nStatus = 404;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply) << std::flush;
}

bool ClientAllowed(const string& strAddress)
{
    if (strAddress == asio::ip::address_v4::loopback().to_string())
        return true;
    const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
    BOOST_FOREACH(string strAllow, vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}

#ifdef USE_SSL
//
// IOStream device that speaks SSL but can also speak non-SSL
//
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(SSLStream &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(stream.get_io_service());
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    SSLStream& stream;
};
#endif

void ThreadRPCServer(void* parg)
{
    //HCE:
    //IMPLEMENT_RANDOMIZE_STACK(ThreadRPCServer(parg));
    fRPCServerRunning = true;
    try
    {
        vnThreadsRunning[4]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[4]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[4]--;
        PrintException(&e, "ThreadRPCServer()");
    }
    catch (...) {
        vnThreadsRunning[4]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    fRPCServerRunning = false;

    TRACE_FL("ThreadRPCServer exiting\n");
}

void HandleAccept(const system::error_code& error,
    boost::shared_ptr<asio::ip::tcp::socket> socket,
    asio::ip::tcp::acceptor& acceptor);

void StartAccept(boost::asio::ip::tcp::acceptor& acceptor)
{
    using boost::asio::ip::tcp;
    boost::shared_ptr< tcp::socket > socket(
        new tcp::socket(acceptor.get_executor()));

    // Add an accept call to the service.  This will prevent io_service::run()
    // from returning.
    acceptor.async_accept(*socket,
        boost::bind(HandleAccept,
            boost::asio::placeholders::error,
            socket,
            boost::ref(acceptor)));
}

void ThreadRPCServer2(void* parg)
{
    TRACE_FL("ThreadRPCServer started\n");

    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
    {
        string strWhatAmI = "To use Paracoin";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        PrintConsole(
            _("Warning: %s, you must set rpcpassword=<password>\nin the configuration file: %s\n"
                "If the file does not exist, create it with owner-readable-only file permissions.\n"),
            strWhatAmI.c_str(),
            GetConfigFile().c_str());
        hc::CreateThread("ParaRPCServer2Shutdown", Shutdown, NULL);
        return;
    }

    bool fUseSSL = GetBoolArg("-rpcssl");
    asio::ip::address bindAddress = mapArgs.count("-rpcallowip") ? asio::ip::address_v4::any() : asio::ip::address_v4::loopback();

    asio::io_service& io_service = *reinterpret_cast<asio::io_service*>(parg);
    ip::tcp::endpoint endpoint(bindAddress, GetArg("-rpcparaport", 8118));
    ip::tcp::acceptor acceptor(io_service, endpoint);

    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));

#ifdef USE_SSL
    ssl::context context(io_service, ssl::context::sslv23);
    if (fUseSSL)
    {
        context.set_options(ssl::context::no_sslv2);
        filesystem::path certfile = GetArg("-rpcsslcertificatechainfile", "server.cert");
        if (!certfile.is_complete()) certfile = filesystem::path(GetDataDir()) / certfile;
        if (filesystem::exists(certfile)) context.use_certificate_chain_file(certfile.string().c_str());
        else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", certfile.string().c_str());
        filesystem::path pkfile = GetArg("-rpcsslprivatekeyfile", "server.pem");
        if (!pkfile.is_complete()) pkfile = filesystem::path(GetDataDir()) / pkfile;
        if (filesystem::exists(pkfile)) context.use_private_key_file(pkfile.string().c_str(), ssl::context::pem);
        else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pkfile.string().c_str());

        string ciphers = GetArg("-rpcsslciphers",
            "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(context.impl(), ciphers.c_str());
    }
#else
    if (fUseSSL)
        throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");
#endif

    //HCE: Add a job to start accepting connections.
    StartAccept(acceptor);

    //HCE: Process event loop.
    io_service.run();
}

void HandleWrite(boost::shared_ptr<asio::ip::tcp::socket> socket,
    std::shared_ptr<boost::asio::streambuf> stream, const boost::system::error_code& error)
{
    return;
}

Object CombineFromArr(const Array & requests)
{
    string strMethod;

    Value valMethod = find_value(requests[0].get_obj(), "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(-32600, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(-32600, "Method must be a string");

    strMethod = valMethod.get_str();

    // Parse params
    Array parasIn;
    for (auto &req : requests) {
        const auto &obj = req.get_obj();

        Value id = find_value(obj, "id");

        Value valParams = find_value(obj, "params");
        Array params;
        if (valParams.type() == array_type) {
            params = valParams.get_array();
            params.push_back(id); //HCE: last params is id
            parasIn.push_back(params);
        }
        else if (valParams.type() == null_type) {
            params = Array();
            params.push_back(id); //HCE: last params is id
            parasIn.push_back(params);
        }
        else
            throw JSONRPCError(-32600, "Params must be an array");

    }
    Object objRet;
    objRet.push_back(Pair("method", strMethod));
    objRet.push_back(Pair("params", parasIn));

    return objRet;
}

bool ReplyJsonObjectReq(const Object& request, Value &result, Value &id)
{
    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(-32600, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(-32600, "Method must be a string");
    string strMethod = valMethod.get_str();

    //if (strMethod != "getwork")
    //    printf("ThreadRPCServer method=%s\n", strMethod.c_str());

    // Parse params
    Value valParams = find_value(request, "params");
    Array params;
    if (valParams.type() == array_type)
        params = valParams.get_array();
    else if (valParams.type() == null_type)
        params = Array();
    else
        throw JSONRPCError(-32600, "Params must be an array");

    // Find method
    map<string, rpcfn_type>::iterator mi = mapCallTable.find(strMethod);
    if (mi == mapCallTable.end())
        throw JSONRPCError(-32601, "Method not found");

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode") && !setAllowInSafeMode.count(strMethod))
        throw JSONRPCError(-2, string("Safe mode: ") + strWarning);

    try {
        // Execute
        if ((*(*mi).second) == &help ||
            (*(*mi).second) == &queryminingstatus ||
            (*(*mi).second) == &getblockcount ||
            (*(*mi).second) == &getblocknumber ||
            (*(*mi).second) == &getconnectioncount ||
            (*(*mi).second) == &issuecoin ||
            (*(*mi).second) == &getcoininfo) {
            //Lock is unnecessary
            result = (*(*mi).second)(params, false);
        } else {
            int nTry = 10;
            CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__);
            while (nTry-- > 0) {
                if (!criticalblock.TryEnter(__FILE__, __LINE__)) {
                    boost::this_thread::sleep_for(boost::chrono::milliseconds(200));
                    if (nTry == 0) {
                        //Paracoin is busying , maybe it is backtracking or chain switching
                        throw JSONRPCError(-3, "busying");
                    }
                }
                else {
                    CRITICAL_BLOCK(pwalletMain->cs_wallet)
                        result = (*(*mi).second)(params, false);
                    break;
                }
            }
        }
    }
    catch (std::exception& e) {
        result = JSONRPCError(-1, e.what());
        return false;
    }
    return true;
}

void HandleReadHttpBody(boost::shared_ptr<asio::ip::tcp::socket> socket,
                std::shared_ptr<boost::asio::streambuf> stream, int content_len, const boost::system::error_code& error)
{
    if (content_len == 0) {
        return;
    }

    if (!error)
    {
        std::istream stream_in(stream.get());
        std::ostream stream_out(stream.get());

        vector<char> vch(content_len);
        stream_in.read(&vch[0], content_len);

        string strRequest = string(vch.begin(), vch.end());
        Value id = Value::null;
        try
        {
            // Parse request
            Value valRequest;

            if (!read_string(strRequest, valRequest)) {
                throw JSONRPCError(-32700, "Parse error");
            }

            auto reqType = valRequest.type();
            if (reqType != obj_type && reqType != array_type)
                throw JSONRPCError(-32700, "Parse error");

            Object request;
            bool isarry = false;
            if (reqType == array_type) {
                Array arrResult;
                Array arrReq = valRequest.get_array();
                //HCE: Combine multiple methods into single
                request = std::move(CombineFromArr(arrReq));
                isarry = true;
            } else {
                request = valRequest.get_obj();
            }

            Value result;
            if (ReplyJsonObjectReq(request, result, id)) {
                // Send reply
                string strReply;
                if (!isarry) {
                    strReply = JSONRPCReply(result, Value::null, id);
                } else {
                    strReply = write_string(result, false);
                }
                stream_out << HTTPReply(200, strReply) << std::flush;
            }
            else {
                ErrorReply(stream_out, result.get_obj(), id);
            }
        }
        catch (Object & objError)
        {
            ErrorReply(stream_out, objError, id);
        }
        catch (std::exception & e)
        {
            ErrorReply(stream_out, JSONRPCError(-32700, e.what()), id);
        }
    }
    asio::async_write(*socket.get(), *stream.get(),
        boost::bind(HandleWrite, socket, stream, boost::asio::placeholders::error));
}

void HandleReadHttpHeader(boost::shared_ptr<asio::ip::tcp::socket> socket,
    std::shared_ptr<boost::asio::streambuf> stream, const boost::system::error_code& error)
{
    if (!error)
    {
        /* boost::asio::streambuf::const_buffers_type bufs = buffer->data();
         std::string msgstr(boost::asio::buffers_begin(bufs),
             boost::asio::buffers_begin(bufs) +
             input_buffer_.size());

         std::vector<std::string> msgVector;
         boost::split(msgVector, msgstr, boost::is_any_of(":"));*/
        bool fUseSSL = GetBoolArg("-rpcssl");

        std::istream stream_in(stream.get());
        std::ostream stream_out(stream.get());

        //socket->read_some(stream);
        //boost::asio::read(*socket.get(), stream);
        // Restrict callers by IP
        ip::tcp::endpoint peer = socket->remote_endpoint();
        if (!ClientAllowed(peer.address().to_string())) {
            // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
            if (!fUseSSL)
                stream_out << HTTPReply(403, "") << std::flush;
            return;
        }

        map<string, string> mapHeaders;
        string strRequest;

        // Read status
        int nStatus = ReadHTTPStatus(stream_in);

        // Read header
        int content_length = ReadHTTPHeader(stream_in, mapHeaders);
        if (content_length < 0 || content_length > MAX_SIZE)
            throw JSONRPCError(-32600, "content-length too big or too small");

        int nLeft = stream->in_avail();

        if (nLeft < content_length) {
            asio::async_read(*socket.get(), *stream.get(),
                boost::asio::transfer_at_least(content_length - nLeft),
                boost::bind(HandleReadHttpBody, socket, stream, content_length, boost::asio::placeholders::error));
            return;
        }
        HandleReadHttpBody(socket,stream, content_length, error);
        //boost::thread api_caller(ReadHTTP, boost::ref(stream_in), boost::ref(mapHeaders), boost::ref(strRequest));
        //if (!api_caller.timed_join(boost::posix_time::seconds(GetArg("-rpctimeout", 30)))) {   // Timed out:
        //    //acceptor.cancel();
        //    printf("ThreadRPCServer ReadHTTP timeout\n");
        //    return;
        //}

        //HCE: don't HTTPAuthorized
        // Check authorization
        //if (mapHeaders.count("authorization") == 0)
        //{
        //    stream << HTTPReply(401, "") << std::flush;
        //    break;
        //}

        //if (!HTTPAuthorized(mapHeaders))
        //{
        //    // Deter brute-forcing short passwords
        //    if (mapArgs["-rpcpassword"].size() < 15)
        //        Sleep(50);

        //    stream << HTTPReply(401, "") << std::flush;
        //    printf("ThreadRPCServer incorrect password attempt\n");
        //    break;
        //}
    }
}

void HandleAccept(const system::error_code& error,
    boost::shared_ptr< asio::ip::tcp::socket > socket,
    asio::ip::tcp::acceptor& acceptor)
{
    //HCE: If there was an error, then do not add any more jobs to the service.
    if (error) {
        printf("Error accepting connection: %s", error.message().c_str());
        return;
    }

    bool fUseSSL = GetBoolArg("-rpcssl");

    do
    {
        // Accept connection
#ifdef USE_SSL
        ssl::context context(io_service, ssl::context::sslv23);
        if (fUseSSL)
        {
            context.set_options(ssl::context::no_sslv2);
            filesystem::path certfile = GetArg("-rpcsslcertificatechainfile", "server.cert");
            if (!certfile.is_complete()) certfile = filesystem::path(GetDataDir()) / certfile;
            if (filesystem::exists(certfile)) context.use_certificate_chain_file(certfile.string().c_str());
            else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", certfile.string().c_str());
            filesystem::path pkfile = GetArg("-rpcsslprivatekeyfile", "server.pem");
            if (!pkfile.is_complete()) pkfile = filesystem::path(GetDataDir()) / pkfile;
            if (filesystem::exists(pkfile)) context.use_private_key_file(pkfile.string().c_str(), ssl::context::pem);
            else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pkfile.string().c_str());

            string ciphers = GetArg("-rpcsslciphers",
                "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
            SSL_CTX_set_cipher_list(context.impl(), ciphers.c_str());
        }
#else
        if (fUseSSL)
            throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");
#endif

#ifdef USE_SSL
        SSLStream sslStream(io_service, context);
        SSLIOStreamDevice d(sslStream, fUseSSL);
        iostreams::stream<SSLIOStreamDevice> stream(d);
#else
        //ip::tcp::iostream stream;
        std::shared_ptr<boost::asio::streambuf> stream(new boost::asio::streambuf());

#endif

        ip::tcp::endpoint peer = socket->remote_endpoint();
//        vnThreadsRunning[4]--;
//#ifdef USE_SSL
//        acceptor.accept(sslStream.lowest_layer(), peer);
//#else
//        acceptor.accept(*stream.rdbuf(), peer);
//#endif
//
//        vnThreadsRunning[4]++;
        if (fShutdown)
            return;

        asio::async_read(*socket.get(), *stream.get(),
            boost::asio::transfer_at_least(1),
            boost::bind(HandleReadHttpHeader, socket, stream, boost::asio::placeholders::error));


    } while (false);

    //HCE: Done using socket, ready for another connection
    StartAccept(acceptor);

}

void StartRPCServer()
{
    //HCE: only one, else the second time bind will be failure
    int n = 1;//std::thread::hardware_concurrency();
    for (int i = 0; i < n; i++) {
        std::shared_ptr<boost::asio::io_service> io(new boost::asio::io_service());
        rpcServerList.push_back(io);
        hc::CreateThread("ParaRPCServer", ThreadRPCServer, io.get());
    }
}

void StopRPCServer()
{
    for (auto& io : rpcServerList) {
        io->stop();
    }
}


Object CallRPC(const string& strMethod, const Array& params, const string &strServer, const string &strPort)
{
    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
                "If the file does not exist, create it with owner-readable-only file permissions."),
            GetConfigFile().c_str()));

    // Connect to localhost
    bool fUseSSL = GetBoolArg("-rpcssl");
#ifdef USE_SSL
    asio::io_service io_service;
    ssl::context context(io_service, ssl::context::sslv23);
    context.set_options(ssl::context::no_sslv2);
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, fUseSSL);
    iostreams::stream<SSLIOStreamDevice> stream(d);
    if (!d.connect(strServer, strPort))
        throw runtime_error("couldn't connect to server");
#else
    if (fUseSSL)
        throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");

    ip::tcp::iostream stream(strServer, strPort);
    if (stream.fail())
        throw runtime_error("couldn't connect to server");
#endif


    // HTTP basic authentication
    string strUserPass64 = EncodeBase64_(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string strReply;
    int nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == 401)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != 400 && nStatus != 404 && nStatus != 500)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}







int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        Array params;
        for (int i = 2; i < argc; i++)
            params.push_back(argv[i]);

        int n = params.size();

        //
        // Special case non-string parameter types
        //
        if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
        if (strMethod == "setgenerate"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
        if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
        if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
        if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
        if (strMethod == "getbalance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
        if (strMethod == "move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);
        if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
        if (strMethod == "sendfrom"               && n > 3) ConvertTo<boost::int64_t>(params[3]);
        if (strMethod == "listtransactions"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "listtransactions"       && n > 2) ConvertTo<boost::int64_t>(params[2]);
        if (strMethod == "listaccounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "sendmany"               && n > 1)
        {
            string s = params[1].get_str();
            Value v;
            if (!read_string(s, v) || v.type() != obj_type)
                throw runtime_error("type mismatch");
            params[1] = v.get_obj();
        }
        if (strMethod == "sendmany"                && n > 2) ConvertTo<boost::int64_t>(params[2]);

        // Execute
        Object reply = CallRPC(strMethod, params, GetArg("-rpcconnect", "127.0.0.1"), GetArg("-rpcparaport", "8118"));

        // Parse reply
        const Value& result = find_value(reply, "result");
        const Value& error = find_value(reply, "error");

        if (error.type() != null_type)
        {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet = abs(code);
        }
        else
        {
            // Result
            if (result.type() == null_type)
                strPrint = "";
            else if (result.type() == str_type)
                strPrint = result.get_str();
            else
                strPrint = write_string(result, true);
        }
    }
    catch (std::exception& e)
    {
        strPrint = string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}



Value issuecoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "issuecoin <Name> [Genesis block message] [Model] [Logo]\n");

    vector<string> key = { "name", "description", "model", "logo" };
    map<string, string> mapGenenisBlockParams;
    for (int i=0; i<params.size(); i++) {
        mapGenenisBlockParams[key[i]] = params[i].get_str();
    }

    mapGenenisBlockParams["time"] = std::to_string(GetTime());

    std::unique_ptr<CryptoCurrency> spNewCurrency(new CryptoCurrency(false));
    spNewCurrency->SetParas(mapGenenisBlockParams);

    string gid = spNewCurrency->GetUUID();

    std::thread t(&CryptoCurrency::RsyncMiningGenesiBlock, std::move(spNewCurrency));
    t.join();

    Array arr;
    arr.push_back(gid);

    //HCE: Mining operator run quickly, so return requestid directly, 'gid2rid' is unnecessary to RPC client side.
    return gid2rid(arr, false);
}

Value gid2rid(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("gid2rid <GID>\n");

    string requestid = CryptoCurrency::GetRequestID(params[0].get_str());

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}

/*
Value issuecoin(const Array& params, bool fHelp)
{
    //name,time,type,nBits,consensus,ledger,maturity,coinBase,reward,fee,version,description
    if (fHelp || params.size() < 2)
        throw runtime_error(
            "issuecoin {name} [description] [reward] [bits] [version] [time]\n");

    vector<string> key = { "name", "description", "reward", "bits", "version", "time" };
    map<string, string> mapGenenisBlockParams;
    for (int i=0; i<params.size(); i++) {
        mapGenenisBlockParams[key[i]] = params[i].get_str();
    }

    if (mapGenenisBlockParams["time"].empty()) {
        mapGenenisBlockParams["time"] = std::to_string(GetTime());
    }

    CryptoCurrency newcurrency(false);
    newcurrency.SetParas(mapGenenisBlockParams);
    if (newcurrency.ReadCoinFile()) {
        throw JSONRPCError(-1, string("The CryptoCoin already existed"));
    }

    CBlock genesis = newcurrency.MineGenesisBlock();
    if (!newcurrency.WriteCoinFile()) {
        throw JSONRPCError(-2, string("WriteCoinFile failed"));
    }

    string requestid, errmsg;
    if (!CommitGenesisToConsensus(&genesis, requestid, errmsg)) {
        throw JSONRPCError(-3, string("CommitGenesisToConsensus failed: ") + errmsg);
    }

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}
*/

Value commitcoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("commitcoin <name>\n");

    map<string, string> mapGenenisBlockParams;
    mapGenenisBlockParams["name"] = params[0].get_str();

    CryptoCurrency newcurrency(false);
    newcurrency.SetParas(mapGenenisBlockParams);

    string coinhash = "";
    string errmsg;
    if (!newcurrency.ReadCoinFile(params[0].get_str(), coinhash, errmsg)) {
        throw JSONRPCError(-1, string("The CryptoCoin maybe not existed: ") + errmsg);
    }

    CBlock genesis = newcurrency.GetGenesisBlock();
    if (genesis.GetHash() != newcurrency.GetHashGenesisBlock()) {
        throw JSONRPCError(-2, string("CryptoCoin genesis block data error"));
    }

    string requestid;
    //HCE: before call consensus layer function, unlock critical to avoid dead lock
    UNCRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        UNCRITICAL_BLOCK_T_MAIN(cs_main)
        {
            if (!CommitGenesisToConsensus(&genesis, requestid, errmsg)) {
                throw JSONRPCError(-3, string("CommitGenesisToConsensus failed: ") + errmsg);
            }
        }
    }

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}

void ReadBlockFromChainSpace(const T_LOCALBLOCKADDRESS& addr, CBlock& block)
{
    CHyperChainSpace* chainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!chainspace->GetLocalBlockPayload(addr, payload)) {
        throw JSONRPCError(-1, string("The local block not existed"));
    }

    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        throw JSONRPCError(-2, string("Incorrect local block data"));
    }
}

Value getcoininfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3)
        throw runtime_error("getcoininfo <hyperblockId> <chainNumber> <localId> \n");

    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stoi(params[0].get_str()),
        std::stoi(params[1].get_str()),
        std::stoi(params[2].get_str()));

    CBlock genesisBlock;
    ReadBlockFromChainSpace(addr, genesisBlock);

    CryptoCurrency currency(false);

    if (!currency.ParseCoin(genesisBlock)) {
        throw JSONRPCError(-3, string("Failed to parse local block data,maybe not genesis block"));
    }

    Object result;
    result.push_back(Pair("name", currency.GetName()));
    result.push_back(Pair("message", currency.GetDesc()));
    result.push_back(Pair("model", currency.GetModel()));
    result.push_back(Pair("logo", currency.GetLogo()));
    result.push_back(Pair("hash", currency.GetHashPrefixOfGenesis()));
    return result;
}

Value querygenesisblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("querygenesisblock <GID>\n");
    uint32_t hid;
    uint16 chainnum;
    uint16 localid;

    string uuid = params[0].get_str();
    string requestid = CryptoCurrency::GetRequestID(uuid);

    //HCE: query database
    T_LOCALBLOCKADDRESS addr;
    if (!requestid.empty())
    {
        bool isfound = Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestid, addr);
        if (!isfound) {
            throw JSONRPCError(-1, string("GID not exist"));
        }
    }

    Object result;
    result.push_back(Pair("hyperblockId", addr.hid));
    result.push_back(Pair("chainNum", addr.chainnum));
    result.push_back(Pair("localblockId", addr.id));
    return result;
}

Value importcoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3)
        throw runtime_error("importcoin <hyperblockId> <chainNumber> <localId> \n");

    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stoi(params[0].get_str()),
        std::stoi(params[1].get_str()),
        std::stoi(params[2].get_str()));

    CBlock genesisBlock;
    ReadBlockFromChainSpace(addr, genesisBlock);
    if (!genesisBlock.CheckProgPow()) {
        throw JSONRPCError(-3, string("Failed to check genesis block"));
    }

    CryptoCurrency newcurrency(false);
    if (!newcurrency.ParseCoin(genesisBlock)) {
        throw JSONRPCError(-4, string("Failed to parse local block data,maybe not genesis block"));
    }

    newcurrency.SetGenesisAddr(addr.hid, addr.chainnum, addr.id);

    Object result;

    result.push_back(Pair("name", newcurrency.GetName()));
    result.push_back(Pair("message", newcurrency.GetDesc()));
    result.push_back(Pair("model", newcurrency.GetModel()));
    result.push_back(Pair("logo", newcurrency.GetLogo()));
    result.push_back(Pair("hash", newcurrency.GetHashPrefixOfGenesis()));

    return result;
}

//Value startmining(const Array& params, bool fHelp)
//{
//    if (fHelp)
//        throw runtime_error("startmining\n");
//
//    Object result;
//    if (!g_cryptoCurrency.AllowMining()) {
//        g_cryptoCurrency.StartMining();
//        result.push_back(Pair("result", "start mining for coin: " + g_cryptoCurrency.GetName()));
//        return result;
//    }
//    else {
//        throw JSONRPCError(-2, g_cryptoCurrency.GetName() + string(" already started"));
//    }
//}

//Value stopmining(const Array& params, bool fHelp)
//{
//    if (fHelp)
//        throw runtime_error("stopmining\n");
//
//    if (!g_cryptoCurrency.AllowMining()) {
//        throw JSONRPCError(-2, "already stopped");
//    }
//
//    if (!g_cryptoCurrency.StopMining()) {
//        throw JSONRPCError(-3, "cannot stopped");
//    }
//
//    Object result;
//    result.push_back(Pair("result", "stopped"));
//    return result;
//}

Value queryminingstatus(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error("queryminingstatus\n");

    bool isAllowed;
    string strDescription = g_miningCond.GetMiningStatus(&isAllowed);

    Object result;
    result.push_back(Pair("status", isAllowed ? "mining" : "stopped"));

    result.push_back(Pair("statuscode", g_miningCond.MiningStatusCode()));

    if (g_miningCond.IsBackTracking()) {
        BackTrackingProgress progress = g_miningCond.GetBackTrackingProcess();
        result.push_back(Pair("latestheight", progress.nLatestBlockHeight));
        result.push_back(Pair("latesttripleaddr", progress.strLatestBlockTripleAddr));
        result.push_back(Pair("backtrackingheight", progress.nBackTrackingBlockHeight));
        result.push_back(Pair("backtrackinghash", progress.strBackTrackingBlockHash));
    }

    result.push_back(Pair("currentheight", (pindexBest ? pindexBest->nHeight : 0)));
    result.push_back(Pair("statusdesc", strDescription));

    return result;
}

//HCE: Generate a chain address which uses as target address of cross-chain transaction
extern "C" BOOST_SYMBOL_EXPORT
bool getchainaddress(const map<string, string>&mapparams, string & hexaddress, string & strError)
{
    //<hid> <chainid> <localid> <hash of genesis block of target chain> [recv address on target chain]: generate a target chain address");

    WitnessCrossChainHash wcc;

    wcc.genesis_hid = atoi(mapparams.at("hid").c_str());
    wcc.genesis_chainid = atoi(mapparams.at("chainid").c_str());
    wcc.genesis_localid = atoi(mapparams.at("localid").c_str());

    if (mapparams.count("recv_address")) {
        auto recvaddr = ParseHex(mapparams.at("recv_address").c_str());
        std::reverse(recvaddr.begin(), recvaddr.end());
        wcc.recv_address = BaseHash<uint160>(uint160(recvaddr));
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    T_LOCALBLOCKADDRESS addr;
    addr.set(wcc.genesis_hid, wcc.genesis_chainid, wcc.genesis_localid);

    T_SHA256 hb_thash;
    if (!hyperchainspace->GetHyperBlockHash(wcc.genesis_hid, hb_thash)) {
        //throw JSONRPCError(-1,
        //    StringFormat("The hyper block(%d) not exist", wcc.hid));
        strError = StringFormat("The hyper block(%d) not exist", wcc.genesis_hid);
    }

    wcc.hhash = BaseHash<uint160>(right160(hb_thash));

    T_LOCALBLOCK localblock;
    if (hyperchainspace->GetLocalBlock(addr, localblock)) {

        if (!localblock.GetAppType().isEthereumGenesis()) {
            //throw JSONRPCError(-1,
            //    StringFormat("The local block(%d %d %d) isn't genesis block of ethereum", addr.hid, addr.chainnum, addr.id));
            strError = StringFormat("The local block(%d %d %d) isn't genesis block of ethereum", addr.hid, addr.chainnum, addr.id);
        }

        //    T_SHA256 localchainhash = localblock.GetHashSelf();
        //    auto genesishash = right160(localchainhash);
        //    wcc.genesis_block_hash = BaseHash<uint160>(genesishash);
        //    bool isEqual = std::equal(genesishash.begin(), genesishash.end(), wcc.genesis_block_hash.begin());
        //    if (!isEqual) {
        //        throw JSONRPCError(-1,
        //            StringFormat("genesis block hash %s in chain not match with %s",
        //                HexStr(wcc.genesis_block_hash.begin(), wcc.genesis_block_hash.end()),
        //                HexStr(genesishash.begin(), genesishash.end())));
        //    }
    }
    else {
        //throw JSONRPCError(-2,
        //    StringFormat("Cannot read the local block(%d %d %d) in my storage", addr.hid, addr.chainnum, addr.id));
        strError = StringFormat("Cannot read the local block(%d %d %d) in my storage", addr.hid, addr.chainnum, addr.id);
    }

    uint256 h = uint256S(mapparams.at("target_genesis_hash").c_str());
    std::reverse(h.begin(), h.end());

    auto genesishash = right160(h);
    wcc.genesis_block_hash = BaseHash<uint160>(genesishash);

    //CTxDestination address(wcc);
    //hexaddress = EncodeDestination(address);

    //HC: ImmutableWitnessCrossChainHash is more short than WitnessCrossChainHash
    CTxDestination address((ImmutableWitnessCrossChainHash)wcc);
    hexaddress = EncodeDestination(address);

    //CTxDestination addr = DecodeDestination(hexaddress);

    //ostringstream oss;
    //oss << StringFormat("hyper block(%d %d %d)\n base hash %s",
    //    wcc.hid, wcc.chainid, wcc.localid, wcc.hhash.ToString()) << endl;
    //oss << StringFormat("hash of genesis block of target chain %s", wcc.genesis_block_hash.ToString());
    //oss << StringFormat("receiving address of target chain %s", wcc.recv_address.ToString());
    //oss << StringFormat("cross chain target address", hexaddress);

    //Object ret;
    //ret.push_back(Pair("hyper block", StringFormat("%d %d %d", wcc.hid, wcc.chainid, wcc.localid)));
    //ret.push_back(Pair("hyper block base hash", StringFormat("%s", wcc.hhash.ToString())));
    //ret.push_back(Pair("hash of genesis block of target chain", StringFormat("%s", wcc.genesis_block_hash.ToString())));
    //ret.push_back(Pair("receiving address of target chain", StringFormat("%s", wcc.recv_address.ToString())));
    //ret.push_back(Pair("cross chain target address", hexaddress));

    return true;
}


//HC: 跨链转出
extern "C" BOOST_SYMBOL_EXPORT
bool sendtochain(const std::map<string, string>&mapparams, string & txhash, string & strError)
{
    if (pwalletMain->IsCrypted() && (mapparams.size() < 2)) {
        strError = "sendtochain <fromaccount> <tochainaddress> <amount> <toaddress>\n"
            "<amount> is a integer and 100000000 equals 1 para\n"
            "requires wallet passphrase to be set with walletpassphrase first";
        return false;
    }

    try {
        string strAccount = AccountFromValue(mapparams.at("fromaccount"));

        CTxDestination address = DecodeDestination(mapparams.at("chainaddress"));
        if (!IsValidDestination(address)) {
            strError = "Invalid destination chain address";
            return false;
        }

        if (address.which() == TxDestinationIndex<ImmutableWitnessCrossChainHash>()) {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            ImmutableWitnessCrossChainHash immWitnessCC = boost::get<ImmutableWitnessCrossChainHash>(address);

            bool rc = false;
            string err;
            std::tie(rc, err) = consensuseng->CheckCrossChainTx(immWitnessCC.genesis_hid,
                immWitnessCC.genesis_chainid,
                immWitnessCC.genesis_localid,
                immWitnessCC.hhash,
                immWitnessCC.genesis_block_hash);

            if (!rc) {
                strError = StringFormat("Invalid destination chain address: %s", err);
                return false;
            }

            WitnessCrossChainHash witnessCC(std::move(immWitnessCC));
            auto& key = mapparams.at("senderprikey");
            witnessCC.sender_prikey = uint256S(key);

            uint160 toaddress;
            toaddress.SetHex(mapparams.at("to"));
            witnessCC.recv_address = BaseHash<uint160>(toaddress);

            //HC: Para交易的目标地址里带上Aleth交易的发送者地址，形成锁定关系
            CTxDestination addressTxDest(witnessCC);

            // Amount
            char* end = nullptr;
            int64 nAmount = std::strtoll(mapparams.at("amount").c_str(), &end, 10);

            CWalletTx wtx;
            wtx.strFromAccount = strAccount;

            if (pwalletMain->IsLocked()) {
                strError = "Please enter the wallet passphrase with walletpassphrase first.";
                return false;
            }

            // Check funds
            int nMinDepth = 1;
            if (!AccountBalanceIsEnough(strAccount, nMinDepth, nAmount)) {
                strError = "Account has insufficient funds";
                return false;
            }

            CScript scriptPubKey = GetScriptForDestination(addressTxDest);
            strError = pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
            if (strError != "")
                return false;

            txhash = wtx.GetHash().GetHex();
            return  true;
        }
        strError = "Invalid destination chain address type";
        return false;

    }
    catch (Object& objError) {
        strError = write_string(Value(objError), false);
        return false;
    }
    catch (std::exception& e) {
        strError = e.what();
        return false;
    }
}

//HC：跨链收款
extern "C" BOOST_SYMBOL_EXPORT bool recvfromchain(const map<string, string>&mapparams, string & txhash, string & strError)
{
    if (pwalletMain->IsCrypted() && (mapparams.size() < 2)) {
        strError = "recvfromchain <chain address> <amount> [comment] [comment-to]\n"
            "<amount> is a integer and 100000000 equals 1 para\n"
            "requires wallet passphrase to be set with walletpassphrase first";
        return false;
    }

    try {
        char* end = nullptr;
        int64 nAmount = std::strtoll(mapparams.at("amount").c_str(), &end, 10);

        // Wallet comments
        CWalletTx wtx;
        wtx.fromCrossChain = true;
        wtx.fromethtxhash = mapparams.at("eth_tx_hash");

        uint256 genesishash = uint256S(mapparams.at("genesis_block_hash").c_str());

        std::reverse(genesishash.begin(), genesishash.end());

        //auto genesishash = right160(h);
        wtx.fromgenesisblockhash = BaseHash<uint256>(genesishash);

        if (pwalletMain->IsLocked()) {
            strError = "Error: Please enter the wallet passphrase with walletpassphrase first.";
            return false;
        }

        /* CTxDestination address = DecodeDestination(mapparams.at("para_recv_script"));
         if (!IsValidDestination(address)) {
             strError = "Invalid destination address";
             return false;
         }*/

         //CScript scriptPubKey = GetScriptForDestination(address);
        auto script = ParseHex(mapparams.at("para_recv_script"));
        CScript scriptPubKey(script.begin(), script.end());

        //HC: 以太坊转出交易hash + 签名 + 公钥 + 以太坊子链创世块hash 构成输入签名脚本
        wtx.fromscriptSig << ParseHex(wtx.fromethtxhash)
            << ParseHex(mapparams.at("eth_tx_publickey"))
            << (unsigned int)std::stoul(mapparams.at("eth_tx_hid"))
            << (unsigned short)std::stoul(mapparams.at("eth_tx_chainid"))
            << (unsigned short)std::stoul(mapparams.at("eth_tx_localid"))
            << genesishash;

        strError = pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
        if (strError != "")
            return false;

        txhash = wtx.GetHash().GetHex();
    }
    catch (Object& objError) {
        strError = write_string(Value(objError), false);
        return false;
    }

    return true;
}

extern "C" BOOST_SYMBOL_EXPORT bool GetDestinationFromScriptPubKey(const string & scriptpubkey,
    string & destinationaddress,
    string & err)
{

    auto script = ParseHex(scriptpubkey);
    CScript sc(script.begin(), script.end());

    CTxDestination address;
    ExtractDestination(sc, address);

    if (!IsValidDestination(address)) {
        err = "Invalid address";
        return false;
    }
    destinationaddress = EncodeDestination(address);
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT bool GetScriptPubKeyFromDestination(const string & destinationaddress,
    string & scriptpubkey,
    string & err)
{
    CTxDestination address = DecodeDestination(destinationaddress);
    if (!IsValidDestination(address)) {
        err = "Invalid address";
        return false;
    }

    CScript scriptPubKey = GetScriptForDestination(address);
    scriptpubkey = ToHexString(ToByteVector(scriptPubKey));
    return true;
}

extern bool ForwardFindBlockInMain(int blkheight, const uint256& blkhash, int h1, int h2, CBlock& block,
    BLOCKTRIPLEADDRESS& blktriaddr, vector<int>& vecHyperBlkIdLacking);

bool GetTxState(const string &txhash, int &blocknum, int64_t &blockstamp, int &blockmaturity,
    int64_t &hyperId,
    int64_t &chainId,
    int64_t &localId,
    string &desc,
    string &strError)
{
    blocknum = -1;
    blockmaturity = -1;

    hyperId = -1;
    chainId = 0;
    localId = 0;

    uint256 hashtx(txhash);
    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    CTransaction tx;
    bool fFound = txdb.ReadTxIndex(hashtx, txindex);

    if (fFound) {
        if (tx.ReadFromDisk(txindex.pos)) {
            if (tx.GetHash() != hashtx) {
                strError = "Failed to ReadFromDisk raw transaction";
                return false;
            }

            blockmaturity = txindex.GetDepthInMainChain();
            blocknum = 1 + nBestHeight - blockmaturity;
            desc = "The transaction has been packaged and added to the chain";

            CBlock block;
            BLOCKTRIPLEADDRESS addrblock;
            char* pWhere = nullptr;
            if (GetBlockData(txindex.pos.hashBlk, block, addrblock, &pWhere)) {
                BLOCKTRIPLEADDRESS triaddr;
                vector<int> vecHyperBlkIdLacking;

                blockstamp = block.nTime;
                int64_t start_hid = block.nPrevHID + 1;
                int64_t end_hid = block.nPrevHID + 2;

                CBlock blk;
                if (ForwardFindBlockInMain(txindex.pos.nHeightBlk,
                    txindex.pos.hashBlk, start_hid, end_hid, blk, triaddr, vecHyperBlkIdLacking)) {
                    hyperId = triaddr.hid;
                    chainId = triaddr.chainnum;
                    localId = triaddr.id;
                }
            }
            return true;
        }
    } else {
        if (mapTransactions.count(hashtx)) {
            desc = "The transaction is in transaction pool";
            return true;
        }
    }

    strError = "Failed to get raw transaction";
    return false;
}

extern "C" BOOST_SYMBOL_EXPORT
bool GetTxDetails(const string & strhash, std::map<string, string>&mapparams, string & strError)
{
    uint256 hashtx(strhash);
    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    CTransaction tx;
    bool fFound = txdb.ReadTxIndex(hashtx, txindex);

    if (fFound) {
        fFound = false;
        if (tx.ReadFromDisk(txindex.pos)) {
            if (tx.GetHash() == hashtx) {
                fFound = true;
            }
        }
    }
    else {
        if (mapTransactions.count(hashtx)) {
            tx = mapTransactions.at(hashtx);
            fFound = true;
        }
    }

    if (fFound) {
        for (auto& elm : tx.vout) {
            CTxDestination addressRet;
            ExtractDestination(elm.scriptPubKey, addressRet);
            if (addressRet.which() == TxDestinationIndex<WitnessCrossChainHash>()) {

                WitnessCrossChainHash witnessCC = boost::get<WitnessCrossChainHash>(addressRet);

                //HC：获取链地址
                ImmutableWitnessCrossChainHash imm = witnessCC;
                addressRet = CTxDestination(imm);
                mapparams["chainaddress"] = EncodeDestination(addressRet);

                mapparams["amount"] = StringFormat("%lld", elm.nValue);
                //mapparams["senderaddress"] = witnessCC.sender_address.ToString();
                mapparams["senderprikey"] = witnessCC.sender_prikey.ToString();
                mapparams["to"] = witnessCC.recv_address.ToString();
                break;
            }
        }
        return true;
    }

    strError = "Failed to get raw transaction";
    return false;
}


bool _VerifyTxHelp(const CTransaction& tx, 
    const uint32_t& eth_genesis_hid,
    const uint16_t& eth_genesis_chainid,
    const uint16_t& eth_genesis_localid,
    const string& eth_genesis_blockhash,
    const string& senderpublickey,
    const string& recvaddress,
    const string& amount,
    string& errinfo)
{
    uint256 target_genesis_hash = uint256S(eth_genesis_blockhash.c_str());
    std::reverse(target_genesis_hash.begin(), target_genesis_hash.end());
    auto genesishash = right160(target_genesis_hash);

    uint160 toaddress;
    toaddress.SetHex(recvaddress);
    BaseHash<uint160> recvaddr(toaddress);

    errinfo = "unknown transaction";

    //HC: 比较交易参数是否一致
    for (auto& elm : tx.vout) {
        CTxDestination addressRet;
        ExtractDestination(elm.scriptPubKey, addressRet);
        if (addressRet.which() == TxDestinationIndex<WitnessCrossChainHash>()) {

            if (StringFormat("%lld", elm.nValue) == amount) { //HC：转账金额

                WitnessCrossChainHash witnessCC = boost::get<WitnessCrossChainHash>(addressRet);
                if (witnessCC.recv_address == recvaddr) { //HC: 收款地址

                     //HC：目标链地址比较
                    if (witnessCC.genesis_hid == eth_genesis_hid &&
                        witnessCC.genesis_chainid == eth_genesis_chainid &&
                        witnessCC.genesis_localid == eth_genesis_localid &&
                        witnessCC.genesis_block_hash == BaseHash<uint160>(genesishash)) {

                        //HC: 比较eth交易的发送者公钥
                        if (AppPlugins::callFunction<bool>("aleth", "validateswapkey", witnessCC.sender_prikey.GetHex(), senderpublickey)) {
                            return true;
                        }
                        errinfo = "illegal sender";
                    }
                    else {
                        errinfo = "illegal target chain";
                    }
                }
                else {
                    errinfo = "illegal receiving address";
                }
            }
            else {
                errinfo = "illegal funds";
            }
            break;
        }
    }
    return false;
}

//
//HC：Para转到eth, 系统分别在Para上创建一笔Tp转出交易，Eth上创建一笔Te转入交易
//HC: Aleth模块调用本函数来验证Te所对应的Tp交易，以便确定Te的合法性
//HC: 适用于节点自身运行了Para应用的情形
//
extern "C" BOOST_SYMBOL_EXPORT
bool VerifyTxParaAppLoaded(const string & hextxhash, 
                           const uint32_t & eth_genesis_hid,
                           const uint16_t & eth_genesis_chainid,
                           const uint16_t & eth_genesis_localid,
                           const string & eth_genesis_blockhash,
                           const string & senderpublickey,
                           const string & recvaddress,
                           const string & amount,
                           string & errinfo)
{
    uint256 hashtx(hextxhash);

    int verbosity = 1;

    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    CTransaction tx;
    bool fFound = txdb.ReadTxIndex(hashtx, txindex);

    if (fFound) {
        if (tx.ReadFromDisk(txindex.pos)) {
            if (tx.GetHash() == hashtx) {
                //return fngettx(tx, verbosity, txindex.GetDepthInMainChain(), txindex);
                if (txindex.GetDepthInMainChain() < 0) {
                    return false;
                }
                return _VerifyTxHelp(tx, eth_genesis_hid, eth_genesis_chainid, eth_genesis_localid, eth_genesis_blockhash,
                    senderpublickey, recvaddress, amount, errinfo);

            }
        }
    } else {
        CRITICAL_BLOCK(cs_mapTransactions)
            if (mapTransactions.count(hashtx)) {
                //HC: already exist in transaction pool
                return _VerifyTxHelp(tx, eth_genesis_hid, eth_genesis_chainid, eth_genesis_localid, eth_genesis_blockhash,
                    senderpublickey, recvaddress, amount, errinfo);
            }
    }

    errinfo = "Transaction cannot be found from Para chain";
    return false;
}


//HC: 跨链交易，Para转到eth, 系统分别在Para上创建一笔Tp转出交易，Eth上创建一笔Te转入交易
//HC: Aleth模块调用本函数来验证Te所对应的Tp交易，以便确定Te的合法性
//HC: 参数说明：
//HC: eth_genesis_hid, eth_genesis_chainid, eth_genesis_localid: Eth链创世块的三元组地址
//HC: eth_genesis_blockhash: Eth链创世块的hash
//
extern "C" BOOST_SYMBOL_EXPORT
bool VerifyTx(const string & payload,                      //要验证的交易所在块
    const bool &paraappgood,
    const string &hextxhash,
    const uint32_t &eth_genesis_hid,
    const uint16_t &eth_genesis_chainid,
    const uint16_t &eth_genesis_localid,
    const string &eth_genesis_blockhash,
    const string &senderpublickey,
    const string &recvaddress,
    const string &amount,
    string &errinfo)
{
    if (paraappgood) {
        bool found = VerifyTxParaAppLoaded(hextxhash, eth_genesis_hid, eth_genesis_chainid, eth_genesis_localid, eth_genesis_blockhash,
            senderpublickey, recvaddress, amount, errinfo);
        if (found) {
            return true;
        }
    }

    //HC: extract transactions from block
    CBlock blk;
    if (!ResolveBlock(blk, payload.c_str(), payload.size()))
        return false;

    uint256 target_genesis_hash = uint256S(eth_genesis_blockhash.c_str());
    std::reverse(target_genesis_hash.begin(), target_genesis_hash.end());
    auto genesishash = right160(target_genesis_hash);

    uint160 toaddress;
    toaddress.SetHex(recvaddress);
    BaseHash<uint160> recvaddr(toaddress);

    errinfo = "Transaction cannot be found";

    uint256 h(hextxhash);
    for (auto& tx : blk.vtx) {
        if (tx.GetHash() == h) {
            return _VerifyTxHelp(tx, eth_genesis_hid, eth_genesis_chainid, eth_genesis_localid, eth_genesis_blockhash,
                senderpublickey, recvaddress, amount, errinfo);
        }
    }

    return false;
}


#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            printf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    }
    catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif
