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

#include "globalconfig.h"
#include "newLog.h"

#include "headers.h"
#include "db/dbmgr.h"
#include "../dllmain.h"
#include "node/HCMQBroker.h"
#include "node/defer.h"
#include "plshared.h"


#include <boost/filesystem.hpp>

#include <regex>

#undef printf

extern bool ExtractAddress(const CScript& scriptPubKey, std::vector<unsigned char>& vchPubKey);

using PUBKEY = std::vector<unsigned char>;

std::set<T_SHA256> g_setLocalBlockScanned;
map<PUBKEY, int64> g_mapWallet;


class CBulkWallet : public CWalletDB
{
public:

    using CWalletDB::CWalletDB;

    CBulkWallet(const string& strWalletFile) :
        _dstWalletFile(strWalletFile),
        CWalletDB(strWalletFile, "cr+")
    {
    }

    void Import(CWallet &dstWallet)
    {
        cout << "Start wallet data import...\n";

        CBulkWallet srcW(_dstWalletFile, "r");

        if (!srcW.BulkImpWalletKey(&dstWallet))
            throw runtime_error("CBulkWallet : can't import wallet key");

        if (!srcW.BulkImpWalletWKey(&dstWallet))
            throw runtime_error("CBulkWallet : can't import wallet wkey");

        if (!srcW.BulkImpWalletMKey(&dstWallet))
            throw runtime_error("CBulkWallet : can't import wallet mkey");

        if (!srcW.BulkImpWalletCKey(&dstWallet))
            throw runtime_error("CBulkWallet : can't import wallet ckey");

        if (!srcW.ReadDefaultKey(dstWallet.vchDefaultKey)) {
            throw runtime_error("CBulkWallet : can't import wallet default key");
        }
    }

private:

    bool impKey(CWallet* pwallet, CDataStream& ssKeySecond, CDataStream& ssValue, std::vector<unsigned char>& vchPubKey)
    {
        ssKeySecond >> vchPubKey;
        vector<unsigned char> vchPrivKey;
        ssValue >> vchPrivKey;

        CPrivKey privkey;
        privkey.resize(vchPrivKey.size());
        std::copy(vchPrivKey.begin(), vchPrivKey.end(), privkey.begin());

        CKey keyPair;
        if (!keyPair.SetPrivKey(privkey)) {
            return "Incorrect private key\n";
        }
        CCryptoKeyStore* p = pwallet;
        p->AddKey(vchPubKey, keyPair);
        return true;

        CBitcoinAddress coinaddress = CBitcoinAddress(keyPair.GetPubKey());
        if (pwallet->HaveKey(coinaddress)) {
            //"Key pair has already been in wallet\n";
            return true;
        }
        else if (pwallet->AddKey(vchPubKey, keyPair)) {
            return true;
        }

        return false;
    }

    bool BulkImpWalletUser(CWalletDB* pDstWalletdb)
    {
        std::function<bool(CDataStream&, CDataStream&, string&)> fn = [this, pDstWalletdb](CDataStream& ssKeySecond,
            CDataStream& ssValue, string& strAddress) ->bool {

            ssKeySecond >> strAddress;
            string strname;
            ssValue >> strname;
            pDstWalletdb->WriteName(strAddress, strname);
            return true;
        };

        std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("name"), nextT);
            msgstatus = strprintf("name : %s", nextT.c_str());  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("name"), string(""));

        if (!BulkLoad("name", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CBulkWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("key"), nextT);
            msgstatus = "key : ******";  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("key"), veckey);

        if (!BulkLoad("key", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletWKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CBulkWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("wkey"), nextT);
            msgstatus = "wallet key : ******";  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("wkey"), veckey);

        if (!BulkLoad("wkey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    //HCE: Encrypt bitcoin's key pair using vMasterkey
    //HCE: vMasterkey is plain text, kMasterKey contains cipher text
    //HCE: crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey), see CWallet::EncryptWallet(const string& strWalletPassphrase)
    bool BulkImpWalletMKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, unsigned int&)> fn = [pwallet](CDataStream& ssKeySecond,
            CDataStream& ssValue, unsigned int& nID) ->bool {

            ssKeySecond >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if (pwallet->mapMasterKeys.count(nID) != 0)
                return false; //DB_CORRUPT;
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
            return true;
        };

        std::function<CDataStream(const unsigned int&, string&)> fnNext = [](const unsigned int& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("mkey"), nextT);
            msgstatus = "mkey : ******";  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("mkey"), 0);
        if (!BulkLoad("mkey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    //HCE: crypt keys
    bool BulkImpWalletCKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CBulkWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("ckey"), nextT);
            msgstatus = "ckey : ******";  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("ckey"), veckey);

        if (!BulkLoad("ckey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletSettings(CWalletDB* pDstWalletdb)
    {
        std::function<bool(CDataStream&, CDataStream&, string&)> fn = [this, pDstWalletdb](CDataStream& ssKeySecond,
            CDataStream& ssValue, string& strKey) ->bool {

            //HCE: read all unused key pairs
            ssKeySecond >> strKey;

            // Options
            int nValue = 0;

            if (strKey == "fGenerateBitcoins" ||
                strKey == "nTransactionFee" ||
                strKey == "fLimitProcessors" ||
                strKey == "nLimitProcessors" ||
                strKey == "fMinimizeToTray" ||
                strKey == "fMinimizeOnClose" ||
                strKey == "fUseProxy" ||
                strKey == "addrProxy" ||
                strKey == "fUseUPnP") {
                ssValue >> nValue;
                pDstWalletdb->WriteSetting(strKey, nValue);
            }

            return true;
        };

        std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("setting"), nextT);
            msgstatus = "setting : ******";  //HCE: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("setting"), string(""));
        if (!BulkLoad("setting", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

private:
    string _dstWalletFile;
};

class hcstatlogger
{
public:
    hcstatlogger()
    {

        std::string logpath = ".";
        std::string dlog = logpath + "/stat_hyperchain.log";
        std::string flog = logpath + "/stat_hyperchain_basic.log";
        std::string rlog = logpath + "/stat_hyperchain_rotating.log";
        spdlog::set_level(spdlog::level::err); //HCE: Set specific logger's log level
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        g_daily_logger = spdlog::daily_logger_mt("stat_daily_logger", dlog.c_str(), 0, 30);
        g_daily_logger->set_level(spdlog::level::info);
        g_basic_logger = spdlog::basic_logger_mt("stat_file_logger", flog.c_str());
        //HCE: Create a file rotating logger with 100M size max and 3 rotated files.
        g_rotating_logger = spdlog::rotating_logger_mt("stat_rotating_logger", rlog.c_str(), 1048576 * 100, 3);
        g_console_logger = spdlog::stdout_color_mt("stat_console");
        g_console_logger->set_level(spdlog::level::err);
        g_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        g_consensus_console_logger = spdlog::stdout_color_mt("consensus");
        g_consensus_console_logger->set_level(spdlog::level::err);
        g_consensus_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        spdlog::flush_every(std::chrono::seconds(3));

    }

    ~hcstatlogger()
    {
        spdlog::shutdown();
    }
};

int ParseTx(const string& dbpath, uint32_t genesisHID, uint16_t genesisChainNum, uint16_t genesisID)
{
    DBmgr* _db = Singleton<DBmgr>::instance();
    _db->open(dbpath.c_str());
    if (!_db->isOpen()) {
        cout << "cannot open db file: " << dbpath << endl;
        return -1;
    }

    std::set<uint64> _localHID;
    int ret = _db->getAllHyperblockNumInfo(_localHID);

    std::set<uint64_t> setMyHIDInDB;
    for (auto iter = _localHID.lower_bound(genesisHID); iter != _localHID.end(); ++iter) {
        setMyHIDInDB.insert(*iter);
    }

    if (setMyHIDInDB.size() == 0) {
        cout << "not found any block, make sure " << dbpath << " is existed." << endl;
        return -1;
    }

    string mynodeid("123456789012345678901234567890ab", CUInt128::value * 2);
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::instance(mynodeid);

    defer{
        _db->close();
    };

    //HCE: load block triple address index
    vector<T_PAYLOADADDR> vecPA;
    T_SHA256 thhash;

    cout << "Paracoin Tool: scanning: " << dbpath << "\n"
         << "\t" << *setMyHIDInDB.rbegin() - genesisHID + 1 << " Hyperblocks on disk: " << endl;

    T_APPTYPE app(APPTYPE::paracoin, genesisHID, genesisChainNum, genesisID);

    uint64_t totalnum = setMyHIDInDB.size();
    uint64_t progress = 0;
    uint64_t cuurprogress = 0;

    auto iter = setMyHIDInDB.begin();
    for (; iter != setMyHIDInDB.end(); ++iter) {

        progress++;
        if (progress * 100 / totalnum > cuurprogress) {
            cuurprogress = progress * 100 / totalnum;
            if (cuurprogress % 2 == 0) {
                cout << ">";
            }
        }

        vecPA.clear();
        if (hyperchainspace->GetLocalBlocksByHIDDirectly(*iter, app, thhash, vecPA)) {

            //HCE: Check if the local block have already scanned.
            if (g_setLocalBlockScanned.count(thhash)) {
                continue;
            }
            g_setLocalBlockScanned.insert(thhash);

            //HCE: scan the Para transactions in local block
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                CBlock block;
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    continue;
                }

                if (block.vtx.size() > 0) {
                    CTransaction& tx = block.vtx.front();
                    if (tx.IsCoinBase()) {

                        PUBKEY vchPubKey;
                        if (ExtractAddress(tx.vout.front().scriptPubKey, vchPubKey)) {
                            if (g_mapWallet.count(vchPubKey)) {
                                g_mapWallet[vchPubKey] += tx.vout.front().nValue;
                            }
                            else {
                                g_mapWallet.insert(make_pair(vchPubKey, tx.vout.front().nValue));
                            }
                        }
                    }
                    else {
                        cout << "tx isn't coinbase" << endl;
                    }
                }
            }
        }
    }

    return 0;
}

//HCE: after sorting, identify txs whether is in my wallet
void IdentifyMyTrans(const string& txfilename, const string& resultfile)
{
    typedef struct
    {
        int id;
        string keyaddr;
        int64 val;
    } Item;

    list<Item> txs;

    FILE* fp = std::fopen(txfilename.c_str(), "r");
    if (!fp) {
        cout << strprintf("cannot open file: %s\n", txfilename.c_str());
        return;
    }

    CWallet *pwalletMain = new CWallet();
    CBulkWallet migr("wallet.dat");

    cout << "Start wallet import...";
    try {
        migr.Import(*pwalletMain);
    }
    catch (std::exception& e) {
        cout << e.what() << endl;
        return;
    }

    //bool fFirstRun;
    //int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    //if (nLoadWalletRet != DB_LOAD_OK) {
    //    cout << "cannot open wallet\n";
    //    return;
    //}

    CommadLineProgress progress;
    progress.Start();

    int64 nCount = 0;
    int64 nLast = 0;
    for (;; nCount++) {

        int id;
        int64 nValue = 0;
        char pubkeyaddress[512] = { 0 };

        int rs = std::fscanf(fp, "%u %s : %llu", &id, pubkeyaddress, &nValue);
        if (rs == EOF) {
            break;
        }
        Item item;
        item.id = id;
        item.keyaddr = pubkeyaddress;
        item.val = nValue;

        CBitcoinAddress paraaddr;
        paraaddr.SetString(item.keyaddr);

        if (pwalletMain->HaveKey(paraaddr)) {
            txs.push_back(item);
        }

        if (nCount - nLast > 10000) {
            progress.PrintStatus(nCount - nLast, strprintf("%s...: %llu", pubkeyaddress, nValue).c_str());
            nLast = nCount;
        }
    }

    if (std::ferror(fp)) {
        throw runtime_error(strprintf("I/O error when reading transaction file: %s\n", txfilename.c_str()));
    }
    std::fclose(fp);

    cout << strprintf("\nGot %u transactions\n", txs.size());

    //save result
    ofstream ff(resultfile);
    ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!ff) {
        cerr << strprintf("%s cannot be opened\n", resultfile.c_str());
        return;
    }


    int i = 1;
    int64 nTotal = 0;
    for (auto elm : txs) {
        //61 or 125 is server IP Address
        ff << elm.id << " " << elm.keyaddr << " : " << elm.val << endl;
        nTotal += elm.val;
    }
    ff << "Total:" << nTotal << endl;
    ff.close();

    cout << strprintf("\nTotal in wallet:%" PRI64d ", Result saved into % s\n", nTotal, resultfile.c_str());
}


void SortTrans(const string& txfilename, const string& resultfile)
{
    typedef struct
    {
        string key;
        int64 val;
    } Item;

    list<Item> txs;

    FILE* fp = std::fopen(txfilename.c_str(), "r");
    if (!fp) {
        throw runtime_error(strprintf("cannot open file: %s\n", txfilename.c_str()));
    }

    uint32_t genesisHID;
    uint32_t genesisChainNum;
    uint32_t genesisID;

    int rs = std::fscanf(fp, "Triple address: %u %u %u", &genesisHID, &genesisChainNum, &genesisID);
    cout << strprintf("Got chain genesis block triple address: %u %u %u\n", genesisHID, genesisChainNum, genesisID);


    CommadLineProgress progress;
    progress.Start();

    int64 nCount = 0;
    int64 nLast = 0;
    for (;; nCount++) {

        int64 nValue = 0;
        char pubkey[512] = { 0 };

        int rs = std::fscanf(fp, "%s : %llu", pubkey, &nValue);
        if (rs == EOF) {
            break;
        }
        Item item;
        item.key = pubkey;
        item.val = nValue;

        if (item.val <= 800000000) {
            txs.push_back(item);
        }
        else if (item.val > 800000000) {

            bool added = false;
            auto iter = txs.begin();
            for (; iter != txs.end(); ++iter) {
                if (iter->val <= item.val) {
                    txs.insert(iter, item);
                    added = true;
                    break;
                }
            }

            if (!added) {
                txs.push_back(item);
            }
        }

        if (nCount - nLast > 10000) {
            pubkey[16] = '\0';
            progress.PrintStatus(nCount - nLast, strprintf("%s...: %llu", pubkey, nValue).c_str());
            nLast = nCount;
        }
    }

    if (std::ferror(fp)) {
        throw runtime_error(strprintf("I/O error when reading transaction file: %s\n", txfilename.c_str()));
    }
    std::fclose(fp);

    cout << strprintf("\nGot %u transactions\n", txs.size());

    //save result
    ofstream ff(resultfile);
    ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!ff) {
        cerr << strprintf("%s cannot be opened\n", resultfile.c_str());
        return;
    }


    int i = 1;
    for (auto elm : txs) {
        CBitcoinAddress bitcoinaddr;
        bitcoinaddr.SetPubKey(ParseHex(elm.key));
        ff << i++ << " " << bitcoinaddr.ToString() << " : " << elm.val << endl;
    }
    ff.close();

    cout << strprintf("\nResult saved into %s\n", resultfile.c_str());
}


int main(int argc, char* argv[])
{
    namespace fs = boost::filesystem;
    AppParseParameters(argc, argv);

    //SortTrans(R"(E:\BaiduNetdiskDownload\52\paralism111111.tx)",
    //    R"(E:\BaiduNetdiskDownload\52\paralism_sort.tx)"
    //);

    //HCE: -datadir=E:\workspace\git\buildwin64\bin\Debug\xx  -model=informal
    string strDataDir = GetDataDir();
    cout <<
        strprintf("This program parse address of txs whether they is in wallet for Paracoin\n"
            "Please put wallet files into %s ", strDataDir.c_str()) << endl;

    IdentifyMyTrans(R"(E:\BaiduNetdiskDownload\52\paralism_sort.tx)",
        R"(E:\BaiduNetdiskDownload\52\paralism_sort_52.tx)"
    );

    //IdentifyMyTrans(strDataDir + R"(\paralism_sort_addr.tx)",
    //    strDataDir + R"(\paralism_sort_in_wallet.tx)"
    //);
    return 0;


    SoftwareInfo();
    if (argc !=4) {
        cout << "At first, put all hyper chain db files in current directory, file name must start with 'hyperchain', and end with '.db'." << endl;
        cout << "\tFor example: hyperchain125.db, hyerchainuuxeee.db" << endl;
        cout << "Usage: stat hid chainnum id" << endl;
        cout << "Result is in paralism.tx" << endl;
        return -1;
    }

    hcstatlogger log;

    uint32_t genesisHID = atoi(argv[1]);
    uint16_t genesisChainNum = atoi(argv[2]);
    uint16_t genesisID = atoi(argv[3]);

    std::regex base_regex("hyperchain.*\\.db");
    std::smatch base_match;

    fs::directory_iterator item_begin(boost::filesystem::system_complete("."));
    fs::directory_iterator item_end;
    for (; item_begin != item_end; item_begin++) {
        if (!fs::is_directory(*item_begin)) {
            std::string fname = item_begin->path().filename().string();
            if (std::regex_match(fname, base_match, base_regex)) {
                std::string dbpath = item_begin->path().string();
                ParseTx(dbpath, genesisHID, genesisChainNum, genesisID);
                cout << endl;
            }
        }
    }

    cout << "Parsing is finished, dumping result..." << endl;

    ofstream ofs("./paralism.tx");
    ofs << strprintf("Triple address: %u %u %u", genesisHID, genesisChainNum, genesisID)<< endl;
    for (auto& elm : g_mapWallet) {
        ofs << ToHexString(elm.first) << " : " << elm.second << endl;
    }
    cout << StringFormat("%d output results have already put into file: paralism.tx\n", g_mapWallet.size());
    //HCE: check if pubkey is 125 or 69
    /* const valtype& vchPubKey = item.second;
     vector<unsigned char> vchPubKeyFound;
     if (!keystore.GetPubKey(Hash160(vchPubKey), vchPubKeyFound))
         return false;
     if (vchPubKeyFound != vchPubKey)
         return false;*/

    return 0;
}
