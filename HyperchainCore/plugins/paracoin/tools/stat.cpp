/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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



#include <boost/filesystem.hpp>

#include <regex>

#undef printf

extern bool ExtractAddress(const CScript& scriptPubKey, std::vector<unsigned char>& vchPubKey);

using PUBKEY = std::vector<unsigned char>;

std::set<T_SHA256> g_setLocalBlockScanned;
map<PUBKEY, int64> g_mapWallet;


class hcstatlogger
{
public:
    hcstatlogger()
    {

        std::string logpath = ".";
        std::string dlog = logpath + "/stat_hyperchain.log";
        std::string flog = logpath + "/stat_hyperchain_basic.log";
        std::string rlog = logpath + "/stat_hyperchain_rotating.log";
        spdlog::set_level(spdlog::level::err);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        g_daily_logger = spdlog::daily_logger_mt("stat_daily_logger", dlog.c_str(), 0, 30);
        g_daily_logger->set_level(spdlog::level::info);
        g_basic_logger = spdlog::basic_logger_mt("stat_file_logger", flog.c_str());

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


            if (g_setLocalBlockScanned.count(thhash)) {
                continue;
            }
            g_setLocalBlockScanned.insert(thhash);


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

int main(int argc, char* argv[])
{
    namespace fs = boost::filesystem;

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

    /* const valtype& vchPubKey = item.second;
     vector<unsigned char> vchPubKeyFound;
     if (!keystore.GetPubKey(Hash160(vchPubKey), vchPubKeyFound))
         return false;
     if (vchPubKeyFound != vchPubKey)
         return false;*/

    return 0;
}