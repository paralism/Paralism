/*Copyright 2016-2023 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "AppPlugins.h"
#include "newLog.h"

#include <cpprest/http_listener.h>
#include <cpprest/filestream.h>
#include "RestApi.h"

#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "../HyperChain/HyperChainSpace.h"
#include "../headers/commonstruct.h"
#include "../headers/inter_public.h"
//#include "../headers/UUFile.h"
#include "../HttpUnit/HttpUnit.h"
#include "../util/common.h"
#include "../consensus/buddyinfo.h"
#include "../consensus/consensus_engine.h"
#include "util/threadname.h"
#include "../node/defer.h"

#include "vm/vm.h"


#ifdef WIN32
#include <io.h>
#include <fcntl.h>
#include <codecvt>
#endif

#include <chrono>
#include <string>
#include <locale>
#include <sstream>
#include <regex>
using namespace std;
using std::chrono::system_clock;


#define MAX_BUF_LEN 512
#define LOCAL_BLOCK_BASE_LEN	sizeof(T_LOCALBLOCK)

#define BATCH_BUFFER_MAXIMUM  5
#define BATCH_DATA_MAXIMUM (1024 * 1024)

list<T_BATCHBUFFER> m_BatchBufferList;
CMutexObj m_MuxBatchBufferList;
T_PBATCHBUFFER input = nullptr;

std::map<uint64, system_clock::time_point> g_mapDownLoad;
std::mutex _guard;


std::shared_ptr<CommandHandler> g_spRestHandler;

list<thread>  m_threads;
bool _isstop = false;

string tstringToUtf8(const utility::string_t& str)
{
#ifdef _UTF16_STRINGS
    //HCE: On Windows, all strings are wide
    wstring_convert<codecvt_utf8<wchar_t> > strCnv;
    return strCnv.to_bytes(str);
#else
    //HCE: On POSIX platforms, all strings are narrow
    return str;
#endif
}

utility::string_t stringToTstring(const string& str)
{
#ifdef _UTF16_STRINGS
    //HCE: On Windows, all strings are wide
    std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> strCnv;
    return strCnv.from_bytes(str);
#else
    //HCE: On POSIX platforms, all strings are narrow
    return str;
#endif
}

bool CheckMyVersion(string& newversion)
{
    newversion = "";
    web::json::value json_return;
    try {
        web::json::value json_v;
        web::http::client::http_client client(_XPLATSTR("https://www.hyperchain.net/"));
        client.request(web::http::methods::GET, _XPLATSTR("/sw/ParalismLatestSWVersion.json"))
            .then([](const web::http::http_response& response) {
                return response.extract_json(); })
            .then([&json_return](const pplx::task<web::json::value>& task) {
                try {
                    json_return = task.get();
                }
                catch (const web::http::http_exception & e) {
                    std::cout << "error " << e.what() << std::endl;
                } })
            .wait();
    }
    catch (web::json::json_exception & je) {
        std::cout << je.what();
        return false;
    }
    catch (std::exception & e) {
        std::cout << e.what();
        return false;
    }

    if (!json_return.has_field(_XPLATSTR("version"))) {
        return false;
    }

    newversion = t2s(json_return[_XPLATSTR("version")].as_string());
    return true;
}

CommandHandler::CommandHandler(const utility::string_t &url) : m_listener(url)
{
    m_listener.support(methods::GET, std::bind(&CommandHandler::handle_get, this, std::placeholders::_1));
    m_listener.support(methods::POST, std::bind(&CommandHandler::handle_post, this, std::placeholders::_1));
    m_listener.support(methods::PUT, std::bind(&CommandHandler::handle_put, this, std::placeholders::_1));
    m_listener.support(methods::DEL, std::bind(&CommandHandler::handle_del, this, std::placeholders::_1));
}



std::vector<utility::string_t> requestPath(const http_request& message) {
    auto relativePath = uri::decode(message.relative_uri().path());
    return uri::split_path(relativePath);
}

//UUFile m_uufiletest;

utility::string_t resource_type(const utility::string_t& strSuffix)
{
    std::map<utility::string_t, utility::string_t> oVals;
    oVals[_XPLATSTR(".html")] = _XPLATSTR("text/html");
    oVals[_XPLATSTR(".js")] = _XPLATSTR("application/javascript");
    oVals[_XPLATSTR(".css")] = _XPLATSTR("text/css");
    oVals[_XPLATSTR(".png")] = _XPLATSTR("application/octet-stream");
    oVals[_XPLATSTR(".jpg")] = _XPLATSTR("application/octet-stream");

    auto pIt = oVals.find(strSuffix);
    if (pIt != oVals.end())
        return pIt->second;
    return _XPLATSTR("application/octet-stream");
}

#define BADPARAMETER(msg) message.reply(status_codes::OK, json::value(_XPLATSTR("Bad Parameter:"#msg)));

void CommandHandler::handle_get(http_request message)
{
    /*utility::string_t hash;

    auto uri = message.relative_uri().to_string();
    if (string::npos != uri.find(_XPLATSTR("html"))) {
        string localPath = m_uufiletest.GetAppPath();
        string confPath = localPath + "index.html";

        char *strBody = NULL;
        unsigned int uiRecvLen = 0;
        int ret = HttpDownloadF("http://192.168.0.55/hyperchain/index.html", &strBody, uiRecvLen);
        if (200 == ret) {
            message.reply(status_codes::OK, strBody, ::utility::conversions::to_utf8string("text/html; charset=utf-8"));
        }
        else {
            concurrency::streams::fstream::open_istream(stringToTstring(confPath.c_str()), std::ios::in).then([=](concurrency::streams::istream is)
            {
                message.reply(status_codes::OK, is, _XPLATSTR("text/html"));
            });
        }

        if (strBody != NULL) {
            delete strBody;
            strBody = NULL;
        }
        return;
    }*/

    g_basic_logger->debug("RestApi Method: {}, URI: {}, Query: {})", "GET", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));

    auto path = requestPath(message);
    if (!path.empty() && path.size() == 1) {

        std::map<utility::string_t, utility::string_t> query = uri::split_query(uri::decode(message.request_uri().query()));

        json::value vRet;

        if (path[0] == _XPLATSTR("SubmitRegistration")) {
            auto data = query.find(_XPLATSTR("data"));
            if (data == query.end()) {
                BADPARAMETER(data);
                return;
            }

            if (data != query.end() && !data->second.empty()) {
                string strdata = tstringToUtf8(data->second);

                RestApi api;
                SubmitData data;
                data.payload = strdata;
                http::status_code code;
                vRet = api.MakeRegistration(data, code);
            }
        }

        else if (path[0] == _XPLATSTR("SwapPara2Eth")) {
            auto cntEntryName = query.find(_XPLATSTR("name"));
            if (cntEntryName == query.end()) {
                BADPARAMETER(name);
                return;
            }

            auto cntEntryFrom = query.find(_XPLATSTR("fromaccount"));
            if (cntEntryFrom == query.end()) {
                BADPARAMETER(fromaccount);
                return;
            }

            auto cntEntryToChain = query.find(_XPLATSTR("tochain"));
            if (cntEntryToChain == query.end()) {
                BADPARAMETER(tochain);
                return;
            }

            auto cntEntryAmount = query.find(_XPLATSTR("amount"));
            if (cntEntryAmount == query.end()) {
                BADPARAMETER(amount);
                return;
            }

            std::string sName = tstringToUtf8(cntEntryName->second);
            std::string sFrom = tstringToUtf8(cntEntryFrom->second);
            std::string sToChain = tstringToUtf8(cntEntryToChain->second);
            std::string sAmount = tstringToUtf8(cntEntryAmount->second);

            std::string sToAdress;
            auto cntEntryToAdress = query.find(_XPLATSTR("toaddress"));
            if (cntEntryToAdress != query.end()) {
                sToAdress = tstringToUtf8(cntEntryToAdress->second);
            }

            if (sFrom == "\"\"" || sFrom == "\'\'") {
                sFrom = "";
            }

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap2Eth(sFrom, sToChain, sToAdress, sAmount, sName);
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapEth2Para")) {
            auto cntEntryName = query.find(_XPLATSTR("name"));
            if (cntEntryName == query.end()) {
                BADPARAMETER(name);
                return;
            }

            auto cntEntryFrom = query.find(_XPLATSTR("from"));
            if (cntEntryFrom == query.end()) {
                BADPARAMETER(from);
                return;
            }

            auto cntEntryTo = query.find(_XPLATSTR("to"));
            if (cntEntryTo == query.end()) {
                BADPARAMETER(to);
                return;
            }

            auto cntEntryAmount = query.find(_XPLATSTR("amount"));
            if (cntEntryAmount == query.end()) {
                BADPARAMETER(amount);
                return;
            }

            std::string sName = tstringToUtf8(cntEntryName->second);
            std::string sFrom = tstringToUtf8(cntEntryFrom->second);
            std::string sTo = tstringToUtf8(cntEntryTo->second);
            std::string sAmount = tstringToUtf8(cntEntryAmount->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap2Para(sFrom, sTo, sAmount, sName);
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapStatus")) {
            std::string sTxno;
            auto cntEntryTxno = query.find(_XPLATSTR("txno"));
            if (cntEntryTxno != query.end())
                sTxno = tstringToUtf8(cntEntryTxno->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("status", sTxno, "");
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapList")) {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("list", "", "");
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapImport")) {
            std::string sTxhash;
            auto cntEntryTxhash = query.find(_XPLATSTR("txhash"));
            if (cntEntryTxhash != query.end())
                sTxhash = tstringToUtf8(cntEntryTxhash->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("import", sTxhash, "");
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapImportse")) {
            std::string sTxhash;
            auto cntEntryTxhash = query.find(_XPLATSTR("txhash"));
            if (cntEntryTxhash != query.end())
                sTxhash = tstringToUtf8(cntEntryTxhash->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("importse", sTxhash, "");
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapRename")) {
            auto cntEntryTxno = query.find(_XPLATSTR("txno"));
            if (cntEntryTxno == query.end()) {
                BADPARAMETER(txno);
                return;
            }

            auto cntEntryNewname = query.find(_XPLATSTR("newname"));
            if (cntEntryNewname == query.end()) {
                BADPARAMETER(newname);
                return;
            }

            std::string sTxno = tstringToUtf8(cntEntryTxno->second);
            std::string sNewname = tstringToUtf8(cntEntryNewname->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("rename", sTxno, sNewname);
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("SwapDelete")) {
            auto cntEntryTxno = query.find(_XPLATSTR("txno"));
            if (cntEntryTxno == query.end()) {
                BADPARAMETER(txno);
                return;
            }

            std::string sTxno = tstringToUtf8(cntEntryTxno->second);

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
            string result = consensuseng->Swap("delete", sTxno, "");
            vRet = json::value::string(stringToTstring(result));
        }

        else if (path[0] == _XPLATSTR("GetChainAddress")) {
            auto cntEntryHid = query.find(_XPLATSTR("hid"));
            if (cntEntryHid == query.end()) {
                BADPARAMETER(hid);
                return;
            }

            auto cntEntryChainid = query.find(_XPLATSTR("chainid"));
            if (cntEntryChainid == query.end()) {
                BADPARAMETER(chainid);
                return;
            }

            auto cntEntryLocalid = query.find(_XPLATSTR("localid"));
            if (cntEntryLocalid == query.end()) {
                BADPARAMETER(localid);
                return;
            }

            auto cntEntryTargetHash = query.find(_XPLATSTR("targetgenesisblockhash"));
            if (cntEntryTargetHash == query.end()) {
                BADPARAMETER(targetgenesisblockhash);
                return;
            }
            
            map<string, string> mapparams;
            mapparams["hid"] = tstringToUtf8(cntEntryHid->second);
            mapparams["chainid"] = tstringToUtf8(cntEntryChainid->second);
            mapparams["localid"] = tstringToUtf8(cntEntryLocalid->second);
            mapparams["target_genesis_hash"] = tstringToUtf8(cntEntryTargetHash->second);

            string result, strerr;
            bool ret = AppPlugins::callFunction<bool>("paracoin", "getchainaddress", mapparams, result, strerr);
            if (ret)
                vRet = json::value::string(stringToTstring(result));
            else
                vRet = json::value::string(stringToTstring(strerr));
        }

        else if (path[0] == _XPLATSTR("GetHyperblocks")) {
            auto cntEntryId = query.find(_XPLATSTR("start_id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(start_id);
                return;
            }
            auto cntEntryNum = query.find(_XPLATSTR("num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(num);
                return;
            }

            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());
            uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getHyperblocks(nHyperBlockId, nNum);
        }

        else if (path[0] == _XPLATSTR("SyncHyperblock")) {
            auto cntEntryHId = query.find(_XPLATSTR("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            uint64_t nHyperBlockId = std::stol(tstringToUtf8(sHId));

            if (true == Singleton<DBmgr>::instance()->isBlockExisted(nHyperBlockId)) {
                vRet = json::value::string(_XPLATSTR("success"));
                goto REPLY;
            }

            {
                std::lock_guard<std::mutex> lck(_guard);
                map<uint64, system_clock::time_point>::iterator it = g_mapDownLoad.find(nHyperBlockId);
                if (it != g_mapDownLoad.end()) {
                    using seconds = std::chrono::duration<double, ratio<1>>;
                    system_clock::time_point curr = system_clock::now();
                    seconds timespan = std::chrono::duration_cast<seconds>(curr - it->second);
                    if (timespan.count() < 30) {
                        //HCE: the same HID only sync once in 30 seconds
                        vRet = json::value::string(_XPLATSTR("downloading"));
                        goto REPLY;
                    }
                }
            }

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
            int ret = HSpce->GetRemoteHyperBlockByID(nHyperBlockId);
            if (ret <= 0)
                vRet = json::value::string(_XPLATSTR("nonexistent"));
            else {
                std::lock_guard<std::mutex> lck(_guard);
                g_mapDownLoad[nHyperBlockId] = system_clock::now();
                vRet = json::value::string(_XPLATSTR("downloading"));
            }
        }

        else if (path[0] == _XPLATSTR("GetLocalBlock")) {
            auto cntEntryHId = query.find(_XPLATSTR("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(_XPLATSTR("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(_XPLATSTR("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblock(nHyperBlockId, nLocalBlockId, nNum);
        }

        else if (path[0] == _XPLATSTR("GetLocalChain")) {
            auto cntEntryHId = query.find(_XPLATSTR("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryNum = query.find(_XPLATSTR("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalchain(nHyperBlockId, nNum);
        }

        else if (path[0] == _XPLATSTR("GetOnchainState"))
        {
            auto id = query.find(_XPLATSTR("requestid"));
            if (id == query.end()) {
                BADPARAMETER(requestid);
                return;
            }

            if (id != query.end() && !id->second.empty()) {
                string strid = tstringToUtf8(id->second);

                RestApi api;
                vRet = api.getOnchainState(strid);
            }
        }

        else if (path[0] == _XPLATSTR("GetOnchainInfo"))
        {
            auto id = query.find(_XPLATSTR("requestid"));
            if (id == query.end()) {
                BADPARAMETER(requestid);
                return;
            }

            if (id != query.end() && !id->second.empty()) {
                string strid = tstringToUtf8(id->second);

                RestApi api;
                vRet = api.getOnchainInfo(strid);
            }
        }

        else if (path[0] == _XPLATSTR("GetBatchOnchainState"))
        {
            auto id = query.find(_XPLATSTR("batchid"));
            if (id == query.end()) {
                BADPARAMETER(requestid);
                return;
            }

            if (id != query.end() && !id->second.empty()) {
                string strid = tstringToUtf8(id->second);

                RestApi api;
                vRet = api.getBatchOnchainState(strid);
            }
        }

        else if (path[0] == _XPLATSTR("GetHyperBlockInfo"))
        {
            auto cntEntryId = query.find(_XPLATSTR("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockInfo(nHyperBlockId);
        }
        else if (path[0] == _XPLATSTR("GetHyperBlockHead"))
        {
            auto cntEntryId = query.find(_XPLATSTR("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockHead(nHyperBlockId);
        }
        else if (path[0] == _XPLATSTR("GetHyperBlockBody"))
        {
            auto cntEntryId = query.find(_XPLATSTR("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockBody(nHyperBlockId);
        }

        else if (path[0] == _XPLATSTR("GetLocalBlockHead"))
        {
            auto cntEntryHId = query.find(_XPLATSTR("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(_XPLATSTR("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(_XPLATSTR("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblockHead(nHyperBlockId, nLocalBlockId, nNum);
        }
        else if (path[0] == _XPLATSTR("GetLocalBlockBody"))
        {
            auto cntEntryHId = query.find(_XPLATSTR("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(_XPLATSTR("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(_XPLATSTR("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblockBody(nHyperBlockId, nLocalBlockId, nNum);
        }

        /*else if (path[0] == _XPLATSTR("GetRegWaitingList"))
        {
            ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr)
                return;

            LIST_T_LOCALCONSENSUS listInfo = consensuseng->GetPoeRecordList();
            ITR_LIST_T_LOCALCONSENSUS itr = listInfo.begin();
            int i = 0;
            for (itr; itr != listInfo.end(); itr++)
            {
                char strBuf[MAX_BUF_LEN] = {0};
                CCommonStruct::Hash512ToStr(strBuf, &(*itr).tLocalBlock.tPayLoad.tPayLoad.tFileHash);


                string_t oss;
                char num[8];
                memset(num, 0, sizeof(num));
                sprintf(num, "%d", i);
                oss = _XPLATSTR("readyOnChainHash[");
                oss += stringToTstring(num);
                oss += _XPLATSTR("]");
                vRet[oss] = json::value::string(stringToTstring(strBuf));

                i += 1;
            }

        }*/

        else if (path[0] == _XPLATSTR("GetListOnChainReqCount")) {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            T_P2PMANAGERSTATUS* pConsensusStatus = consensuseng->GetConsunsusState();

            size_t size = pConsensusStatus->GetListOnChainReqCount();
            vRet[_XPLATSTR("ListOnChainReqCount")] = json::value::number(size);
        }
        
        else if (path[0] == _XPLATSTR("GetLatestHyperBlockNo")) {
            uint64 localHID = Singleton<DBmgr>::instance()->getLatestHyperBlockNo();

            CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
            uint64 globalHID = hyperchainspace->GetGlobalLatestHyperBlockNo();

            if (localHID > globalHID)
                vRet[_XPLATSTR("laststHyperBlockNo")] = json::value::number(localHID);
            else
                vRet[_XPLATSTR("laststHyperBlockNo")] = json::value::number(globalHID);
        }
        else if (path[0] == _XPLATSTR("GetNodeRuntimeEnv"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            if (nodemgr == nullptr) {
                vRet[_XPLATSTR("NodeEnv")] = json::value::string(_XPLATSTR("initializing"));
            }
            else {
                HCNodeSH me = nodemgr->myself();
                string strnodeenv = me->serialize();

                vRet[_XPLATSTR("NodeEnv")] = json::value::string(s2t(strnodeenv));
            }
        }
        else if (path[0] == _XPLATSTR("GetStateOfCurrentConsensus"))
        {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("initializing"));
            }
            else {
                uint64_t blockNo;
                uint16 blockNum = 0;
                uint16 chainNum = 0;
                uint16 uiState = consensuseng->GetStateOfCurrentConsensus(blockNo, blockNum, chainNum);

                vRet[_XPLATSTR("curBuddyNo")] = json::value::number(blockNo);
                if (uiState == IDLE) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("idle"));
                }
                else if (uiState == LOCAL_BUDDY) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("localbuddy"));
                }
                else if (uiState == GLOBAL_BUDDY) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("globalbuddy"));
                }
            }
        }
        else if (path[0] == _XPLATSTR("GetDataOfCurrentConsensus")) {

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("initializing"));
            }
            else {
                uint64_t blockNo;
                uint16 blockNum = 0;
                uint16 chainNum = 0;
                uint16 uiState = consensuseng->GetStateOfCurrentConsensus(blockNo, blockNum, chainNum);

                vRet[_XPLATSTR("curBuddyNo")] = json::value::number(blockNo);
                if (uiState == IDLE) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("idle"));
                }
                else if (uiState == LOCAL_BUDDY) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("localbuddy"));
                    vRet[_XPLATSTR("blockNum")] = json::value::number(blockNum);
                }
                else if (uiState == GLOBAL_BUDDY) {
                    vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("globalbuddy"));
                    vRet[_XPLATSTR("chainNum")] = json::value::number(chainNum);
                }
            }
        }
        else if (path[0] == _XPLATSTR("GetDetailOfCurrentConsensus"))
        {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("initializing"));
            }
            else {
                size_t reqblknum, rspblknum, reqchainnum, rspchainnum, globalbuddychainnum;
                size_t localchainBlocks;

                consensuseng->GetDetailsOfCurrentConsensus(reqblknum, rspblknum,
                    reqchainnum, rspchainnum, localchainBlocks, nullptr, globalbuddychainnum);

                uint64 localHID = Singleton<DBmgr>::instance()->getLatestHyperBlockNo();
                uint32 requestBlocks = reqblknum + reqchainnum;
                uint32 respondBlocks = rspblknum + rspchainnum;

                vRet[_XPLATSTR("latestHyperBlockNo")] = json::value::number(localHID);
                vRet[_XPLATSTR("localchainBlocks")] = json::value::number(localchainBlocks);
                vRet[_XPLATSTR("requestBlocks")] = json::value::number(requestBlocks);
                vRet[_XPLATSTR("respondBlocks")] = json::value::number(respondBlocks);
            }
        }
        else if (path[0] == _XPLATSTR("GetLatestCacheBlockHeaderNo"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
            uint64 headerHID = HSpce->GetHeaderHashCacheLatestHID();
            bool bReady = HSpce->IsLatestHyperBlockReady();
            vRet[_XPLATSTR("laststCacheBlockNo")] = json::value::number(headerHID);
            vRet[_XPLATSTR("isReady")] = json::value::boolean(bReady);
        }
        else if (path[0] == _XPLATSTR("CreatCustomerizeConsensusScript"))
        {
            auto cntEntryType = query.find(_XPLATSTR("Type"));
            if (cntEntryType == query.end()) {
                BADPARAMETER(Type);
                return;
            }
            auto cntEntryScript = query.find(_XPLATSTR("Script"));
            if (cntEntryScript == query.end()) {
                BADPARAMETER(Script);
                return;
            }

            if (cntEntryType != query.end() && !cntEntryType->second.empty() && cntEntryScript != query.end() && !cntEntryScript->second.empty()) {
                utility::string_t sType = cntEntryType->second;
                utility::string_t sScript = cntEntryScript->second;

                string strType = tstringToUtf8(sType);
                if (0 != strType.compare("xml") || (sScript.length() > (1024 * 2))) {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("type is wrong"));
                }
                else {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("success"));
                }
            }
        }

        else if (path[0] == _XPLATSTR("GetNeighborNodes"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

            vector<string> vNeighborNodes;
            nodemgr->GetNodesJson(vNeighborNodes);
            json::value arr = json::value::array(vNeighborNodes.size());
            for (size_t i = 0; i < vNeighborNodes.size(); i++) {
                arr[i] = json::value::parse(s2t(vNeighborNodes[i]));
            }

            vRet[_XPLATSTR("NeighborNodes")] = arr;
            vRet[_XPLATSTR("NeighborNodesNum")] = json::value::number(vNeighborNodes.size());
        }
        else if (path[0] == _XPLATSTR("GetNeighborInfo"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

            vRet[_XPLATSTR("NeighborNodesNum")] = json::value::number(nodemgr->getNodeMapSize());
            vRet[_XPLATSTR("KBucketNodesNum")] = json::value::number(nodemgr->GetNodesNum());
        }
        else if (path[0] == _XPLATSTR("GetHyperBlocksIDList"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            vector<string> LocalChainSpace;
            HSpce->GetLocalHIDsection(LocalChainSpace);

            if (LocalChainSpace.empty()) {
                vRet[_XPLATSTR("HyperBlocksNum")] = json::value::number(0);
                vRet[_XPLATSTR("HyperBlocksIDList")] = json::value::string(_XPLATSTR(""));
            }
            else {
                size_t nums = HSpce->GetLocalChainIDSize();
                string Ldata;
                for (auto& t : LocalChainSpace) {
                    Ldata += t;
                    Ldata += ";";
                }

                vRet[_XPLATSTR("HyperBlocksNum")] = json::value::number(nums);
                vRet[_XPLATSTR("HyperBlocksIDList")] = json::value::string(s2t(Ldata));
            }
        }
        else if (path[0] == _XPLATSTR("GetHyperChainSpace"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<string, string> HyperChainSpace;
            HSpce->GetHyperChainShow(HyperChainSpace);

            if (HyperChainSpace.empty()) {
                vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(_XPLATSTR(""));
            }
            else {

                json::value obj;
                for (auto& mdata : HyperChainSpace) {
                    obj[s2t(mdata.first)] = json::value::string(s2t(mdata.second));
                }

                std::stringstream oss;
                obj.serialize(oss);

                vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(s2t(oss.str()));
            }
        }
        else if (path[0] == _XPLATSTR("GetHyperBlockHealthInfo"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<uint64, uint32> HyperBlockHealthInfo;
            HSpce->GetHyperBlockHealthInfo(HyperBlockHealthInfo);

            if (HyperBlockHealthInfo.empty()) {
                vRet[_XPLATSTR("HyperBlockHealthInfo")] = json::value::string(_XPLATSTR(""));
            }
            else {
                string Ldata;
                for (auto& mdata : HyperBlockHealthInfo) {
                    Ldata += to_string(mdata.first);
                    Ldata += ":";
                    Ldata += to_string(mdata.second);
                    Ldata += ";";
                }

                vRet[_XPLATSTR("HyperBlockHealthInfo")] = json::value::string(s2t(Ldata));
            }
        }
        else if (path[0] == _XPLATSTR("GetNodeIDList"))
        {
            auto cntEntryId = query.find(_XPLATSTR("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }

            utility::string_t sId = cntEntryId->second;
            uint64 nblocknum = std::stol(tstringToUtf8(sId));

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<uint64, set<string>> HyperChainSpace;
            HSpce->GetHyperChainData(HyperChainSpace);

            if (HyperChainSpace.empty()) {
                vRet[_XPLATSTR("HyperBlockID")] = json::value::number(nblocknum);
                vRet[_XPLATSTR("NodeIDList")] = json::value::string(_XPLATSTR(""));
            }
            else {
                string nodelist;
                for (auto& mdata : HyperChainSpace) {
                    if (mdata.first != nblocknum)
                        continue;

                    for (auto& sid : mdata.second) {
                        nodelist += sid;
                        nodelist += ";";
                    }
                    break;
                }

                vRet[_XPLATSTR("HyperBlockID")] = json::value::number(nblocknum);
                vRet[_XPLATSTR("NodeIDList")] = json::value::string(s2t(nodelist));
            }
        }
        else if (path[0] == _XPLATSTR("DownloadHyperBlock"))
        {
            auto cntEntryBlockId = query.find(_XPLATSTR("HyperBlockID"));
            if (cntEntryBlockId == query.end()) {
                BADPARAMETER(HyperBlockID);
                return;
            }

            auto cntEntryNodeId = query.find(_XPLATSTR("NodeID"));
            if (cntEntryNodeId == query.end()) {
                BADPARAMETER(NodeID);
                return;
            }

            utility::string_t sblockId = cntEntryBlockId->second;
            uint64 nblocknum = std::stol(tstringToUtf8(sblockId));
            string strnodeid = t2s(cntEntryNodeId->second);

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
            try {
                HSpce->GetRemoteHyperBlockByID(nblocknum, strnodeid);
            }
            catch (std::exception & e) {
                message.reply(status_codes::OK, json::value(stringToTstring(string("Bad Parameter:") + e.what())));
                return;
            }

            vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("request sent"));
        }

    REPLY:
        http_response response(status_codes::OK);
        response.set_body(vRet);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        message.reply(response);
        return;
    }
    message.reply(status_codes::OK, json::value(_XPLATSTR("unknow error")));
}


void HttpMsgReply(const http_request& message, const http::status_code &code, const json::value &vRet)
{
    http_response response(code);
    response.set_body(vRet);
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    message.reply(response).wait();
}


template<class... Args>
void RequestReplyFmt(const http_request& message, http::status_code code, const char * fmt, Args&&... args)
{
    json::value vRet;
    std::string buf = StringFormat(fmt, std::forward<Args>(args)...);

    vRet[_XPLATSTR("returnValue")] = json::value::string(s2t(string(buf.c_str())));
    HttpMsgReply(message, code, vRet);
}

inline
void BadRequestEmptyData(const http_request& message)
{
    RequestReplyFmt(message, status_codes::BadRequest, "%s", "try to submit empty data");
}

inline
void BadRequestDetails(const http_request& message, const std::string &errdesc)
{
    RequestReplyFmt(message, status_codes::BadRequest, "%s", errdesc);
}

inline
void BadRequestDetails(const http_request& message, const char *errdesc)
{
    RequestReplyFmt(message, status_codes::BadRequest, "%s", errdesc);
}


//for example:
//POST /cgi/XXX.pl HTTP/1.0
    //Accept: text/html
    //Connection: Keep-Alive
    //User-Agent: XXX/8.0.15
    //Content-type: multipart/form-data, boundary=XXXxyxy
    //Content-Length: 682
    //
    //----------------------------530432112422221965635283
    //content-disposition: form-data; name="payload"
    //
    //xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    //----------------------------530432112422221965635283
    //content-disposition: form-data; name="smartscript"
    //
    //yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
    //----------------------------530432112422221965635283--
    //
void SubmitRegistrationEx(http_request &message)
{
    json::value vRet;
    SubmitData data;
    try {
        Concurrency::streams::istream inStream = message.body();
        std::string line;
        std::string content;
        std::smatch match_boundary;

        http_headers& header = message.headers();
        if (!header.has(_XPLATSTR("Content-Type"))) {
            throw runtime_error("http request format error: no Content-Type in headers");
        }

        //multipart/form-data; boundary=------1653630963077
        std::string contenttype = t2s(header[_XPLATSTR("Content-Type")]);
        std::regex regex_find_boundary("multipart/form-data; boundary=(.*)");

        if (!std::regex_search(contenttype, match_boundary, regex_find_boundary)) {
            throw runtime_error("http request format error: multipart/form-data incorrect");
        }

        //std::regex regex_boundary("([-]{10,}[0-9]{10,}[^-])");
        std::regex regex_boundary(match_boundary[1].str());

        bool is_boundary_starting = false;

        while (!inStream.is_eof()) {
            concurrency::streams::container_buffer<std::string> inStringBuffer;
            inStream.read_line(inStringBuffer).then([&](std::size_t bytesRead) {
                line = std::move(inStringBuffer.collection());
                if (std::regex_search(line, match_boundary, regex_boundary)) {
                    is_boundary_starting = true;

                    //HCE: extract data
                    if (!content.empty()) {
                        std::string action;
                        std::smatch match_action;
                        std::regex regex_action("\\b(name)=\"(payload|script)\"(.*)");

                        if (std::regex_search(content, match_action, regex_action)) {
                            action = match_action[2];

                            if (match_action[3].length() > MAX_USER_DEFINED_DATA) {
                                RequestReplyFmt(message, status_codes::BadRequest,
                                         "%s size(%d) is larger than %dMB",
                                         action,
                                         match_action[3].length(), MAX_USER_DEFINED_DATA / 1024 / 1024);
                                return;
                            }

                            if (action == "payload") {
                                data.payload = match_action[3];
                            }
                            else if (action == "script") {
                                data.jssourcecode = match_action[3];

                                string excp_desc;
                                qjs::VM vm;
                                if (!vm.compileModule(data.jssourcecode, data.jsbytecode, excp_desc)) {
                                    throw runtime_error(StringFormat("script error when compiling: %s", excp_desc));
                                }
                            }
                        }
                    }
                    content = "";
                    return;
                }

                if (is_boundary_starting) {
                    content += line;
                }
            }).wait();
        }
    }
    catch (std::exception& e) {
        BadRequestDetails(message, e.what());
        std::cout << e.what();
        return ;
    }

    if (data.payload.empty() && data.jssourcecode.empty()) {
        BadRequestEmptyData(message);
        return;
    }

    RestApi api;
    http::status_code code;
    data.app = T_APPTYPE(APPTYPE::smartcontract);
    vRet = api.MakeRegistration(data, code);
    HttpMsgReply(message, code, vRet);
}

void RunJsScriptFromRequest(http_request& message, string &jssourcecode, string &jsbytecode, string &jscoderesult)
{
    Concurrency::streams::istream inStream = message.body();
    ostringstream oss;
    message.extract_string(true).then([&](const pplx::task<utility::string_t>& task) {
        jssourcecode = t2s(task.get());

        if (!jssourcecode.empty() && jssourcecode.length() <= MAX_USER_DEFINED_DATA) {
            RestApi api;
            //HCE: call script and put the result into payload
            string excp_desc;

            qjs::VM vm;

            if (!vm.compile(jssourcecode, jsbytecode, excp_desc)) {
                throw runtime_error(StringFormat("compile error: %s", excp_desc));
            }

            if (!vm.execute(jsbytecode, jscoderesult, excp_desc)) {
                throw runtime_error(StringFormat("execution error: %s", excp_desc));
            }

            if (jscoderesult.empty()) {
                throw runtime_error("result of script execution is empty");
            }
        }
        else if (jssourcecode.length() > MAX_USER_DEFINED_DATA) {
            throw runtime_error(StringFormat("script size(%d) is larger than %dMB",
                                jssourcecode.length(), MAX_USER_DEFINED_DATA / 1024 / 1024));
        }
        else {
            throw runtime_error("try to submit empty data");
        }
    }).wait();  //HCE: must call wait
}

void SubmitScriptExecutedResult(http_request& message)
{
    string jssourcecode;
    string jsbytecode;
    string jscoderesult;
    try {
        RunJsScriptFromRequest(message, jssourcecode, jsbytecode, jscoderesult);

        RestApi api;
        http::status_code code;

        SubmitData data;
        data.app = T_APPTYPE(APPTYPE::smartcontractwithresult);
        data.jssourcecode = jssourcecode;
        data.jsbytecode = jsbytecode;
        data.payload = jscoderesult;

        json::value vRet = api.MakeRegistration(data, code);
        HttpMsgReply(message, code, vRet);
    }
    catch (std::exception& e) {
        BadRequestDetails(message, e.what());
        std::cout << e.what();
    }
}

void EstimateScript(http_request& message)
{
    string jssourcecode;
    string jsbytecode;
    string jscoderesult;

    try {
        RunJsScriptFromRequest(message, jssourcecode, jsbytecode, jscoderesult);

        json::value vRet;
        vRet[_XPLATSTR("returnValue")] = json::value::string(s2t(jscoderesult));
        vRet[_XPLATSTR("bytecode")] = json::value::string(s2t_ign(jsbytecode));
        HttpMsgReply(message, status_codes::OK, vRet);
    }
    catch (std::exception& e) {
        BadRequestDetails(message, e.what());
        std::cout << e.what();
    }
}


void CommandHandler::handle_post(http_request message)
{
    g_basic_logger->debug("RestApi Method: {}, URI: {}, Query: {})", "POST",
                          tstringToUtf8(uri::decode(message.relative_uri().path())),
                          tstringToUtf8(uri::decode(message.relative_uri().query())));

    auto path = requestPath(message);
    if (!path.empty() && path.size() == 1) {

        if (path[0] == _XPLATSTR("SubmitRegistrationEx")) {
            //HCE: Data include payload and smart contract script
            SubmitRegistrationEx(message);
            return;
        }
        else if (path[0] == _XPLATSTR("SubmitScriptResult")) {
            //HCE: The script result executed puts into T_LOCALBLOCKBODY.payload
            //HCE: The script puts into T_LOCALBLOCKBODY.sScript
            SubmitScriptExecutedResult(message);
            return;
        }
        else if (path[0] == _XPLATSTR("EstimateScript")) {
            EstimateScript(message);
            return;
        }
        else if (path[0] == _XPLATSTR("SubmitRegistration")) {
            Concurrency::streams::istream inStream = message.body();
            concurrency::streams::container_buffer<std::string> inStringBuffer;

            inStream.read_line(inStringBuffer).then([=](std::size_t bytesRead) {
                string struserdefined = inStringBuffer.collection();
                json::value vRet;
                http::status_code code = status_codes::OK;

                if (!struserdefined.empty() && struserdefined.length() <= MAX_USER_DEFINED_DATA) {
                    RestApi api;
                    SubmitData data;
                    data.payload = struserdefined;
                    vRet = api.MakeRegistration(data, code);
                    HttpMsgReply(message, code, vRet);
                }
                else if (struserdefined.length() > MAX_USER_DEFINED_DATA) {
                    RequestReplyFmt(message, status_codes::BadRequest, "data size(%d) is larger than %dMB",
                                    struserdefined.length(),
                                    MAX_USER_DEFINED_DATA / 1024 / 1024);
                }
                else {
                    BadRequestEmptyData(message);
                }
            }).then([=](pplx::task<void>t) {
                try {
                    t.get();
                }
                catch (...) {
                    message.reply(status_codes::InternalError, _XPLATSTR("INTERNAL ERROR "));
                }
            });

            return;
        }
        else if (path[0] == _XPLATSTR("BatchRegistration")) {
            Concurrency::streams::istream inStream = message.body();
            concurrency::streams::container_buffer<std::string> inStringBuffer;

            inStream.read_line(inStringBuffer).then([=](std::size_t bytesRead) {
                string struserdefined = inStringBuffer.collection();
                json::value vRet;

                if (!struserdefined.empty() && struserdefined.length() <= BATCH_DATA_MAXIMUM) {
                    RestApi api;
                    vRet = api.MakeBatchRegistration(struserdefined);
                }
                else if (struserdefined.length() > BATCH_DATA_MAXIMUM) {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("BatchRegistration data length >= 1MB"));
                }
                else {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("BatchRegistration data length empty"));
                }

                HttpMsgReply(message, status_codes::OK, vRet);
            }).then([=](pplx::task<void>t) {
                try {
                    t.get();
                }
                catch (...) {
                    message.reply(status_codes::InternalError, _XPLATSTR("INTERNAL ERROR "));
                }
            });

            return;
        }
    }

    message.reply(status_codes::OK, json::value(_XPLATSTR("unknow error")));
}

void CommandHandler::handle_put(http_request message)
{
    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "PUT",
        tstringToUtf8(uri::decode(message.relative_uri().path())),
        tstringToUtf8(uri::decode(message.relative_uri().query())));
    message.reply(status_codes::OK, "PUT");
}

void CommandHandler::handle_del(http_request message)
{
    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "DEL", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));
    message.reply(status_codes::OK, "DEL");
}

void RestApi::blockHeadToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    val[_XPLATSTR("version")] = json::value::string(stringToTstring(localblock.GetVersion().tostring()));
    val[_XPLATSTR("id")] = json::value::number(localblock.GetID());

    val[_XPLATSTR("hid")] = json::value::number(localblock.GetHID());
    val[_XPLATSTR("chain_num")] = json::value::number(localblock.GetChainNum());

    val[_XPLATSTR("hash")] = json::value::string(stringToTstring(localblock.GetHashSelf().toHexString()));

    val[_XPLATSTR("hash_prev")] = json::value::string(stringToTstring(localblock.GetPreHash().toHexString()));
    val[_XPLATSTR("hhash")] = json::value::string(stringToTstring(localblock.GetPreHHash().toHexString()));
    val[_XPLATSTR("ctime")] = json::value::number(localblock.GetCTime());
    val[_XPLATSTR("nonce")] = json::value::number(localblock.GetNonce());

    json::value obj = json::value::array();
    uint16 i = 0;
    for (auto type : localblock.GetAppType()) {
        obj[i++] = json::value::number(type.app);
    }
    val[_XPLATSTR("app_type")] = obj;

    val[_XPLATSTR("root_block_body_hash")] = json::value::string(stringToTstring(localblock.GetRootHash().toHexString()));
    val[_XPLATSTR("script_hash")] = json::value::string(stringToTstring(localblock.GetScriptHash().toHexString()));

    //HCE: get localblock payload_size,block_size
    val[_XPLATSTR("payload_size")] = json::value::number(localblock.GetPayload().size());
    val[_XPLATSTR("block_size")] = json::value::number(localblock.GetSize());
}

void RestApi::blockBodyToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    val[_XPLATSTR("script")] = json::value::string(stringToTstring(localblock.GetScript()));
    val[_XPLATSTR("auth")] = json::value::string(stringToTstring(localblock.GetAuth()));
    val[_XPLATSTR("payload")] = json::value::string(stringToTstring(localblock.GetPayload()));
}

void RestApi::blockToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    blockHeadToJsonValue(localblock, val);
    blockBodyToJsonValue(localblock, val);
}

void RestApi::blockHeadToJsonValue(const T_HYPERBLOCK& hyperblock, size_t hyperBlockSize, json::value& val)
{
    val[_XPLATSTR("version")] = json::value::string(stringToTstring(hyperblock.GetVersion().tostring()));
    val[_XPLATSTR("weight")] = json::value::number(hyperblock.GetWeight());
    val[_XPLATSTR("hid")] = json::value::number(hyperblock.GetID());

    val[_XPLATSTR("hash")] = json::value::string(stringToTstring(hyperblock.GetHashSelf().toHexString()));

    val[_XPLATSTR("hash_prev")] = json::value::string(stringToTstring(hyperblock.GetPreHash().toHexString()));
    val[_XPLATSTR("hash_prev_header")] = json::value::string(stringToTstring(hyperblock.GetPreHeaderHash().toHexString()));
    val[_XPLATSTR("ctime")] = json::value::number(hyperblock.GetCTime());

    val[_XPLATSTR("merkle_hash_all")] = json::value::string(stringToTstring(hyperblock.GetMerkleHash().toHexString()));
    val[_XPLATSTR("br_root")] = json::value::string(stringToTstring(hyperblock.GetBRRoot().toHexString()));
    val[_XPLATSTR("xw_hash")] = json::value::string(stringToTstring(hyperblock.GetXWHash().toHexString()));
    val[_XPLATSTR("script_hash")] = json::value::string(stringToTstring(hyperblock.GetScriptHash().toHexString()));
    val[_XPLATSTR("br_rule")] = json::value::number(hyperblock.GetBRRule());

    json::value obj = json::value::array();
    for (uint16 i = 0; i < hyperblock.GetChildChainsCount(); i++) {
        obj[i] = json::value::number(hyperblock.GetChildChainBlockCount(i));
    }
    val[_XPLATSTR("childchain_blockscount")] = obj;     //HC: 每条子链拥有的子块数
                                                        //HCE: The number of localblocks owned by each childchain

    obj = json::value::array();
    const list<T_SHA256>& tailhashlist = hyperblock.GetChildTailHashList();
    uint16 i = 0;
    for (auto tailhash : tailhashlist) {
        obj[i++] = json::value::string(stringToTstring(tailhash.toHexString()));
    }
    val[_XPLATSTR("tailblockshash")] = obj;       //HC: 每条子链尾块的Hash
                                                  //HCE: The hash of each childchaintail block

    //val[_XPLATSTR("hyperBlockHashVersion")] = json::value::number(1);
    val[_XPLATSTR("hyperBlockSize")] = json::value::number(hyperBlockSize);
}

void RestApi::blockBodyToJsonValue(const T_HYPERBLOCK& hyperblock, json::value& val)
{
    int j = 0;
    json::value vObj = json::value::array();
    for (auto list : hyperblock.body.localBlocksHeaderHash)
    {
        int i = 0;
        json::value lObj = json::value::array();
        for (auto hash : list)
        {
            lObj[i++] = json::value::string(stringToTstring(hash.toHexString()));
        }

        vObj[j++] = lObj;
    }
    val[_XPLATSTR("local_blocks_header_hash")] = vObj;     //HCE: localblock header hash

    int k = 0;
    json::value obj = json::value::array();
    for (auto addr : hyperblock.GetBRAddr()) {
        obj[k++] = json::value::string(stringToTstring(addr.toHexString()));
    }
    val[_XPLATSTR("br_addrs")] = obj;

    val[_XPLATSTR("script")] = json::value::string(stringToTstring(hyperblock.GetScript()));
    val[_XPLATSTR("auth")] = json::value::string(stringToTstring(hyperblock.GetAuth()));
}

void RestApi::blockToJsonValue(const T_HYPERBLOCK& hyperblock, size_t hyperBlockSize, json::value& val)
{
    blockHeadToJsonValue(hyperblock, hyperBlockSize, val);
    blockBodyToJsonValue(hyperblock, val);
}

json::value RestApi::getLocalblock(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockToJsonValue(local, LocalBlock);

    return LocalBlock;
}

json::value RestApi::getLocalblockHead(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockHeadToJsonValue(local, LocalBlock);


    return LocalBlock;
}

json::value RestApi::getLocalblockBody(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockBodyToJsonValue(local, LocalBlock);

    return LocalBlock;
}

json::value RestApi::getHyperblocks(uint64_t nStartId, uint64_t nNum)
{
    json::value vHyperBlocks;
    std::list<T_HYPERBLOCK> queue;
    uint64_t nEndId = nStartId + nNum - 1;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(queue, nStartId, nEndId);
    if (nRet == 0) {
        for (auto& h : queue) {
            string_t sKey = stringToTstring(std::to_string(h.GetID()));
            size_t hyperBlockSize = sizeof(T_HYPERBLOCK);

            Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(h.GetID(), hyperBlockSize);
            blockToJsonValue(h, hyperBlockSize, vHyperBlocks[sKey][0]);

            int i = 1;
            std::list<T_LOCALBLOCK> listlocalblock;
            nRet = Singleton<DBmgr>::instance()->getLocalBlocks(listlocalblock, h.GetID());
            for (auto& l : listlocalblock) {
                blockToJsonValue(l, vHyperBlocks[sKey][i]);
                ++i;
            }
        }
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockInfo(uint64_t hid)
{
    size_t hyperBlockSize = sizeof(T_HYPERBLOCK);

    json::value vHyperBlocks;

    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(hid, hyperBlockSize);

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockToJsonValue(h, hyperBlockSize, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockHead(uint64_t hid)
{
    size_t hyperBlockSize = sizeof(T_HYPERBLOCK);
    json::value vHyperBlocks;
    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(hid, hyperBlockSize);

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockHeadToJsonValue(h, hyperBlockSize, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockBody(uint64_t hid)
{
    json::value vHyperBlocks;
    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockBodyToJsonValue(h, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getLocalchain(uint64_t hid, uint64_t chain_num)
{
    int blocks = 0;
    int chain_difficulty = 0;
    json::value LocalChain;
    int nRet = Singleton<DBmgr>::instance()->getLocalchain(hid, chain_num, blocks, chain_difficulty);
    if (nRet == 0) {
        LocalChain[_XPLATSTR("chain_num")] = json::value::number(chain_num);	//HCE: solo chain number
        LocalChain[_XPLATSTR("blocks")] = json::value::number(blocks);			//HCE: Number of localblocks
        LocalChain[_XPLATSTR("block_chain")] = json::value::string(_XPLATSTR("unknown")); //HCE: solo chain type
        LocalChain[_XPLATSTR("difficulty")] = json::value::number(chain_difficulty);	  //HCE: difficulty
        LocalChain[_XPLATSTR("consensus")] = json::value::string(_XPLATSTR("buddy"));	  //HCE: Consensus algorithm
    }

    return LocalChain;
}

struct HashFunc
{
    std::size_t operator()(const ONCHAINSTATUS& rhs) const {
        return std::hash<int>()(static_cast<int>(rhs));
    }
};

struct EqualKey
{
    bool operator () (const ONCHAINSTATUS& lhs, const ONCHAINSTATUS& rhs) const {
        return lhs == rhs;
    }
};

static unordered_map<ONCHAINSTATUS, string, HashFunc, EqualKey> mapstatus = {
    {ONCHAINSTATUS::queueing,"queueing"},
    {ONCHAINSTATUS::onchaining1,"onchaining1"},
    {ONCHAINSTATUS::onchaining2,"onchaining2"},
    {ONCHAINSTATUS::onchained,"onchained"},
    {ONCHAINSTATUS::matured,"matured"},
    {ONCHAINSTATUS::failed,"failed"},
    {ONCHAINSTATUS::nonexistent,"nonexistent"},
    {ONCHAINSTATUS::unknown,"unknown"},
    {ONCHAINSTATUS::pending,"pending"},
};

json::value RestApi::getOnchainState(const string& requestID)
{
    json::value vHyperBlocks;
    T_LOCALBLOCKADDRESS addr;
    size_t queuenum;
    ONCHAINSTATUS status = ONCHAINSTATUS::unknown;

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        status = consensuseng->GetOnChainState(requestID, queuenum);

        if (status == ONCHAINSTATUS::unknown) {
            //HCE: query memory
            if (consensuseng->CheckSearchOnChainedPool(requestID, addr)) {
                status = ONCHAINSTATUS::failed;
                if (addr.isValid()) {
                    status = ONCHAINSTATUS::onchained;
                }
            }
            else {
                //HCE: query database
                bool isfound = Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestID, addr);
                if (!isfound) {
                    status = ONCHAINSTATUS::nonexistent;
                }
                else {
                    status = ONCHAINSTATUS::matured;
                    if (!addr.isValid()) {
                        status = ONCHAINSTATUS::failed;
                    }
                }
            }
        }
    }

    vHyperBlocks[_XPLATSTR("onChainState")] = json::value::string(stringToTstring(mapstatus[status]));
    if (status == ONCHAINSTATUS::queueing) {
        vHyperBlocks[_XPLATSTR("queuenum")] = json::value::number(queuenum);
    }

    if (addr.isValid()) {
        vHyperBlocks[_XPLATSTR("hyperBlockId")] = json::value::number(addr.hid);
        vHyperBlocks[_XPLATSTR("chainNumber")] = json::value::number(addr.chainnum);
        vHyperBlocks[_XPLATSTR("localBlockId")] = json::value::number(addr.id);
    }
    return vHyperBlocks;
}

json::value RestApi::getOnchainInfo(const string& requestID)
{
    json::value vHyperBlocks;

    int64 onchaintime = 0;
    int64 maturetime = 0;

    DBmgr* pDb = Singleton<DBmgr>::instance();
    pDb->query("SELECT * FROM onchaindata WHERE requestid=?;", [&onchaintime, &maturetime](CppSQLite3Query& q) {
        onchaintime = q.getInt64Field("onchaintime");
        maturetime = q.getInt64Field("maturetime");
        }, requestID);

    vHyperBlocks[_XPLATSTR("onchained_time")] = json::value::number(onchaintime);
    vHyperBlocks[_XPLATSTR("matured_time")] = json::value::number(maturetime);

    return vHyperBlocks;
}


string RestApi::getOnchainState(const string& requestID, T_LOCALBLOCKADDRESS *pblockaddr)
{
    T_LOCALBLOCKADDRESS addr;
    size_t queuenum;
    ONCHAINSTATUS status = ONCHAINSTATUS::unknown;

    defer{
        if (pblockaddr) {
            *pblockaddr = addr;
        }
    };

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (!consensuseng)
        return "consensus engine doesn't run";

    status = consensuseng->GetOnChainState(requestID, queuenum);
    if (status != ONCHAINSTATUS::unknown) {
        if (status == ONCHAINSTATUS::queueing) {
            return StringFormat("%s, No. : %d", mapstatus[status], queuenum);
        }
        return mapstatus[status];
    }

    //HCE: query memory
    if (consensuseng->CheckSearchOnChainedPool(requestID, addr)) {
        status = ONCHAINSTATUS::failed;
        if (addr.isValid()) {
            status = ONCHAINSTATUS::onchained;
        }
        return mapstatus[status];
    }

    //HCE: query database
    bool isfound = Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestID, addr);
    if (!isfound) {
        status = ONCHAINSTATUS::nonexistent;
        return mapstatus[status];
    }

    status = ONCHAINSTATUS::matured;
    if (!addr.isValid()) {
        status = ONCHAINSTATUS::failed;
    }

    return mapstatus[status];
}

json::value RestApi::getBatchOnchainState(const string& batchID)
{
    string requestID;
    json::value vHyperBlocks;
    ONCHAINSTATUS status = ONCHAINSTATUS::unknown;

    //HCE: query memory
    CAutoMutexLock muxAuto(m_MuxBatchBufferList);
    for (auto it = m_BatchBufferList.begin(); it != m_BatchBufferList.end(); it++) {
        if (0 == batchID.compare((it->id).c_str())) {
            status = ONCHAINSTATUS::pending;
            break;
        }
    }

    if (status == ONCHAINSTATUS::unknown) {
        //HCE: query database
        bool isfound = Singleton<DBmgr>::instance()->getRequestID(batchID, requestID);
        if (!isfound) {
            status = ONCHAINSTATUS::nonexistent;
        }
    }

    if (status != ONCHAINSTATUS::unknown) {
        vHyperBlocks[_XPLATSTR("onChainState")] = json::value::string(stringToTstring(mapstatus[status]));
        return vHyperBlocks;
    }

    //HC: 根据requestID查询上链状态
    //HCE: Query the chain status based on the requestID
    return getOnchainState(requestID);
}

json::value RestApi::MakeBatchRegistration(string strdata)
{
    json::value valQueueID;

    CAutoMutexLock muxAuto(m_MuxBatchBufferList);
    if (input != nullptr && !(input->full) &&
        (input->len + strdata.length()) > MAX_USER_DEFINED_DATA) {
        input->full = true;
    }

    if (input == nullptr || input->full == true) {
        if (m_BatchBufferList.size() >= BATCH_BUFFER_MAXIMUM) {
            //HC: 缓冲区已满，无法接收上链请求
            //HCE: The buffer is full and cannot receive the on-chain request
            valQueueID[_XPLATSTR("batchid")] = json::value::string(stringToTstring(""));
            valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("failed"));

            return valQueueID;
        }

        T_BATCHBUFFER newbuf;
        m_BatchBufferList.emplace_back(std::move(newbuf));
        auto ir = m_BatchBufferList.rbegin();
        input = &(*ir);
    }

    input->data.append(strdata.c_str());
    input->len += strdata.length();

    m_BatchBufferList.size();
    valQueueID[_XPLATSTR("batchid")] = json::value::string(stringToTstring(input->id));
    valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("submitted"));

    return valQueueID;
}

void RestApi::SubmitBatchRegistration()
{
    CAutoMutexLock muxAuto(m_MuxBatchBufferList);
    if (m_BatchBufferList.empty())
        return;

    using seconds = std::chrono::duration<double, ratio<1>>;
    system_clock::time_point curr = system_clock::now();
    vector<string> vcdata;

    for (auto it = m_BatchBufferList.begin(); it != m_BatchBufferList.end();) {

        seconds timespan = std::chrono::duration_cast<seconds>(curr - it->ctime);
        if (!it->full && timespan.count() < 180) {
            //HC: 缓冲区未满且时间小于3分钟
            //HCE: The buffer is not full and the time is less than 3 minutes
            return;
        }

        if (&(*it) == input) {
            input = nullptr;
        }

        vcdata.clear();

        SubmitData smdata;
        smdata.payload = it->data;
        if (Upqueue(smdata, vcdata)) {
            Singleton<DBmgr>::instance()->updateBatchOnChainState(it->id, vcdata[0], it->data);
            m_BatchBufferList.erase(it++);
        }
        else {
            g_daily_logger->error("RestApi::SubmitBatchRegistration, Upqueue() failed");
            return;
        }
    }
}

void RestApi::SubmitBatchRegistrationThread()
{
    std::function<void(int)> sleepfn = [](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstop) {
                break;
            }
            this_thread::sleep_for(chrono::milliseconds(200));
        }
    };

    while (!_isstop) {
        sleepfn(60);
        SubmitBatchRegistration();
    }
}

void RestApi::RetrySubmit()
{
    vector<string> requestidvec;
    vector<string> succeedvec;
    vector<string> failedvec;

    int ret = Singleton<DBmgr>::instance()->getRequestIDs(requestidvec);
    if (ret != 0)
        return;

    if (requestidvec.empty())
        return;

    for (auto &requestid : requestidvec) {
        json::value vRet;
        vRet = getOnchainState(requestid);
        string status = t2s(vRet[_XPLATSTR("onChainState")].as_string());
        if (status.compare("matured") == 0) {
            succeedvec.push_back(requestid);
            continue;
        }

        if (status.compare("nonexistent") == 0 || status.compare("failed") == 0) {
            failedvec.push_back(requestid);
            continue;
        }

        if (status.compare("queueing") == 0) {
            break;
        }
    }

    if (succeedvec.size() > 0) {
        for (auto &succeedid : succeedvec) {
            Singleton<DBmgr>::instance()->updateSucceedRequestIDs(succeedid);
        }
    }

    if (failedvec.size() > 0) {
        int ret;
        vector<string> vcdata;

        for (auto &failedid : failedvec) {
            string data;
            ret = Singleton<DBmgr>::instance()->getBatchOnChainData(failedid, data);
            if (ret != 0 || data.empty()) {
                g_daily_logger->error("RestApi::RetrySubmit, getBatchOnChainData() failed, requestid: {}", failedid);
                continue;
            }

            vcdata.clear();
            SubmitData smdata;
            smdata.payload = data;
            if (Upqueue(smdata, vcdata)) {
                Singleton<DBmgr>::instance()->updateBatchOnChainState(failedid, vcdata[0]);
            }
            else {
                g_daily_logger->error("RestApi::RetrySubmit, Upqueue() failed");
                return;
            }

        }
    }

}

void RestApi::RetrySubmitThread()
{
    std::function<void(int)> sleepfn = [](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstop) {
                break;
            }
            this_thread::sleep_for(chrono::milliseconds(200));
        }
    };

    while (!_isstop) {
        sleepfn(30);
        RetrySubmit();
        sleepfn(570);
    }
}

json::value RestApi::MakeRegistration(const SubmitData& data, http::status_code& code)
{
    vector<string> vcdata;
    vcdata.clear();

    json::value valQueueID;
    if (Upqueue(data, vcdata)) {
        valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("queueing"));
        valQueueID[_XPLATSTR("requestid")] = json::value::string(stringToTstring(vcdata[0]));
        valQueueID[_XPLATSTR("queuenum")] = json::value::string(stringToTstring(vcdata[1]));
        code = status_codes::OK;
    }
    else {
        valQueueID[_XPLATSTR("requestid")] = json::value::string(stringToTstring(""));
        valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("failed"));
        valQueueID[_XPLATSTR("cause")] = json::value::string(stringToTstring(vcdata[0]));
        code = status_codes::BadRequest;
    }

    return valQueueID;
}

bool RestApi::Upqueue(const SubmitData& data, vector<string>& out_vc)
{
    string requestid;
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng == nullptr) {
        out_vc.push_back("ConsensusEngine is stopped");
        g_daily_logger->error("RestApi::Upqueue(), ConsensusEngine is stopped");
        g_console_logger->error("ConsensusEngine is stopped");
        return false;
    }
    uint32 nOrder;
    string excp_desc;

    if (consensuseng->AddNewBlockEx(data, requestid, nOrder, excp_desc)) {
        out_vc.push_back(requestid);
        out_vc.push_back(std::to_string(nOrder));
        return true;
    }
    out_vc.push_back(excp_desc);
    return false;
}

int RestApi::startRest(int nport)
{
    stringstream ss;

#ifdef WIN32
    ss << "http://*:" << nport;
#else
    ss << "http://0.0.0.0:" << nport;
#endif

    cout << "Start RestServer: " << ss.str() << endl;

    utility::string_t address = s2t(ss.str());

    web::uri_builder uri1(address);
    auto addr = uri1.to_uri().to_string();
    g_spRestHandler = std::make_shared<CommandHandler>(addr);

    try {
        g_spRestHandler->open().wait();
    }
    catch (std::exception & ex) {
        g_daily_logger->error("Start RestServer error");
        g_console_logger->error("Start RestServer error");
        cout << "RestServer exception:" << __FUNCTION__ << " " << ex.what() << endl;
    }

    _isstop = false;
    m_threads.emplace_back(&RestApi::SubmitBatchRegistrationThread);
    auto it = m_threads.rbegin();
    hc::SetThreadName(&(*it), "RestApi::SubmitBatchRegistration");

    m_threads.emplace_back(&RestApi::RetrySubmitThread);
    it = m_threads.rbegin();
    hc::SetThreadName(&(*it), "RestApi::RetrySubmit");


    return 0;
}

int RestApi::stopRest()
{
    try {
        g_spRestHandler->close().wait();
    }
    catch (std::exception & ex) {
        cout << "RestServer exception:" << __FUNCTION__ << " " << ex.what() << endl;
    }

    _isstop = true;
    for (auto& t : m_threads) {
        t.join();
    }
    m_threads.clear();

    return 0;
}
