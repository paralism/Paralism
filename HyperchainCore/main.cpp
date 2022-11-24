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

#include "globalconfig.h"
#include "newLog.h"

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#include <direct.h>
#pragma comment(lib, "shell32.lib")
#else
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <signal.h>
#include <string.h>
#include <execinfo.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <netdb.h> /* struct hostent */
#include <arpa/inet.h> /* inet_ntop */
#include <ifaddrs.h> /* getifaddrs */
#endif

#include <iostream>
#include <sstream>

#include "wnd/common.h"

#include "db/RestApi.h"
#include "db/dbmgr.h"

#include "node/defer.h"
#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/UdpAccessPoint.hpp"
#include "node/UdpRecvDataHandler.hpp"
#include "node/NetworkFunctions.h"
#include "node/HCMQBroker.h"

#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/PullChainSpaceTask.hpp"

#include "AppPlugins.h"

#include "consolecommandhandler.h"
#include "consensus/consensus_engine.h"
#include "ntpclient.h"

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options/detail/config_file.hpp>

//#include <boost/asio.hpp>
//#include <boost/date_time/posix_time/posix_time.hpp>
#include <UpdateInfo.h>
#define Miningversion 100

using namespace std;
using namespace boost::program_options;

#ifdef WIN32
#include <client/windows/handler/exception_handler.h>
#else
#include <client/linux/handler/exception_handler.h>
#endif


string GetHyperChainDataDir()
{
    boost::filesystem::path pathDataDir;
    if (mapHCArgs.count("-datadir")) {
        pathDataDir = boost::filesystem::system_complete(mapHCArgs["-datadir"]);
        if (!boost::filesystem::exists(pathDataDir))
            if (!boost::filesystem::create_directories(pathDataDir)) {
                cerr << "can not create directory: " << pathDataDir << endl;
                pathDataDir = boost::filesystem::system_complete(".");
            }
    }
    else
        pathDataDir = boost::filesystem::system_complete(".");

    if (mapHCArgs.count("-model") && mapHCArgs["-model"] == "informal")
        pathDataDir /= "informal";
    else if (mapHCArgs.count("-model") && mapHCArgs["-model"] == "formal")
        pathDataDir /= "formal";
    else {
        pathDataDir /= "sandbox";
    }

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

static std::string make_log_path()
{
    return CreateChildDir("hyperchain_logs");
}

static std::string make_db_path()
{
    return CreateChildDir("hp");
}

extern NodeType g_nodetype;
string g_localip;

bool CheckLocalTime()
{
    bool Flag = false;
    string ntpservers[] = {"ntp.aliyun.com","time.asia.apple.com","cn.ntp.org.cn","time.google.com","time.windows.com","time.apple.com"};

    for (int i = 0; i < 5; i++) {
        struct hostent* host = gethostbyname(ntpservers[i].c_str());
        if (NULL == host) {
#ifdef WIN32
            cout << "CheckLocalTime(), gethostbyname[" << ntpservers[i].c_str() << "] failed! " << WSAGetLastError() << endl;
#else
            cout << "CheckLocalTime(), gethostbyname[" << ntpservers[i].c_str() << "] failed! " << strerror(h_errno) << endl;
#endif
            //return false;
            continue;
        }

        for (int i = 0; host->h_addr_list[i] != NULL; ++i) {
            char ipStr[32];
            const char* ret = inet_ntop(host->h_addrtype, host->h_addr_list[i], ipStr, sizeof(ipStr));
            if (NULL == ret) {
#ifdef WIN32
                cout << "CheckLocalTime(), inet_ntop failed! " << WSAGetLastError() << endl;
#else
                cout << "CheckLocalTime(), inet_ntop failed! " << strerror(errno) << endl;
#endif
                //return false;
                continue;
            }

            cout << "CheckLocalTime(), ntpserver:[" << ntpservers[i].c_str() << "], ip: [" << ipStr << "]" << endl;

            NtpClient ntp(ipStr);
            time_t tt = ntp.getTime();
            if (tt == 0) {
#ifndef WIN32
                sleep(1);
#else
                Sleep(1000);
#endif
                continue;
            }

            time_t now = time(nullptr);
            time_t delay = 0;

            if (now >= tt) {
                delay = now - tt;
            }
            else {
                delay = tt - now;
            }

            //HC: 时间误差为10秒(含)内
            if (delay <= 10)
                return true;

            //HC: 设置系统时间为网络时间
            cout << "System time has big difference with ntpserver and will stop only if set time to ntpserver time!" << endl;
            cout << "Do you want to set time to ntpserver time?(y/n, default:n)?";

            char c_action;
            cin >> std::noskipws >> c_action;

            if (c_action == 'y' || c_action == 'Y') {

                time_t tt = ntp.getTime();

#ifdef WIN32
                tm* temptm = localtime(&tt);
                SYSTEMTIME systime = { 1900 + temptm->tm_year,
                                        1 + temptm->tm_mon,
                                        temptm->tm_wday,
                                        temptm->tm_mday,
                                        temptm->tm_hour,
                                        temptm->tm_min,
                                        temptm->tm_sec,
                                        0 };

                if (SetLocalTime(&systime))
                    return true;

#else
                struct timeval tv;
                struct timezone tz;
                gettimeofday(&tv, &tz);

                tv.tv_sec = tt;
                tv.tv_usec = 0;

                if (settimeofday(&tv, &tz) == 0)
                    return true;
#endif
            
            }

            //HC: 没有设置或没有成功
            char ntpstamp[32] = { 0 };
            strftime(ntpstamp, 32, "%Y-%m-%d %H:%M:%S", std::localtime(&tt));

            char localstamp[32] = { 0 };
            strftime(localstamp, 32, "%Y-%m-%d %H:%M:%S", std::localtime(&now));

            //ntp.show(tt);
            std::cout << "System time error! " << '\t' << "Local Time: " << localstamp << ',  ' << "NTP Server Time: " << ntpstamp << std::endl;

            return false;
        }
    }

    std::cout << "Unable to connect to NTP server! Please check network!" << endl;
    return false;
}

bool GetLocalHostInfo()
{
    char name[256];
    int ret = gethostname(name, sizeof(name));
    if (ret != 0) {
#ifdef WIN32
        g_daily_logger->error("gethostname() failed! [{}]", WSAGetLastError());
#else
        g_daily_logger->error("gethostname() failed! [{}]", strerror(errno));
#endif
        return false;
    }

    struct hostent* host = gethostbyname(name);
    if (NULL == host) {
#ifdef WIN32
        g_daily_logger->error("gethostbyname() failed! [{}]", WSAGetLastError());
#else
        g_daily_logger->error("gethostbyname() failed! [{}]", strerror(h_errno));
#endif
        return false;
    }

    for (int i = 0; host->h_addr_list[i] != NULL; ++i) {
        char ipStr[32];
        const char* ret = inet_ntop(host->h_addrtype, host->h_addr_list[i], ipStr, sizeof(ipStr));
        if (NULL == ret) {
#ifdef WIN32
            g_daily_logger->error("inet_ntop() failed! [{}]", WSAGetLastError());
#else
            g_daily_logger->error("inet_ntop() failed! [{}]", strerror(errno));
#endif
            return false;
        }

        g_daily_logger->debug("GetLocalHostInfo(), ipStr: [{}]", ipStr);

        uint32 ip = StringIPtoUint32(ipStr);
        if (ip == 0) {
            g_daily_logger->error("StringIPtoUint32() failed! ipStr: [{}]", ipStr);
            return false;
        }

        if (IsLanIP(ip)) {
            g_localip = ipStr;
            return true;
        }
    }


#ifndef WIN32
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0) {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;

            char pszIP[100];
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                if (inet_ntop(ifa->ifa_addr->sa_family, (void*)&(s4->sin_addr), pszIP, sizeof(pszIP)) != NULL) {

                    g_daily_logger->debug("GetLocalHostInfo(), ipStr: [{}]", pszIP);

                    uint32 ip = StringIPtoUint32(pszIP);
                    if (ip == 0) {
                        g_daily_logger->error("StringIPtoUint32() failed! ipStr: [{}]", pszIP);
                        return false;
                    }

                    if (IsLanIP(ip)) {
                        g_localip = pszIP;
                        return true;
                    }
                }
            }
        }

        freeifaddrs(myaddrs);
    }
#endif

    return false;

}

void GenerateNodeslist()
{
    size_t found = g_localip.find_last_of('.');
    if (found == std::string::npos) {
        cout << "My Local IP error:" << g_localip << endl;
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::instance();

    int port = 8115;
    char str[4] = { 0 };
    string lip = g_localip.substr(0, found + 1);
    int myip = std::stoi(g_localip.substr(found + 1));

    for (int i = 1; i < 255; i++) {
        //HC: for example: 10.0.0.1-10.0.0.254
        if (i == myip)
            continue;

        string ip = lip;
        ip += to_string(i);
        sprintf(str, "%03d", i);

        string nid;
        nid.assign(29, '0');
        nid.append(str, 3);

        string nodeid(nid.c_str(), CUInt128::value * 2);
        HCNodeSH tmp = std::make_shared<HCNode>(std::move(CUInt128(nodeid)));
        //string str = HCNode::generateNodeId();
        //HCNodeSH tmp = std::make_shared<HCNode>(CUInt128(str));
        tmp->addAP(std::make_shared<UdpAccessPoint>(ip, port));

        nodemgr->addNode(tmp);
    }
}

void parseNetAddress(const string &netaddress, string &ip, int &port)
{
    size_t found = netaddress.find_first_of(':');
    if (found == std::string::npos) {
        ip = netaddress;
    }
    else {
        ip = netaddress.substr(0, found);
        port = std::stoi(netaddress.substr(found + 1));
    }

    uint32 ipu32 = StringIPtoUint32(ip);
    if (ipu32 == 0) {
        struct hostent* host = gethostbyname(ip.c_str());
        if (NULL == host) {
#ifdef WIN32
            cout << "parseNetAddress(), gethostbyname[" << ip.c_str() << "] failed! " << WSAGetLastError() << endl;
#else
            cout << "parseNetAddress(), gethostbyname[" << ip.c_str() << "] failed! " << strerror(h_errno) << endl;
#endif
            return;
        }

        for (int i = 0; host->h_addr_list[i] != NULL; ++i) {
            char ipStr[32];
            const char* ret = inet_ntop(host->h_addrtype, host->h_addr_list[i], ipStr, sizeof(ipStr));
            if (NULL == ret) {
#ifdef WIN32
                g_daily_logger->error("parseNetAddress(), inet_ntop() failed! [{}]", WSAGetLastError());
#else
                g_daily_logger->error("parseNetAddress(), inet_ntop() failed! [{}]", strerror(errno));
#endif
                continue;
            }

            cout << "parseNetAddress(), hostname:[" << ip.c_str() << "], ip: [" << ipStr << "]" << endl;

            ip = ipStr;
            return;
        }
    }
}

static char vNodeID[] = "0123456789abcdef";

void makeSeedServer(const vector<string> & seedservers)
{
    NodeManager *nodemgr = Singleton<NodeManager>::instance();
    int i = 0;
    for (auto &ss : seedservers) {
        if (i > 15) {
            //HC: at mostly 16 seed servers
            break;
        }
        string nodeid(CUInt128::value * 2, vNodeID[i++]);
        HCNodeSH seed = std::make_shared<HCNode>(std::move(CUInt128(nodeid)));

        string server;
        int port = 8116;
        parseNetAddress(ss, server, port);
        seed->addAP(std::make_shared<UdpAccessPoint>(server, port));
        nodemgr->seedServer(seed);
    }
}

void initNode(const map<string, string>& vm, string& udpip, int& udpport)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->loadMyself();

    string mynodeid;
    HCNodeSH me = nodemgr->myself();
    try {
        if (!me->isValid()) {
            cout << "The machine is a new node, generating nodeid..." << endl;
            string str = HCNode::generateNodeId();
            mynodeid = str;
            HCNodeSH tmp = std::make_shared<HCNode>(CUInt128(str));
            nodemgr->myself(tmp);
            me = nodemgr->myself();

            nodemgr->saveMyself();
        }
        else {
            mynodeid = me->getNodeId<string>();
        }
    }
    catch (std::exception &e) {
        cout << "Exception occurs in " << __FUNCTION__ << ": " << e.what() << endl;
        exit(-1);
    }

    if (vm.count("-me")) {
        string strMe = vm.at(string("-me"));
        cout << "My IP and port is " << strMe << endl;

        parseNetAddress(strMe, udpip, udpport);

        me->removeAPs();
        me->addAP(std::make_shared<UdpAccessPoint>(udpip, udpport));
    }
    else if (g_nodetype == NodeType::Autonomous) {
        cout << "My IP and port is " << g_localip << ":" << udpport << endl;

        me->removeAPs();
        me->addAP(std::make_shared<UdpAccessPoint>(g_localip, udpport));
    }

    nodemgr->myself(me);
    nodemgr->saveMyself();
}

class hclogger
{
public:
    hclogger()
    {
        std::string logpath = make_log_path();
        std::string dlog = logpath + "/hyperchain.log";
        std::string flog = logpath + "/hyperchain_basic.log";
        std::string rlog = logpath + "/hyperchain_rotating.log";
        spdlog::set_level(spdlog::level::err); //HC: Set specific logger's log level
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        g_daily_logger = spdlog::daily_logger_mt("daily_logger", dlog.c_str(), 0, 30);
        g_daily_logger->set_level(spdlog::level::info);
        g_basic_logger = spdlog::basic_logger_mt("file_logger", flog.c_str());
        //HC: Create a file rotating logger with 100M size max and 3 rotated files.
        g_rotating_logger = spdlog::rotating_logger_mt("rotating_logger", rlog.c_str(), 1048576 * 100, 3);
        g_console_logger = spdlog::stdout_color_mt("console");
        g_console_logger->set_level(spdlog::level::err);
        g_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        g_consensus_console_logger = spdlog::stdout_color_mt("consensus");
        g_consensus_console_logger->set_level(spdlog::level::err);
        g_consensus_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        spdlog::flush_every(std::chrono::seconds(3));

    }

    ~hclogger()
    {
        spdlog::shutdown();
    }
};


//NodeType g_nodetype = NodeType::Bootstrap;
extern int g_argc;
extern char **g_argv;
bool g_isChild = false;

void stopAll()
{
    if (g_appPlugin) {
        cout << "Stopping Applications..." << endl;
        g_appPlugin->StopAllApp();
    }

    g_sys_interrupted = 1; //HC: stop MQ
    auto datahandler = Singleton<UdpRecvDataHandler>::getInstance();
    if (datahandler) {
        cout << "Stopping UdpRecvDataHandler..." << endl;
        datahandler->stop();
    }

    ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        cout << "Stopping Consensuseng..." << endl;
        consensuseng->stop();
    }
    CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    if (hyperchainspace) {
        cout << "Stopping Hyperchain Space..." << endl;
        hyperchainspace->stop();
    }

    NodeUPKeepThreadPool* nodeUpkeepThreadpool = Singleton<NodeUPKeepThreadPool>::getInstance();
    if (nodeUpkeepThreadpool) {
        cout << "Stopping NodeUPKeepThreadPool..." << endl;
        nodeUpkeepThreadpool->stop();
    }

    NodeManager* nmg = Singleton<NodeManager>::getInstance();
    if (nmg) {
        cout << "Stopping NodeManager..." << endl;
        nmg->stop();
    }

    UdtThreadPool *udpthreadpool = Singleton<UdtThreadPool, const char*, uint32_t>::getInstance();
    if (udpthreadpool) {
        cout << "Stopping UDT..." << endl;
        udpthreadpool->stop();
    }

    if (g_nodetype != NodeType::LedgerRPCClient) {
        cout << "Stopping Rest Server..." << endl;
        RestApi::stopRest();
    }

    HCMQBroker *brk = Singleton<HCMQBroker>::getInstance();
    if (brk) {
        cout << "Stopping HCBroker..." << endl;
        brk->stop();
    }

    if (Singleton<DBmgr>::instance()->isOpen()) {
        cout << "Closing Database" << endl;
        Singleton<DBmgr>::instance()->close();
    }
}

#ifdef WIN32
bool dumpCallback(const wchar_t* dump_path,
    const wchar_t* minidump_id,
    void* context,
    EXCEPTION_POINTERS* exinfo,
    MDRawAssertionInfo* assertion,
    bool succeeded)
{
    cout << "Exception occurs:" << (char*)context << endl;
    stopAll();
    cout << "Rebooting..." << endl;

    std::system((char*)context);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    return succeeded;
}
#else

bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
    int ret;

    cout << "Exception occurs:" << g_argv[0] << endl;
    stopAll();
    cout << "Rebooting..." << endl;

    //HC: add child options
    std::shared_ptr<char*> hc_argv(new char*[g_argc + 2]);

    int i = 0;
    char ** p = hc_argv.get();
    for (; i < g_argc; i++) {
        p[i] = g_argv[i];
    }
    char option[16] = { "--child" };
    p[g_argc] = option;
    p[g_argc + 1] = nullptr;

    while (!g_isChild) {
        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, "fork() error.errno:%d error:%s\n", errno, strerror(errno));
            break;
        }
        if (pid == 0) {
            ret = execv(hc_argv.get()[0], hc_argv.get());
            if (ret < 0) {
                fprintf(stderr, "execv ret:%d errno:%d error:%s\n", ret, errno, strerror(errno));
                continue;
            }
            break;
        }

        if (pid > 0) {
            fprintf(stdout, "Parent process enter waiting status\n");

            int status;
            pid_t childpid = wait(&status);
            fprintf(stdout, "Created a child process %d\n", childpid);
            if (WIFEXITED(status)) {			//Child exit normally
                fprintf(stdout, "Child process exited with code %d\n", WEXITSTATUS(status));
                break;
            }
            else if (WIFSIGNALED(status)) {		//Child was terminated by a siganl
                fprintf(stdout, "Child process terminated by signal %d\n", WTERMSIG(status));
            }
            else if (WIFSTOPPED(status)) {		//Child was stopped by a delivery siganl
                fprintf(stdout, "%d signal case child stopped\n", WSTOPSIG(status));
            }
            else if (WIFCONTINUED(status)) {	//Child was resumed by delivery SIGCONT
                fprintf(stdout, "Child was resumed by SIGCONT\n");
            }
            cout << "Rebooted" << endl;
        }
    }
    return succeeded;
}

#endif

void signalHandler(int sig)
{
    ConsoleCommandHandler* console =
        Singleton<ConsoleCommandHandler, std::streambuf*, std::streambuf*>::getInstance();
    if (console) {
        console->stop();
    }
}

string getMyCommandLine(int argc, char *argv[])
{
    string commandline;
    for (int i = 0; i < argc; ++i) {
        commandline += argv[i];
        commandline += " ";
    }
    return commandline;
}

void ParseParameters(int argc, char* argv[])
{
    mapHCArgs.clear();
    mapHCMultiArgs.clear();
    for (int i = 1; i < argc; i++) {
        char psz[10000] = { 0 };
        strlcpy(psz, argv[i], sizeof(psz));
        char* pszValue = (char*)"";
        if (strchr(psz, '=')) {
            pszValue = strchr(psz, '=');
            *pszValue++ = '\0';
        }

        if (psz[0] != '-')
            break;
        mapHCArgs[psz] = pszValue;
        mapHCMultiArgs[psz].push_back(pszValue);
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-')
            continue;
        vHCCommands.push_back(argv[i]);
    }
}

class CloneArgs
{
public:
    CloneArgs(int argc, char* argv[]) {
        nArgc = 1 + vHCCommands.size();
        for (auto& elm : mapHCMultiArgs) {
            nArgc += elm.second.size();
        }

        ppArgv = new char* [nArgc];

        int len = strlen(argv[0]) + 1;
        ppArgv[0] = new char[len];
        strlcpy(ppArgv[0], argv[0], len);

        int i = 1;
        for (auto& key : mapHCArgs) {
            for (string& value : mapHCMultiArgs[key.first]) {
                string kv;
                if (value.empty()) {
                    kv = key.first;
                }
                else {
                    kv = StringFormat("%s=%s", key.first, value);
                }
                int len = kv.size() + 1;
                ppArgv[i] = new char[len];
                strlcpy(ppArgv[i++], kv.c_str(), len);
            }
        }
        for (auto& cmmd : vHCCommands) {
            int len = cmmd.size() + 1;
            ppArgv[i] = new char[len];
            strlcpy(ppArgv[i++], cmmd.c_str(), len);
        }
    }

    ~CloneArgs() {
        if (ppArgv) {
            int i = 0;
            for (; i < nArgc; i++) {
                delete[] ppArgv[i];
            }
            delete[] ppArgv;
        }
    }

    int nArgc = 0;
    char** ppArgv = nullptr;
};

inline const char* _(const char* psz)
{
    return psz;
}

static bool foreground = true;
static google_breakpad::ExceptionHandler* exceptionhandler = nullptr;

//every 13 hours to check if there is update;
void checkupdate()
{
    while (true) {
        //Check if needs to update
        UpdateInfo updateinfo;
        string localmd5;

        if (updateinfo.GetUpdateInfo()) {

            int fminingversion = Miningversion;
            if (fminingversion < updateinfo.fminingversion) {
                auto f = (*g_appPlugin)["paracoin"];
                if (f) {
                    std::list<string> cmdlist;
                    cmdlist.emplace_back("c");
                    cmdlist.emplace_back("d");
                    cmdlist.emplace_back("versionlow");
                    string info;
                    f->appConsoleCmd(cmdlist, info, info);
                }

                cout << "Paracoin version is too low,coin mining is stopped!" << endl;
            }

            if (updateinfo.CheckUpdate())
                cout << "Program has new version! Type 'update' to update the program!" << endl;

        }

        std::this_thread::sleep_for(std::chrono::hours(13));
    }
}

int main(int argc, char *argv[])
{
    SoftwareInfo();

    if (!CheckLocalTime())
        return 0;

    //boost::filesystem::path pathHC(argv[0]);
    //pathHC = pathHC.branch_path() / ".";
    //pathHC = boost::filesystem::system_complete(pathHC);
    //boost::filesystem::current_path(pathHC);

    ParseParameters(argc, argv);
    ProgramConfigFile::LoadSettings();

    string strUsage = string() +
        _("Usage:") + "\t\t\t\t\t\t\t\t\t\t\n" +
        "  hc [options]                   \t  " + "\n" +
        "  hc [options] <command> [params]\t  " + _("Execute a JSON-RPC command, only when run as JSON-RPC Client\n") +
        "  hc [options] help              \t\t  " + _("List JSON-RPC commands, only when run as JSON-RPC Client\n") +
        "  hc [options] help <command>    \t\t  " + _("Get help for a JSON-RPC command, only when run as JSON-RPC Client\n") +
        _("Options:\n") +
        "  -? or --help     \t\t  " + _("Print help message\n") +
        "  -v               \t\t  " + _("Print version message\n") +
        "  -daemon          \t\t  " + _("Run as a background node, only for *nux\n") +
        "  -child           \t\t  " + _("Run as a child process, only inner use for *nux\n") +
        "  -me=<ip:port>    \t\t  " + _("Listen for connections from other nodes,for example:10.0.0.1:8116\n") +
        "  -seedserver=<ip:port> \t\t  " + _("Specify a seed server,for example:127.0.0.1:8116\n") +
        "  -restport=<port> \t\t  " + _("Listen for RESTful connections on <port> (default: 8080)\n") +
        "  -model=<type>   \t\t   " + _("which network node will be connected to, type can be sandbox, informal or formal (default: sandbox)\n") +
        "  -datadir=<dir>   \t\t  " + _("Specify data directory\n") +
        "  -conf[=file]     \t\t  " + _("Specify configuration file (default: <datadir>/<model>/hc.cfg)\n") +
        //HC: Paracoin and Ledger parameter
        "  -with=<app>      \t\t  " + _("Start with application, for example:-with=ledger, -with=paracoin\n") +
        //"  -pid=<file>      \t\t  " + _("Specify pid file (default: bitcoind.pid)\n") +
        //"  -gen             \t\t  " + _("Generate coins\n") +
        //"  -gen=0           \t\t  " + _("Don't generate coins\n") +
        //"  -min             \t\t  " + _("Start minimized\n") +
        //"  -timeout=<n>     \t  " + _("Specify connection timeout (in milliseconds)\n") +
        //"  -proxy=<ip:port> \t  " + _("Connect through socks4 proxy\n") +
        //"  -dns             \t  " + _("Allow DNS lookups for addnode and connect\n") +
        //"  -addnode=<ip>    \t  " + _("Add a node to connect to\n") +

        "  -connect=<ip:port> \t  " + _("Connect only to the specified node\n") +
        //"  -nolisten        \t  " + _("Don't accept connections from outside\n") +
#ifdef USE_UPNP
#if USE_UPNP
        "  -noupnp          \t  " + _("Don't attempt to use UPnP to map the listening port\n") +
#else
        "  -upnp            \t  " + _("Attempt to use UPnP to map the listening port\n") +
#endif
#endif
        //"  -paytxfee=<amt>  \t  " + _("Fee per KB to add to transactions you send\n") +
        "  -server=<port>   \t\t  " + _("Listen and accept command line from outside on <port>\n") +
#ifndef __WXMSW__
        //"  -daemon          \t\t  " + _("Run in the background as a daemon and accept commands\n") +
#endif
        //"  -testnet         \t\t  " + _("Use the test network\n") +
        "  -rpcclient       \t\t  " + _("Run as a Ledger/Paracoin JSON-RPC Client\n") +
        "  -rpcuser=<user>  \t  " + _("Username for JSON-RPC connections\n") +
        "  -rpcpassword=<pw>\t  " + _("Password for JSON-RPC connections\n") +
        "  -rpcallowip=<ip> \t\t  " + _("Allow JSON-RPC connections from specified IP address\n") +
        //"  -rpcconnect=<ip> \t  " + _("Send commands to node running on <ip> (default: 127.0.0.1)\n");
        "  -rpcparaport=<port>  \t\t  " + _("Listen for Paracoin JSON-RPC connections on <port> (default: 8118)\n") +
        "  -rpcledgerport=<port>  \t\t  " + _("Listen for Ledger JSON-RPC connections on <port> (default: 8119)\n");
    //"  -keypool=<n>     \t  " + _("Set key pool size to <n> (default: 100)\n") +
    //"  -rescan          \t  " + _("Rescan the block chain for missing wallet transactions\n");


#ifdef USE_SSL
    strUsage += string() +
        _("\nSSL options: (see the Hyperchain Wiki for SSL setup instructions)\n") +
        "  -rpcssl                                \t  " + _("Use OpenSSL (https) for JSON-RPC connections\n") +
        "  -rpcsslcertificatechainfile=<file.cert>\t  " + _("Server certificate file (default: server.cert)\n") +
        "  -rpcsslprivatekeyfile=<file.pem>       \t  " + _("Server private key (default: server.pem)\n") +
        "  -rpcsslciphers=<ciphers>               \t  " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)\n");
#endif

    // Remove tabs
    strUsage.erase(std::remove(strUsage.begin(), strUsage.end(), '\t'), strUsage.end());

    if (mapHCArgs.size() == 0 || mapHCArgs.count("-?") || mapHCArgs.count("--help")) {
        cout << strUsage << endl;
        return 0;
    }

    if (mapHCArgs.count("-v")) {
        cout << VERSION_STRING << endl;
        return 0;
    }

    if (mapHCArgs.count("-daemon")) {
        foreground = false;
    }

    if (mapHCArgs.count("-child")) {
        g_isChild = true;
    }

    bool isExceptionAutoReboot = false;
    if (mapHCArgs.count("-autoreboot")) {
        isExceptionAutoReboot = true;
    }

    g_argc = argc;
    g_argv = argv;

#ifdef WIN32
    string commandline = getMyCommandLine(argc, argv);
    if (isExceptionAutoReboot) {
        exceptionhandler = new google_breakpad::ExceptionHandler(L"./",
            nullptr,
            dumpCallback,
            (char*)commandline.c_str(),
            google_breakpad::ExceptionHandler::HANDLER_ALL);
    }
#else

    //HC: fork myself, become a daemon
    umask(0);
    while (!foreground) {
        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, "fork() error.errno:%d error:%s\n", errno, strerror(errno));
            exit(-1);
        }
        if (pid > 0) {
            exit(0);
        }

        if (-1 == setsid()) {
            fprintf(stderr, "child process setsid error\n");
            exit(1);
        }

        pid = fork();
        if (pid == -1) {
            fprintf(stderr, "fork error\n");
            exit(1);
        }
        else if (pid) {
            exit(0);
        }

        //HC: redirect stdin stdout to null
        int fd = open("/dev/null", O_RDWR);
        dup2(fd, 0);
        dup2(fd, 1);
        if (fd > 2) {
            close(fd);
        }
        signal(SIGCHLD, SIG_IGN);
        signal(SIGQUIT, signalHandler);
        break;
    }

    if (isExceptionAutoReboot) {
        google_breakpad::MinidumpDescriptor descriptor("./");
        exceptionhandler = new google_breakpad::ExceptionHandler(descriptor,
            nullptr, dumpCallback, nullptr, true, -1);
    }

#endif

    if (mapHCArgs.count("-connect")) {
        //HC: run as client and connect to server
        string strServer = mapHCArgs.at(string("-connect"));

        int port = 8115;
        string serverIP;
        parseNetAddress(strServer, serverIP, port);

        SocketClientStreamBuf sockbuf(serverIP, port);
        ConsoleCommandHandler console(cin.rdbuf(), &sockbuf);
        console.run_as_client();

        return 0;
    }

    hclogger log;

    HCMQBroker *brk = Singleton<HCMQBroker>::instance();
    g_inproc_context = brk->context();
    brk->start();
    cout << "HCBroker::Start..." << endl;

    bool bGetIp = GetLocalHostInfo();
    if (mapHCArgs.count("-rpcclient")) {
        g_nodetype = NodeType::LedgerRPCClient;
    }
    else if (mapHCArgs.count("-seedserver")) {
        string seedserver = "127.0.0.1:8116";
        auto &seedservers = mapHCMultiArgs["-seedserver"];
        cout << "Run as a normal node, bootstrap servers are: " << endl;
        for (auto &ss : seedservers) {
            cout << "\t" << ss << endl;
        }
        g_nodetype = NodeType::Normal;
        makeSeedServer(seedservers);
    }
    else if (!mapHCArgs.count("-me")) {
        if (bGetIp)
            g_nodetype = NodeType::Autonomous;
    }
    else {
        g_nodetype = NodeType::Bootstrap;
        cout << "Run as a normal node with bootstrap" << endl;
    }

    std::string dbpath = make_db_path();
    dbpath += "/hyperchain.db";
    Singleton<DBmgr>::instance()->open(dbpath.c_str());

    pro_ver = ProtocolVer::NET::SAND_BOX;
    if (mapHCArgs.count("-model") && mapHCArgs["-model"] == "informal")
        pro_ver = ProtocolVer::NET::INFORMAL_NET;

    NodeManager *nodemgr = Singleton<NodeManager>::instance();
    nodemgr->SetLocalIP(g_localip);

    nodemgr->start();

    string udpip;
    int udpport = 8115;
    initNode(mapHCArgs, udpip, udpport);
    nodemgr->loadNeighbourNodes_New();

    if (g_nodetype == NodeType::Autonomous && nodemgr->getNodeMapSize() == 0) {
        GenerateNodeslist();
    }

    HCNodeSH me = nodemgr->myself();
    string mynodeid = me->getNodeId<string>();
    nodemgr->InitKBuckets();

    CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::instance(mynodeid);

    Singleton<UdpRecvDataHandler>::instance();

    UdtThreadPool *udpthreadpool = Singleton<UdtThreadPool, const char*, uint32_t>::instance("", udpport);

    NodeUPKeepThreadPool* nodeUpkeepThreadpool = Singleton<NodeUPKeepThreadPool>::instance();

    CloneArgs cargs(argc, argv);
    g_appPlugin = Singleton<AppPlugins, int, char**>::instance(cargs.nArgc, cargs.ppArgv);

    if (g_nodetype != NodeType::LedgerRPCClient) {

        nodeUpkeepThreadpool->start();
        cout << "NodeUPKeepThreadPool::Start... " << endl;

        hyperchainspace->start(Singleton<DBmgr>::instance());
        cout << "HyperChainSpace::Start... " << endl;

        udpthreadpool->start();

        int nPort = 8080;
        if (mapHCArgs.count("-restport")) {
            nPort = std::stoi(mapHCArgs["-restport"]);
        }

        RestApi::startRest(nPort);

        ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::instance();
        consensuseng->start();

        if (mapHCArgs.count("-teston")) {
            consensuseng->startTest();
        }

        g_appPlugin->StartAllApp();

        cout << "Consensus MQID:   " << Singleton<ConsensusEngine>::getInstance()->MQID() << endl;
        cout << "ChainSpace MQID:  " << Singleton<CHyperChainSpace, string>::getInstance()->MQID() << endl;
        cout << "NodeManager MQID: " << Singleton<NodeManager>::getInstance()->MQID() << endl << endl;
    }
    else {
        //HC: application RPC query client
        g_appPlugin->StartAllApp();
    }

    ConsoleCommNetServer netserver(g_inproc_context); //HC: Here is tcp port
    if (mapHCArgs.count("-server")) {
        int port = std::stoi(mapHCArgs["-server"]);
        netserver.start(port);
    }

    std::thread thrCheck(checkupdate);
    thrCheck.detach();

    ConsoleCommandHandler *console =
        Singleton<ConsoleCommandHandler, std::streambuf* , std::streambuf*>::instance(cin.rdbuf(), cout.rdbuf());

    ConsoleCommandHandler::role r = ConsoleCommandHandler::role::SERVER;
    if (mapHCArgs.count("-daemon")) {
        r = ConsoleCommandHandler::role::DAEMON;
    }
    console->run(r);

    stopAll();

    if (console->_bUpdate)
        execlp("./Autoupdate", "Autoupdate", (char*)0);

    return 0;
}
