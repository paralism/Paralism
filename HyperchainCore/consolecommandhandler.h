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

#pragma once

#include "headers/inter_public.h"
#include "node/zmsg.h"
#include "consensus/crosschaintx.h"

#include <streambuf>
#include <iostream>
#include <functional>
#include <vector>
#include <string>
#include <list>
#include <algorithm>
#include <iomanip>
using namespace std;

#include "newLog.h"


string GetHyperChainDataDir();
string CreateChildDir(const string& childdir);

class SocketClientStreamBuf : public std::streambuf
{
public:
    SocketClientStreamBuf(const string& strIP, int port);
    ~SocketClientStreamBuf();

    void get(string& strIP, int &port);
    void set(const string& strIP, int port);
protected:
    virtual int_type overflow(int_type c);
    virtual int sync();

private:
    void connect_to();
    int  FlushBuffer();

private:
    zmq::context_t* m_context;
    std::shared_ptr<zmq::socket_t> m_client;

    string m_ip;
    int m_port;

    string m_buffer;
    bool m_isstopped = false;
};

class ConsoleCommNetServer
{
public:
    ConsoleCommNetServer(zmq::context_t *ctx)
    {
        m_context = ctx;
    }

    ~ConsoleCommNetServer()
    {
        stop();
    }

    void start(int port);
    void stop();

protected:

    void request_process(std::string &sender, zmsg* msg);
    void msg_handler();

    zmq::context_t* m_context;
    std::shared_ptr<zmq::socket_t> m_socket;
    std::unique_ptr<std::thread> m_pollthread;
    bool m_isbinded = false;
    int m_port;
};

class ConsoleCommandHandler
{

public:
    explicit ConsoleCommandHandler(std::streambuf* in_smbuf, std::streambuf *out_smbuf);
    ~ConsoleCommandHandler();

    bool _bUpdate;

    enum class role : char
    {
        CLIENT,
        SERVER,
        DAEMON
    };
    role _r = role::SERVER;

    //HCE: Run console
    //HCE: @para r Run as role r
    void run(role r);

    //HCE: Run console as role::CLIENT
    void run_as_client();

    //HCE: if value of savingcommand is not null, save savingcommand into command history, else save command.
    void handleCommand(const string &command, string &savingcommand);
    void stop();

private:

    struct cmdstruct {
    public:
        cmdstruct(const char *keystring, std::function<void(const list<string> &, string&)> f) {
            key = keystring;
            func = f;
        }
        bool operator==(const cmdstruct &other) const {
            return (strcmp(key, other.key) == 0);
        }

        const char *key;
        std::function<void(const list<string> &, string& savingcommand)> func;
    };

    bool _isRunning;
    std::istream _istream;
    std::ostream _ostream;
    std::vector<cmdstruct> _commands;
    std::map<std::string, std::string> _mapSettings;

    std::map<int, crosschain::EthToParaExecutor> _mapEth2ParaTx;


private:

    //HCE: Load settings from HC config file
    void loadSettings();

    //HCE: Write settings to HC config file from _mapSettings
    void writeSettings();

    //HCE: Insert a remote server using ip and port
    //HCE: @para ip Server ip
    //HCE: @para port Server port
    void insertRemoteServer(string& ip, int port);
    string GetConfigFile();

    void exit();

    //HCE: Show HC common commands and their arguments
    void showUsages();

    //HCE: Show my neighbor nodes
    void showNeighborNode();

    //HCE: Show MQ Thread infomation
    void showMQBroker();

    //HCE: Show hyper chain space infomation
    void showHyperChainSpace();

    //HCE: Show more infomation according to input block
    void showHyperChainSpaceMore(const list<string> &commlist);

    //HCE: Show local data
    void showLocalData();

    //HCE: Show UDP details
    void showUdpDetails();

    //HCE: Show hyper chain details
    void showHyperChainSpaceInteral();

    //HCE: Show consensus infomation
    void showConsensusInfo();

    //HCE: Show some basic infomation of this node
    void showInnerBasicInfo();

    //HCE: Show hyper block infomation by hid
    //HCE: @para hid Hyper block id
    //HCE: @isShowDetails Show details or not
    void showHyperBlock(uint64 hid, bool isShowDetails);

    //HCE: Download hyper block according to input node id and block id
    void downloadHyperBlock(const list<string> &commlist);

    //HCE: Download block header according to input node id and block id
    void downloadBlockHeader(const list<string> &commlist);

    //HCE: Show specified local hyper block details
    void searchLocalHyperBlock(const list<string> &commlist);

    //HCE: Show inner infomation
    void showInnerDataStruct(const list<string>& paralist);

    //HCE: parse app data
    void parseAppData(const list<string> &paralist);

    void debug(const list<string> &paralist);

    void setLoggerLevel(const list<string> &level);
    void setLoggerLevelHelp(std::shared_ptr<spdlog::logger> & logger, const list<string> &level);
    void setConsensusLoggerLevel(const list<string> &level);

    //HCE: Start specified applications
    //HCE: @para appli Application list
    void startApplication(const list<string> &appli);

    //HCE: Stop specified applications
    //HCE: @para appli Application list
    void stopApplication(const list<string> &appli);

    //HCE: Show applications are running or not
     //HCE: @para appli Application list
    void statusApplication(const list<string> &appli);

    //HCE: Enable or disable consensus simulate test
    void enableTest(const list<string> &onoff);

    //HCE: Submit on chain data
    void submitData(const list<string>& cmdlist);

    //HCE: Query on chain state for specified requestid
    void queryOnchainState(const list<string>& cmdlist);

    void switchRemoteServer(const list<string>& cmdlist);

    //HCE: Extract script from file
    string extractScriptDataFromFile(const string& filename);

    //HCE: Show VM module commands
    void showVMUsage();

    //HCE: Handle VM module commands
    void handleVM(const list<string> &vmcmdlist);

    void getChainAddr(const list<string> &vmcmdlist);

    //HCE: create a cross chain transaction, from Para to ethereum
    void swap2Eth(const list<string> &vmcmdlist);
    void swap2Para(const list<string> &vmcmdlist);
    void swap(const list<string> &vmcmdlist);

    //HCE: Handle specified app module commands
    void appConsoleCmd(const string& appname, const list<string>& cmdlist, string& savingcommand);

    //HCE: Handle ledger module commands
    void handleToken(const list<string>& cmdlist, string& savingcommand);

    //HCE: Handle paracoin module commands
    void handleCoin(const list<string>& cmdlist, string& savingcommand);

    //HCE: Handle eth module commands
    void handleEth(const list<string>& cmdlist, string& savingcommand);

    //HCE: use to test paracoin and ledger
    void simulateHyperBlkUpdated(const list<string>& cmdlist);

    //HCE: Update HC program
    bool UpdateProgram();
};

class ProgramConfigFile
{
public:
    //HCE: Get HC config file name from args "-conf"
    //HCE: @para cfgfile HC config file name string
    //HCE: @returns HC config file name string
    static string GetCfgFile(const string& cfgfile = "hc.cfg");

    //HCE: Load config settings from HC config file
    //HCE: @para cfgfile HC config file name string
    //HCE: @returns void
    static void LoadSettings(const string& cfgfile = "hc.cfg");
};




