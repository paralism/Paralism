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

#pragma once

#include "headers/inter_public.h"
#include "node/zmsg.h"

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
    int_type overflow(int_type c);
    int sync();

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

    enum class role : char
    {
        CLIENT,
        SERVER,
        DAEMON
    };
    role _r = role::SERVER;

    void run(role r);
    void run_as_client();


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

private:

    void loadSettings();
    void writeSettings();
    void insertRemoteServer(string& ip, int port);
    string GetConfigFile();

    void exit();
    void showUsages();
    void showNeighborNode();
    void showMQBroker();
    void showHyperChainSpace();
    void showHyperChainSpaceMore(const list<string> &commlist);
    void showLocalData();

    void showUdpDetails();
    void showHyperBlock(uint64 hid, bool isShowDetails);

    void downloadHyperBlock(const list<string> &commlist);
    void downloadBlockHeader(const list<string> &commlist);
    void searchLocalHyperBlock(const list<string> &commlist);
    void showInnerDataStruct();
    void resolveAppData(const list<string> &paralist);
    void debug(const list<string> &paralist);

    void setLoggerLevel(const list<string> &level);
    void setLoggerLevelHelp(std::shared_ptr<spdlog::logger> & logger, const list<string> &level);
    void setConsensusLoggerLevel(const list<string> &level);
    void startApplication(const list<string> &appli);
    void stopApplication(const list<string> &appli);
    void statusApplication(const list<string> &appli);

    void enableTest(const list<string> &onoff);

    void submitData(const list<string>& cmdlist);
    void queryOnchainState(const list<string>& cmdlist);

    void switchRemoteServer(const list<string>& cmdlist);

    string extractScriptDataFromFile(const string& filename);
    void showVMUsage();
    void handleVM(const list<string> &vmcmdlist);

    void appConsoleCmd(const string& appname, const list<string>& cmdlist, string& savingcommand);
    void handleToken(const list<string>& cmdlist, string& savingcommand);
    void handleCoin(const list<string>& cmdlist, string& savingcommand);


    void simulateHyperBlkUpdated(const list<string>& cmdlist);

};

class ProgramConfigFile
{
public:
    static string GetCfgFile(const string& cfgfile = "hc.cfg");
    static void LoadSettings(const string& cfgfile = "hc.cfg");
};


