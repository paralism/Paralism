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

#include <map>
#include <set>
#include "consolecommandhandler.h"

#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "db/dbmgr.h"
#include "db/HyperchainDB.h"
#include "AppPlugins.h"
#include "colorprompt.hpp"

#include "node/Singleton.h"
#include "node/UdpAccessPoint.hpp"
#include "node/UdpRecvDataHandler.hpp"
#include "HyperChain/HyperChainSpace.h"
#include "node/NodeManager.h"
#include "consensus/buddyinfo.h"
#include "consensus/consensus_engine.h"
#include "db/RestApi.h"
#include "util/hex.hpp"

#include "vm/vm.h"


#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <UpdateInfo.h>

#ifdef LINUX
#include <unistd.h>
#endif // LINUX


int g_argc = 0;
char **g_argv;




extern void stopAll();


using namespace std;
namespace fs = boost::filesystem;
namespace pod = boost::program_options::detail;

std::string g_strSysStartTm = time2string(time(nullptr));


//HCE: Get the directoty of the hyper chain data
//HCE: @returns The directoty string 
string GetHyperChainDataDir()
{
    HC_MAIN_PROGRAM_ARGS;

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

//HCE: Get file name from full path
//HCE: @para fullpath Full path string
//HCE: @returns File name string
string FileNameFromFullPath(const string &fullpath)
{
    size_t s = fullpath.find_last_of("/\\");
    if (s != std::string::npos) {
        return fullpath.substr(s + 1);
    }
    return fullpath;
}

//HCE: Trim whitespaces(" \t\f\v\n\r") in a string
//HCE: @para str String to trim
//HCE: @returns void
void trim(string &str)
{
    std::string whitespaces(" \t\f\v\n\r");

    std::size_t found = str.find_last_not_of(whitespaces);
    if (found != std::string::npos) {
        str.erase(found + 1);
    }
    else {
        str.clear();
        return;
    }

    found = str.find_first_not_of(whitespaces);
    if (found != std::string::npos)
        str.erase(0, found);
}

string ProgramConfigFile::GetCfgFile(const string& cfgfile)
{
    HC_MAIN_PROGRAM_ARGS;
    if (!mapHCArgs.count("-conf")) {
        return "";
    }

    string strconfigfile = mapHCArgs.at("-conf");
    if (strconfigfile.empty()) {
        fs::path pathConfig;
        pathConfig = fs::path(GetHyperChainDataDir()) / cfgfile;

        strconfigfile = pathConfig.string();
    }
    return strconfigfile;
}

void ProgramConfigFile::LoadSettings(const string& scfgfile)
{
    string cfgfile = GetCfgFile(scfgfile);
    if (cfgfile.empty()) {
        return;
    }

    cout << StringFormat("Read configuration file: %s\n", cfgfile);

    fs::ifstream streamConfig(cfgfile);
    if (!streamConfig.good()) {
        cerr << "Failed to read configuration file, please check whether command line is right or not. \n";
        return;
    }

    set<string> setOptions;
    setOptions.insert("*");

    HC_MAIN_PROGRAM_ARGS;

    try {
        for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
            //HCE: Don't overwrite existing settings so command line settings override hc.conf
            string strKey = string("-") + it->string_key;
            if (mapHCArgs.count(strKey) == 0)
                mapHCArgs[strKey] = it->value[0];
            mapHCMultiArgs[strKey].push_back(it->value[0]);
        }
    }
    catch (const std::exception& e) {
        cerr << StringFormat("Read configuration file exception: %s\n", e.what());
    }
}


SocketClientStreamBuf::SocketClientStreamBuf(const string& strIP, int port)
{
    m_context = new zmq::context_t(1);

    m_ip = strIP;
    m_port = port;

    connect_to();
}

SocketClientStreamBuf::~SocketClientStreamBuf()
{
    m_isstopped = true;
    m_client->close();
    if (m_context) {
        delete m_context;
    }
}


void SocketClientStreamBuf::get(string& strIP, int& port)
{
    strIP = m_ip;
    port = m_port;
}

void SocketClientStreamBuf::set(const string& strIP, int port)
{
    m_ip = strIP;
    m_port = port;
}

void SocketClientStreamBuf::connect_to()
{
    m_client.reset(new zmq::socket_t(*m_context, ZMQ_REQ));
    s_set_id(*m_client);
    int linger = 500;
    m_client->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));

    int interval = 100;
    m_client->setsockopt(ZMQ_RECONNECT_IVL, &interval, sizeof(interval));

    m_client->connect(StringFormat("tcp://%s:%d", m_ip, m_port));
    cout << StringFormat("Connect to tcp://%s:%d\n", m_ip, m_port);
}

int SocketClientStreamBuf::sync()
{
    FlushBuffer();
    return 0;
}

std::streambuf::int_type SocketClientStreamBuf::overflow(std::streambuf::int_type c)
{
    m_buffer.append(1, c);
    return 0;
}

int SocketClientStreamBuf::FlushBuffer()
{
    int len = m_buffer.size();
    if (len == 0) {
        return EOF;
    }

    zmsg request;

    cout << StringFormat("Sending request: %s to %s:%d\n\n", m_buffer, m_ip, m_port);

    request.push_front(std::move(m_buffer));
    request.push_front(MDPC_CONSOLECLIENT);

    m_buffer = "";

    int reconn = 0;
    int max_reconn = 3;
    int ntimeout = 3000;
    int max_retries = ntimeout / 100;
    while (!m_isstopped) {
        zmsg msg(request);
        msg.send(*m_client);

        int retries = 0;
        while (!m_isstopped) {
            zmq::pollitem_t items[] = {
                { static_cast<void*>(*m_client), 0, ZMQ_POLLIN, 0 } };
            zmq::poll(items, 1, 100);

            //HCE: If we got a reply, process it
            if (items[0].revents & ZMQ_POLLIN) {
                zmsg* recv_msg = new zmsg(*m_client);

                //HCE: Don't try to handle errors, just assert noisily
                assert(recv_msg->parts() >= 1);

                std::string header = recv_msg->pop_front();
                assert(header.compare(MDPC_CONSOLESERVER) == 0);

                cout << recv_msg->pop_front() << endl;
                return len;
            }
            else {
                retries++;

                if (reconn >= max_reconn) {
                    return 0;
                }

                //HCE: Reconnect, and resend message
                if (retries > max_retries && reconn < max_reconn) {
                    connect_to();
                    reconn++;
                    break;
                }
            }
        }
    }

    return  len;
}

void ConsoleCommNetServer::start(int port)
{
    if (m_pollthread) {
        return;
    }
    m_port = port;

    cout << "ConsoleCommNetServer::start..." << m_port << endl;

    m_pollthread.reset(new std::thread(&ConsoleCommNetServer::msg_handler, this));

    while (!m_isbinded) {
        this_thread::sleep_for(chrono::milliseconds(200));
    }
}

void ConsoleCommNetServer::stop()
{
    if (!m_pollthread) {
        return;
    }
    if (m_pollthread->joinable()) {
        m_pollthread->join();
    }
    m_pollthread.release();
}

void ConsoleCommNetServer::msg_handler()
{
    m_socket.reset(new zmq::socket_t(*m_context, ZMQ_ROUTER));

    m_socket->bind(StringFormat("tcp://*:%d", m_port));

    m_isbinded = true;

    zmq::pollitem_t items[] = {
        { static_cast<void*>(*m_socket), 0, ZMQ_POLLIN, 0} };

    while (!g_sys_interrupted) {
        zmq::poll(items, 1, 200);

        if (items[0].revents & ZMQ_POLLIN) {
            zmsg recvmsg(*m_socket);

            std::string sender = recvmsg.pop_front();
            recvmsg.pop_front();
            std::string header = recvmsg.pop_front();

            if (header.compare(MDPC_CONSOLECLIENT) == 0) {
                request_process(sender, &recvmsg);
            }
            else {
                //HC: *********************invalid message**********************
                recvmsg.dump();
            }
        }
    }
 }

void ConsoleCommNetServer::request_process(std::string &sender, zmsg* msg)
{
    std::string cmmand = msg->pop_front();

    std::ostringstream oss;
    ConsoleCommandHandler handler(cin.rdbuf(), oss.rdbuf());

    string savingcommand;
    handler.handleCommand(cmmand, savingcommand);

    string reply = oss.str();

    msg->push_front(std::move(reply));
    msg->push_front(MDPC_CONSOLESERVER);
    msg->wrap(sender.c_str(), "");
    msg->send(*m_socket);
}



ConsoleCommandHandler::ConsoleCommandHandler(std::streambuf* in_smbuf, std::streambuf* out_smbuf) :
    _bUpdate(false), _isRunning(true), _istream(in_smbuf), _ostream(out_smbuf)
{
    cmdstruct cmd("help", std::bind(&ConsoleCommandHandler::showUsages, this));

    loadSettings();

    _commands.emplace_back(cmdstruct("help", std::bind(&ConsoleCommandHandler::showUsages, this)));
    _commands.emplace_back(cmdstruct("?", std::bind(&ConsoleCommandHandler::showUsages, this)));
    _commands.emplace_back(cmdstruct("node", std::bind(&ConsoleCommandHandler::showNeighborNode, this)));
    _commands.emplace_back(cmdstruct("n", std::bind(&ConsoleCommandHandler::showNeighborNode, this)));
    _commands.emplace_back(cmdstruct("space", std::bind(&ConsoleCommandHandler::showHyperChainSpace, this)));
    _commands.emplace_back(cmdstruct("sp", std::bind(&ConsoleCommandHandler::showHyperChainSpace, this)));
    _commands.emplace_back(cmdstruct("spacemore", std::bind(&ConsoleCommandHandler::showHyperChainSpaceMore, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("spm", std::bind(&ConsoleCommandHandler::showHyperChainSpaceMore, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("local", std::bind(&ConsoleCommandHandler::showLocalData, this)));
    _commands.emplace_back(cmdstruct("l", std::bind(&ConsoleCommandHandler::showLocalData, this)));
    _commands.emplace_back(cmdstruct("down", std::bind(&ConsoleCommandHandler::downloadHyperBlock, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("d", std::bind(&ConsoleCommandHandler::downloadHyperBlock, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("downheader", std::bind(&ConsoleCommandHandler::downloadBlockHeader, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("dh", std::bind(&ConsoleCommandHandler::downloadBlockHeader, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("search", std::bind(&ConsoleCommandHandler::searchLocalHyperBlock, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("se", std::bind(&ConsoleCommandHandler::searchLocalHyperBlock, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("i", std::bind(&ConsoleCommandHandler::showInnerDataStruct, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("ps", std::bind(&ConsoleCommandHandler::parseAppData, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("token", std::bind(&ConsoleCommandHandler::handleToken, this, std::placeholders::_1, std::placeholders::_2)));
    _commands.emplace_back(cmdstruct("t", std::bind(&ConsoleCommandHandler::handleToken, this, std::placeholders::_1, std::placeholders::_2)));
    _commands.emplace_back(cmdstruct("coin", std::bind(&ConsoleCommandHandler::handleCoin, this, std::placeholders::_1, std::placeholders::_2)));
    _commands.emplace_back(cmdstruct("c", std::bind(&ConsoleCommandHandler::handleCoin, this, std::placeholders::_1, std::placeholders::_2)));

    _commands.emplace_back(cmdstruct("eth", std::bind(&ConsoleCommandHandler::handleEth, this, std::placeholders::_1, std::placeholders::_2)));
    _commands.emplace_back(cmdstruct("e", std::bind(&ConsoleCommandHandler::handleEth, this, std::placeholders::_1, std::placeholders::_2)));

    _commands.emplace_back(cmdstruct("debug", std::bind(&ConsoleCommandHandler::debug, this, std::placeholders::_1)));

    _commands.emplace_back(cmdstruct("ll", std::bind(&ConsoleCommandHandler::setLoggerLevel, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("llcss", std::bind(&ConsoleCommandHandler::setConsensusLoggerLevel, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("test", std::bind(&ConsoleCommandHandler::enableTest, this, std::placeholders::_1)));

    _commands.emplace_back(cmdstruct("submit", std::bind(&ConsoleCommandHandler::submitData, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("sm", std::bind(&ConsoleCommandHandler::submitData, this, std::placeholders::_1)));

    _commands.emplace_back(cmdstruct("simulate", std::bind(&ConsoleCommandHandler::simulateHyperBlkUpdated, this, std::placeholders::_1)));

    //HC: Query the on-chain state of a committed block
    _commands.emplace_back(cmdstruct("query", std::bind(&ConsoleCommandHandler::queryOnchainState, this, std::placeholders::_1)));
    
    _commands.emplace_back(cmdstruct("qr", std::bind(&ConsoleCommandHandler::queryOnchainState, this, std::placeholders::_1)));
    
    //HC: javascript VM
    _commands.emplace_back(cmdstruct("vm", std::bind(&ConsoleCommandHandler::handleVM, this, std::placeholders::_1)));

    _commands.emplace_back(cmdstruct("start", std::bind(&ConsoleCommandHandler::startApplication, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("stop", std::bind(&ConsoleCommandHandler::stopApplication, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("app", std::bind(&ConsoleCommandHandler::statusApplication, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("update", std::bind(&ConsoleCommandHandler::UpdateProgram, this)));

    //HC: create cross-chain transaction
    _commands.emplace_back(cmdstruct("getchainaddr", std::bind(&ConsoleCommandHandler::getChainAddr, this, std::placeholders::_1)));

    _commands.emplace_back(cmdstruct("swap", std::bind(&ConsoleCommandHandler::swap, this, std::placeholders::_1)));
    _commands.emplace_back(cmdstruct("s", std::bind(&ConsoleCommandHandler::swap, this, std::placeholders::_1)));
    
    _commands.emplace_back(cmdstruct("exit", std::bind(&ConsoleCommandHandler::exit, this)));
    _commands.emplace_back(cmdstruct("quit", std::bind(&ConsoleCommandHandler::exit, this)));
    _commands.emplace_back(cmdstruct("q", std::bind(&ConsoleCommandHandler::exit, this)));

}

ConsoleCommandHandler::~ConsoleCommandHandler()
{
    if (_r == role::CLIENT) {
        writeSettings();
    }
}

void ConsoleCommandHandler::showUsages()
{
    _ostream << "Copyright 2016-2024 hyperchain.net (Hyperchain (R)) v" << VERSION_STRING << endl;
    _ostream << "These are common commands used in various situations:" << endl;
    _ostream << "The '<>' means that the command has a required argument, and '[]' means an optional argument" << endl << endl;

    _ostream << "   help(?):                        show all available commands" << endl;
    _ostream << "   /h:                             show history of commands" << endl;
    _ostream << "   /c [color]:                     set prompt color(RED GREEN YELLOW BLUE MAGENTA CYAN WHITE)" << endl;
    _ostream << "   clh:                            clear history of commands" << endl;
    _ostream << "   node(n):                        show neighbor node information" << endl;
    _ostream << "   space(sp):                      show HyperChain-Space information" << endl;
    _ostream << "   spacemore(spm):                 show a specified hyper block from HyperChain-Space more information" << endl;
    _ostream << "                                       spm <hid>" << endl;
    _ostream << "   local(l):                       show local data information" << endl;
    _ostream << "   down(d):                        download specified hyper blocks from HyperChain-Space to local" << endl;
    _ostream << "                                       d <nodeid> <hid> [blockcount] " << endl;
    _ostream << "   search(se):                     search detail information for a number of specified hyper blocks,show solo chains with 'v'" << endl;
    _ostream << "                                       se [hid] [v], se [from hid1] [to hid2] [v], se -1 v" << endl;
    _ostream << "   submit(sm):                     submit data onto the chain: submit <data>" << endl;
    _ostream << "   query(qr):                      query status of the submitted data on the chain: query <requestid>" << endl;
    _ostream << "   internal(i):                    show internal information of program: i [b/n/c/sn/sc]" << endl;
    _ostream << "   debug:                          debug the specified application: debug application [file/con/both/off] [err/warn/info/debug/trace] [nobt/bt/bt:id] " << endl;
    _ostream << "   parse(ps):                      parse the specified block data stream into a readable form" << endl;
    _ostream << "                                       ps [ledger/paracoin] [hid chainid localid] or rs [ledger/paracoin] height" << endl;
    _ostream << "   token(t):                       control or show tokens" << endl;
    _ostream << "   coin(c):                        control or show coins" << endl;
    _ostream << "   eth(e):                         control or show ethereum" << endl;
    _ostream << "   start:                          load and start the specified application: start <ledger/paracoin> [options]" << endl;
    _ostream << "                                       start paracoin -debug -gen" << endl;

    _ostream << "   stop:                           stop and unload the specified application: stop <ledger/paracoin>" << endl;
    _ostream << "   app:                            list the loaded applications and their status" << endl;
    _ostream << "   loggerlevel(ll):                set logger level(trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)" << endl;
    _ostream << "   consensusloggerlevel(llcss):    set consensus logger level(trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)" << endl;

    _ostream << "   getchainaddr:                   generate a target chain address of ethereum" << endl;
    _ostream << "   swap(s):                        send/query/import cross-chain transactions, which swap value between paracoin and ethereum" << endl;

    _ostream << "   vm:                             run a javascript script or submit a block with javascript script onto the chain" << endl;

    _ostream << "   update:                         check the program whether it is the latest and update" << endl;
    _ostream << "   exit(quit/q):                   exit the program" << endl << endl;


    _ostream << "Press ctrl-L to clear screen, ctrl-R to reverse history search, ctrl-S to forward history search" << endl << endl;
}

string ConsoleCommandHandler::GetConfigFile()
{
    fs::path pathConfig;
    pathConfig = fs::path(GetHyperChainDataDir()) / ".rmtserver";
    return pathConfig.string();
}


void ConsoleCommandHandler::loadSettings()
{
    fs::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good()) {
        return;
    }

    set<string> setOptions;
    setOptions.insert("*");

    for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        _mapSettings[it->string_key] = it->value[0];
    }
}

void ConsoleCommandHandler::writeSettings()
{
    fs::ofstream streamConfig(GetConfigFile());
    if (!streamConfig.good()) {
        cout << "cannot open configuration file" << endl;
        return;
    }

    if (!streamConfig.good())
        return;

    for (auto& optional : _mapSettings) {
        streamConfig << optional.first << " = " << optional.second << endl;
    }
}


void ConsoleCommandHandler::insertRemoteServer(string& ip, int port)
{
    string server = StringFormat("%s %d", ip, port);
    for (auto& elm : _mapSettings) {
        if (elm.second == server) {
            //HC: already in map
            return;
        }
    }

    size_t s = _mapSettings.size();
    _mapSettings.insert(make_pair(StringFormat("%d", ++s), server));
}

bool ConsoleCommandHandler::UpdateProgram()
{
    //HC:Get hc.exe path
    boost::filesystem::path pathHC(g_argv[0]);
    pathHC = pathHC.branch_path() / ".";
    pathHC = boost::filesystem::system_complete(pathHC);

    //HC:Check if needs to update
    UpdateInfo updateinfo(pathHC);

    string localmd5;
    bool bCheckUpdate = false;

    if (updateinfo.GetUpdateInfo()) {
        if (updateinfo.CheckUpdate())
            bCheckUpdate = true;
    }
    else
        cout << "Get version information error!check your network and try again!" << endl;

    if(bCheckUpdate){
        cout << "Program has new version and needs to update! " << endl;

        cout << "The new fuctions include:" << endl;
        for(auto& strmsg: updateinfo.updatemsg)
            cout << strmsg << endl;

        HC_MAIN_PROGRAM_ARGS;

        cout << "Update may cause data lost." << endl;
        cout << "Please backup your data in directory: " << mapHCArgs["-datadir"] << " before update." << endl;
        cout << "Do you want to update now(y/n, default:n)?";

        char c_action;
        cin >> std::noskipws >> c_action;

        if (c_action == 'y' || c_action == 'Y') {
            if (updateinfo.PreUpdate())
            {
                _bUpdate = true;
                _isRunning = false;
                return true;
            }
            else
                cout << "update files error! update at another time!" << endl;
        }

        if (c_action != '\n') {
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }
    else
        cout << "Program is already the latest version!" << endl;

    return false;

 }

void ConsoleCommandHandler::exit()
{
    cout << "Are you sure you want to exit(y/n, default:y)?";

    char c_action;
    cin >> std::noskipws >> c_action;

    //if (cin.rdbuf()->in_avail() > 0) {
    //HCE: on Linux, have no any effect for calling cin.rdbuf()->in_avail
    //if (cin.rdbuf()->sgetc() != streambuf::traits_type::eof()) {
    if (c_action != '\n') {
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    if (c_action == '\n' || c_action == 'y' || c_action == 'Y') {
        _isRunning = false;
        UpdateProgram();
    }
}

void ConsoleCommandHandler::handleCommand(const string &command, string& savingcommand)
{
    string cmdWord = command;
    size_t pos = command.find_first_of(' ');
    if (pos != std::string::npos) {
        cmdWord = command.substr(0, pos);
    }

    auto it = std::find_if(_commands.begin(), _commands.end(), [&cmdWord](cmdstruct &cmd)->bool {
        if (cmdWord == cmd.key) {
            return true;
        }
        return false;
    });

    list<string> commlist;
    stringTostringlist(command, commlist);

    if (it == _commands.end()) {
        _ostream << "command not found\n";
        return;
    }

    try {
        it->func(commlist, savingcommand);
    }
    catch (std::exception& e) {
        _ostream << StringFormat("An exception occurs: %s\n", e.what());
    }
    catch (...) {
        _ostream << StringFormat("An exception occurs calling %s\n", __FUNCTION__);
    }
}

string GetCommHisFile()
{
    fs::path pathConfig;
    pathConfig = fs::path(GetHyperChainDataDir()) / ".commdhis";
    return pathConfig.string();
}


void ConsoleCommandHandler::run_as_client()
{
    _r = role::CLIENT;
    _commands.emplace_back(cmdstruct("su", std::bind(&ConsoleCommandHandler::switchRemoteServer, this, std::placeholders::_1)));

    string ipaddr;
    int port;
    SocketClientStreamBuf* sockbuf = dynamic_cast<SocketClientStreamBuf*>(_ostream.rdbuf());
    sockbuf->get(ipaddr, port);
    insertRemoteServer(ipaddr, port);

    cout << "Input help for detail usages" << endl;
    //cout << "Exit remote server use command 'qremote'" << endl;
    cout << "Switch remote server: su IPAddress Port\n";


    CColorPrompt lineedit(false, HCPROMPT, GetCommHisFile());
    string command;

    while (_isRunning) {

        command = lineedit.getinputline();
        if (_istream.fail()) {
            _istream.clear();
            continue;
        }

        trim(command);
        if (command == "/h") {
            cout << lineedit.gethistories();
            continue;
        }
        else if (command == "clh") {
            //HCE: clear the history of commands
            lineedit.clearhistories();
            continue;
        }
        else if (command.substr(0, 2) == "/c") {
            lineedit.promptcolor(command.substr(2));
            continue;
        }

        if ((command == "q" || command == "quit" || command == "exit" || command.substr(0,2) == "su") ) {

            string savingcommand;

            handleCommand(command, savingcommand);
            savingcommand.empty() ?
                lineedit.addhisline(command):
                lineedit.addhisline(savingcommand);

            command = "";
            continue;
        }

        //if (command == "qremote") {
        //    command = "quit";
        //}
        _ostream << command;

        //HC: force output
        _ostream.rdbuf()->pubsync();
    }
}


void ConsoleCommandHandler::run(role r)
{
    _r = r;
    _ostream << "Input help for detail usages" << endl;
    string command;

    CColorPrompt lineedit(r == role::DAEMON, HCPROMPT, GetCommHisFile());

    while (_isRunning) {

#ifndef WIN32
        //HC: As daemon, stdin has redirected to /dev/null in main() function
        if (r == role::DAEMON) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
#endif
        command = lineedit.getinputline();
        if (_istream.fail()) {
            _istream.clear();
            continue;
        }

        trim(command);
        if (command.empty()) {
            continue;
        }

        if (command == "/h") {
            _ostream << lineedit.gethistories();
            continue;
        }
        else if (command == "clh") {
            //HCE: clear the history of commands
            lineedit.clearhistories();
            continue;
        }
        else if (command.substr(0, 2) == "/c") {
            lineedit.promptcolor(command.substr(2));
            continue;
        }

        string savingcommand;

        handleCommand(command, savingcommand);
        savingcommand.empty() ?
            lineedit.addhisline(command) :
            lineedit.addhisline(savingcommand);


        _ostream.rdbuf()->pubsync();
    }
}

void ConsoleCommandHandler::stop()
{
    _isRunning = false;
    //HCE: make getline return
    _istream.rdbuf()->sputn("xstop\n", 6);
}

void ConsoleCommandHandler::showNeighborNode()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    _ostream << StringFormat("My neighbor nodes:\n%s\n", nodemgr->toFormatString().c_str());
}

void ConsoleCommandHandler::showMQBroker()
{
    _ostream << "MQ Thread ID:" << endl;
    _ostream << "\t     Consensus: " << Singleton<ConsensusEngine>::getInstance()->MQID() << endl;
    _ostream << "\t    ChainSpace: " << Singleton<CHyperChainSpace, string>::getInstance()->MQID() << endl;
    _ostream << "\t   NodeManager: " << Singleton<NodeManager>::getInstance()->MQID() << endl ;
    _ostream << "\tUdpDataHandler: " << Singleton<UdpRecvDataHandler>::getInstance()->MQID() << endl << endl;

    HCMQMonitor mon;

    zmsg request;

    zmsg *recvmsg = mon.synccall("", &request);

    string ret;
    MQMsgPop(recvmsg, ret);

    _ostream << StringFormat("MQ broker details:\n%s\n", ret.c_str());
}

void ConsoleCommandHandler::showHyperChainSpace()
{
    CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

    map<string, string> HyperChainSpace;
    HSpce->GetHyperChainShow(HyperChainSpace);

    if (HyperChainSpace.empty()) {
        _ostream << "HyperChainSpace is empty..." << endl;
        return;
    }

    _ostream << "HyperChainSpace:" << endl;
    for (auto &mdata : HyperChainSpace) {
        _ostream << "NodeID = " << mdata.first << ", " << mdata.second << endl;
    }

}

void ConsoleCommandHandler::showHyperChainSpaceMore(const list<string> &commlist)
{
    size_t s = commlist.size();
    if (s <= 1) {
        _ostream << "Please specify the block number." << endl;
        return;
    }

    auto iterCurrPos = commlist.begin();
    std::advance(iterCurrPos, 1);
    if (iterCurrPos != commlist.end()) {
        uint64 nblocknum = std::stol(*iterCurrPos);

        CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
        map<uint64, set<string>> HyperChainSpace;
        HSpce->GetHyperChainData(HyperChainSpace);

        if (HyperChainSpace.empty()) {
            _ostream << "HyperChainSpace is empty." << endl;
            return;
        }

        for (auto& mdata : HyperChainSpace) {
            if (mdata.first != nblocknum)
                continue;

            for (auto& sid : mdata.second)
                _ostream << "HyperChainSpace: HyperID = " << nblocknum << ",NodeID = " << sid << endl;
            break;
        }
    }
}

void ConsoleCommandHandler::showLocalData()
{
    string Ldata;
    CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
    vector<string> LocalChainSpace;
    HSpce->GetLocalHIDsection(LocalChainSpace);

    if (LocalChainSpace.empty()) {
        _ostream << "Local HyperData is empty." << endl;
        return;
    }

    for (auto &t : LocalChainSpace) {
        Ldata += t;
        Ldata += ";";
    }

    uint64 HID = HSpce->GetHeaderHashCacheLatestHID();

    _ostream << "LocalHyperBlockData : HyperID = " << Ldata << endl;
    _ostream << "LocalHeaderData : Latest Header ID = " << HID << endl;
}

void ConsoleCommandHandler::downloadHyperBlock(const list<string> &commlist)
{
    size_t s = commlist.size();
    CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

    if (s < 3) {
        _ostream << "Please specify the node id." << endl;
        _ostream << "Please specify the block height." << endl;
        return;
    }

    auto iterCurrPos = commlist.begin();
    std::advance(iterCurrPos, 1);
    string strnodeid = *iterCurrPos;

    //HCE: Test strnode id
    CUInt128 test(strnodeid);

    std::advance(iterCurrPos, 1);
    uint64 nblockid = std::stoll(*iterCurrPos);

    std::advance(iterCurrPos, 1);

    uint64 nblockcount = 1;
    if (iterCurrPos != commlist.end()) {
        nblockcount = std::stoll(*iterCurrPos);
    }

    HSpce->BatchGetRemoteHyperBlockByID(nblockid, nblockcount, strnodeid);
}

void ConsoleCommandHandler::downloadBlockHeader(const list<string> &commlist)
{
    size_t s = commlist.size();
    CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

    if (s < 3) {
        _ostream << "Please specify the node id." << endl;
        _ostream << "Please specify the block id." << endl;
        return;
    }

    auto iterCurrPos = commlist.begin();
    std::advance(iterCurrPos, 1);
    string strnodeid = *iterCurrPos;

    //Test strnode id
    CUInt128 test(strnodeid);

    std::advance(iterCurrPos, 1);
    uint64 nblockid = std::stoll(*iterCurrPos);

    std::advance(iterCurrPos, 1);

    uint16 range = 1;
    if (iterCurrPos != commlist.end()) {
        range = std::stoll(*iterCurrPos);
    }

    HSpce->GetRemoteBlockHeader(nblockid, range, strnodeid);
}

string toReadableTime(time_t t)
{
    char strstamp[32] = { 0 };
    strftime(strstamp, 32, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return string(strstamp);
}

void ConsoleCommandHandler::showHyperBlock(uint64 hid, bool isShowDetails)
{
    T_HYPERBLOCK h;
    bool isHaved = CHyperchainDB::getHyperBlock(h, hid);

    if (isHaved) {
        _ostream << "Hyper Block Id:        " << h.GetID() << endl;
        _ostream << "Created Time:          " << toReadableTime(h.GetCTime()) << endl;
        _ostream << "Version:               " << h.GetVersion().tostring() << endl;
        _ostream << "Hyper Block Hash:      " << h.GetHashSelf().toHexString() << endl;
        _ostream << "PreHyper Block Hash:   " << h.GetPreHash().toHexString() << endl;
        _ostream << "PreHyper Block Header Hash:   " << h.GetPreHeaderHash().toHexString() << endl;
        _ostream << "Hyper Block Weight:    " << h.GetWeight() << endl;
        _ostream << "The total number of solo chains:    " << h.GetChildChainsCount() << endl;
        _ostream << "The total number of local blocks:   " << h.GetChildBlockCount() << endl;

        int nChainID = 1;
        for (auto& chain : h.GetChildChains()) {
            _ostream << StringFormat("\tsolo chain %d:\t", nChainID++);
            for (auto& l : chain) {
                _ostream << l.GetAppType().tohexstring();
                break;
            }
            _ostream << "\t" << chain.size() << endl;
        }

        _ostream << endl << endl;

        if (isShowDetails) {
            int nChainID = 1;
            for (auto& chain : h.GetChildChains()) {
                _ostream << StringFormat("*********************** The %d Chain Details *****************************\n\n", nChainID++);
                for (auto& l : chain) {
                    _ostream << "local block Id:    " << l.GetID() << endl;
                    _ostream << "Version:           " << l.GetVersion().tostring() << endl;
                    _ostream << "Application Type:  " << l.GetAppType().tohexstring() << endl;
                    _ostream << "Chain number:      " << l.GetChainNum() << endl;
                    _ostream << "Created Time:      " << toReadableTime(l.GetCTime()) << endl;
                    _ostream << "Block Hash:        " << l.GetHashSelf().toHexString() << endl;
                    _ostream << "PreBlock Hash:     " << l.GetPreHash().toHexString() << endl;
                    _ostream << "Payload Preview:   " << l.GetPayLoadPreview() << endl;
                    if (l.GetAppType().isSmartContract()) {
                        _ostream << "Script Preview:   " << l.GetScriptPreview() << endl;
                    }
                    _ostream << endl;
                }
            }
        }
        _ostream << endl;
    }
 }

void ConsoleCommandHandler::searchLocalHyperBlock(const list<string> &commlist)
{
    int64 nblocknum = 0;
    int64 nblocknumEnd = 0;

    list<string> commlistcopy = commlist;

    bool isShowDetails = false;
    for (auto bg = commlistcopy.begin(); bg != commlistcopy.end(); ++bg) {
        if (*bg == "v") {
            isShowDetails = true;
            commlistcopy.erase(bg);
            break;
        }
    }

    CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
    int64 nCurrHeight = sp->GetMaxBlockID();

    size_t s = commlistcopy.size();
    if (s <= 1) {
        nblocknum = nCurrHeight;
        nblocknumEnd = nblocknum;
    }
    else {
        auto iterCurrPos = commlistcopy.begin();
        std::advance(iterCurrPos, 1);
        nblocknum = std::stol(*iterCurrPos);
        nblocknumEnd = nblocknum;

        std::advance(iterCurrPos, 1);
        if (iterCurrPos != commlistcopy.end()) {
            if (*iterCurrPos != "v") {
                nblocknumEnd = std::stol(*iterCurrPos);
            }
        }

        //HCE: support <0 value
        if (nblocknum < 0) {
            nblocknum = nCurrHeight + nblocknum;
        }

        if (nblocknumEnd < 0) {
            nblocknumEnd = nCurrHeight + nblocknumEnd;
        }
    }


    for (; nblocknum <= nblocknumEnd; nblocknum++) {
        showHyperBlock(nblocknum, isShowDetails);
    }
}

void ConsoleCommandHandler::showUdpDetails()
{
    _ostream << Singleton<UdtThreadPool, const char*, uint32_t>::getInstance()->getUdtStatics();
}


void ConsoleCommandHandler::debug(const list<string> &paralist)
{
    size_t s = paralist.size();
    if (s == 1) {
        _ostream << "debug application-name [file/con/both/off] [err/warn/info/debug/trace] [nobt/bt/bt:id]\n";
        return;
    }

    auto para = paralist.begin();
    string app = *(++para);
    string onoff;

    ++para;
    for (; para != paralist.end(); ++para) {
        onoff += *para;
        onoff += " ";
    }

    string ret;
    auto f = (*g_appPlugin)[app];
    if (f) {
        f->appTurnOnOffDebugOutput(onoff, ret);
        _ostream << StringFormat("%s\n", ret.c_str());
        return;
    }

    _ostream << "unknown application\n";
}

void ConsoleCommandHandler::parseAppData(const list<string> &paralist)
{
    size_t s = paralist.size();

    string info;
    if (s < 2) {
        for (auto& app : (*g_appPlugin)) {
            info = "";
            app.second.appInfo(info);
            _ostream << StringFormat("%s\n\n", info.c_str());

        }
        return;
    }

    auto para = paralist.begin();
    string app = *(++para);

    auto f = (*g_appPlugin)[app];
    if (!f) {
        _ostream << StringFormat("The application(%s) not found\n", app.c_str());
        return;
    }

    if (paralist.size() == 2) {
        f->appInfo(info);
        _ostream << StringFormat("%s\n", info.c_str());
        return;
    }

    if (paralist.size() == 3) {
        //HCE: query address by height
        int32 height = std::stoi(*(++para));
        f->appResolveHeight(height, info);
        _ostream << StringFormat("%s\n", info.c_str());
        return;
    }

    if (paralist.size() != 5) {
        _ostream << "format error\n";
        return;
    }

    //HCE: Resolve payload into application block
    int64 hID = std::stol(*(++para));
    int16 chainID = std::stoi(*(++para));
    int16 localID = std::stoi(*(++para));

    T_LOCALBLOCKADDRESS addr;
    addr.set(hID, chainID, localID);

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
        _ostream << "The block:" << addr.tostring() << " not exists" << endl;
        return;
    }

    f->appResolvePayload(payload, info);
    _ostream << StringFormat("%s\n", info.c_str());
}

void ConsoleCommandHandler::showConsensusInfo()
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS* pConsensusStatus = consensuseng->GetConsunsusState();

    uint32 l, g, nxt;
    pConsensusStatus->GetConsensusTime(l, g, nxt);
    _ostream << StringFormat("Consensus duration parameters(seconds): %u %u %u\n", l, g - l, nxt - g);
    _ostream << "Block numbers waiting to consensus: " << pConsensusStatus->GetListOnChainReqCount() << endl;
    _ostream << endl;

    size_t reqblknum, rspblknum, reqchainnum, rspchainnum;
    size_t localchainBlocks, globalbuddychainnum;
    LIST_T_LOCALCONSENSUS localbuddychaininfos;

    consensuseng->GetDetailsOfCurrentConsensus(reqblknum, rspblknum,
        reqchainnum, rspchainnum, localchainBlocks, &localbuddychaininfos, globalbuddychainnum);

    switch (pConsensusStatus->GetCurrentConsensusPhase()) {
    case CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE:
        _ostream << "Phase: Prepare to enter LOCALBUDDY_PHASE, "
            << "Consensus condition : " << consensuseng->IsAbleToConsensus() << endl;
        break;
    case CONSENSUS_PHASE::LOCALBUDDY_PHASE:
        _ostream << "Phase: LOCALBUDDY_PHASE" << endl;
        _ostream << "Request block number(listRecvLocalBuddyReq): " << reqblknum << endl;
        _ostream << "Respond block number(listRecvLocalBuddyRsp): " << rspblknum << endl;
        _ostream << "Standby block chain number(listCurBuddyReq): " << reqchainnum << endl;
        _ostream << "Standby block chain number(listCurBuddyRsp): " << rspchainnum << endl;
        break;
    case CONSENSUS_PHASE::GLOBALBUDDY_PHASE:
        _ostream << "Phase: GLOBALBUDDY_PHASE" << endl;
        break;
    case CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE:
        _ostream << "Phase: PERSISTENCE_CHAINDATA_PHASE" << endl;
    }

    int i = 0;
    _ostream << "listLocalBuddyChainInfo Number: " << localbuddychaininfos.size() << endl;
    for (auto& b : localbuddychaininfos) {
        auto& block = b.GetLocalBlock();
        _ostream << "Application Type:  " << block.GetAppType().tohexstring() << endl;
        _ostream << "LocalBlock Payload Preview: " << ++i << "," << block.GetPayLoadPreview() << endl;

        if (block.GetAppType().isSmartContract()) {
            _ostream << "LocalBlock Script Preview: " << block.GetScriptPreview() << endl;
        }
    }
    _ostream << "listGlobalBuddyChainInfo Number: " << globalbuddychainnum << endl;
}

void ConsoleCommandHandler::showInnerBasicInfo()
{
    CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    _ostream << "Starting time: " << g_strSysStartTm << endl;
    //_ostream << "My NodeID: " << nodemgr->getMyNodeId<string>() << endl;
    _ostream << "My Node: " << nodemgr->myself()->serialize() << endl;
    _ostream << "My Max HyperBlock ID: " << sp->GetMaxBlockID() << endl;
    _ostream << "Latest HyperBlock is ready: " << sp->IsLatestHyperBlockReady() << endl;
    _ostream << "My Data Root Directory: " << GetHyperChainDataDir() << endl;
    _ostream << "Network protocol version: " << ProtocolVer::getString() << endl << endl;


    stringstream ss;
    for (int i = 0; i < g_argc; i++) {
        ss << g_argv[i] << " ";
    }
    _ostream << "Command line: " << ss.str() << endl;

    HC_MAIN_PROGRAM_ARGS;

    string cfgfile = ProgramConfigFile::GetCfgFile();
    if (!cfgfile.empty()) {
        _ostream << "Configuration file: " << cfgfile << endl;
        _ostream << "Options: ";
        for (auto& key : mapHCArgs) {
            for (string& value : mapHCMultiArgs[key.first]) {
                if (value.empty()) {
                    _ostream << key.first << " ";
                    continue;
                }
                _ostream << StringFormat("%s=%s ", key.first, value);
            }
        }
        _ostream << endl;
    }

#ifdef WIN32
    _ostream << "PID: " << GetCurrentProcessId() << endl << endl;
#else
    _ostream << "PID: " << getpid() << endl << endl;
#endif
}

void ConsoleCommandHandler::showHyperChainSpaceInteral()
{
    CHyperChainSpace* hspace = Singleton<CHyperChainSpace, string>::getInstance();
    if (!hspace) {
        return;
    }

    _ostream << hspace->GetPullingHyperBlock() << endl;
}


void ConsoleCommandHandler::showInnerDataStruct(const list<string>& paralist)
{
    auto para = paralist.begin();

    if (paralist.size() == 1) {
        showInnerBasicInfo();
        return;
    }

    string option1 = *(++para);
    if (option1 == "b") {
        showMQBroker();
    }
    else if (option1 == "sn") { //statistics node
        NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
        _ostream << nodemgr->GetMQCostStatistics() << endl;
    }
    else if (option1 == "sc") { //statistics chain
        CHyperChainSpace* hspace = Singleton<CHyperChainSpace, string>::getInstance();
        _ostream << hspace->GetMQCostStatistics() << endl;
    }
    else if (option1 == "c") {
        showConsensusInfo();
    }
    else if (option1 == "n") {
        showUdpDetails();
    }
    else if (option1 == "h") {
        showHyperChainSpaceInteral();
    }
    else if (option1 == "uuid") {
        cout << "Are you sure you want to reset uuid of the node(y/n)?";
        string sInput;
        cin >> sInput;
        if (sInput == "y" || sInput == "Y") {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            if (nodemgr->RemoveMyself()) {
                _ostream << "Ok, please restart to take effect." << endl;
            } else {
                _ostream << "Failed to reset uuid" << endl;
            }
        }
    }
    else {
        _ostream << "Available options: b/c/n/sn/sc/uuid, \n"
            "\twhich mean Broker/Consensus/Network/Perf Statis of Node&ChainSpace/Reset uuid." << endl;
    }
}

void ConsoleCommandHandler::setLoggerLevelHelp(std::shared_ptr<spdlog::logger> & logger,
    const list<string> &level)
{
    unordered_map<string, spdlog::level::level_enum> maploglevel = {
        {"trace",spdlog::level::trace},
        {"debug",spdlog::level::debug},
        {"info",spdlog::level::info},
        {"warn",spdlog::level::warn},
        {"err",spdlog::level::err},
        {"critical",spdlog::level::critical},
        {"off",spdlog::level::off},
    };

    spdlog::level::level_enum lev = logger->level();
    if (level.size() > 1) {
        auto pos = ++level.begin();
        if (maploglevel.count(*pos)) {
            lev = maploglevel.at(*pos);
        }
        logger->set_level(lev);
    }
    using loglevelvaluetype = unordered_map<string, spdlog::level::level_enum>::value_type;
    string levelname = "unknown";
    std::find_if(maploglevel.begin(), maploglevel.end(), [&logger, &levelname](const loglevelvaluetype &ll) {
        if (ll.second == logger->level()) {
            levelname = ll.first;
            return true;
        }
        return false;
    });

    //HC:(trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)
    _ostream << StringFormat("%s log level is %s (trace,debug,info,warn,err,critical,off)\n",
        logger->name().c_str(), levelname.c_str());
}

void ConsoleCommandHandler::setLoggerLevel(const list<string> &level)
{
    setLoggerLevelHelp(g_console_logger, level);
    return;
}

void ConsoleCommandHandler::setConsensusLoggerLevel(const list<string> &level)
{
    setLoggerLevelHelp(g_consensus_console_logger, level);
    return;
}

void ConsoleCommandHandler::startApplication(const list<string> &appli)
{
    if (appli.size() > 1) {
        auto option = ++appli.begin();
        auto beg = appli.begin();
        std::advance(beg, 2);
        g_appPlugin->StartApp(*option, beg, appli.end());
        return;
    }

    _ostream << "Invalid command\n";
}

void ConsoleCommandHandler::stopApplication(const list<string> &appli)
{
    //HC: 调用二次完成退出，第一次各模块收到退出通知，置位开始退出 第二次执行全面退出
    if (appli.size() > 1) {
        auto option = ++appli.begin();
        g_appPlugin->StopApp(*option);

        //HC: 全面退出
        g_appPlugin->StopApp(*option);
        return;
    }
    _ostream << "Invalid command\n";
}


void ConsoleCommandHandler::statusApplication(const list<string> &appli)
{
    map<string, string> mapappstatus;
    g_appPlugin->GetAllAppStatus(mapappstatus);

    if (mapappstatus.empty()) {
        _ostream << "No run any application\n";
        return;
    }

    for (auto &s : mapappstatus) {
        _ostream << StringFormat("%-10s\t%s\n", s.first.c_str(), s.second.c_str());
    }
}

void ConsoleCommandHandler::enableTest(const list<string> &onoff)
{
    ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::instance();
    if (onoff.size() > 1) {
        auto option = ++onoff.begin();
        if (*option == "on") {
            consensuseng->startTest();
            _ostream << "Consensus test thread is started\n";
        }
        else if (*option == "off") {
            consensuseng->stopTest();
            _ostream << "Consensus test thread is stopped\n";
        }
    }
    else {
        if (consensuseng->IsTestRunning()) {
            _ostream << "Consensus test thread is on\n";
        }
        else {
            _ostream << "Consensus test thread is off\n";
        }
    }
}


void ConsoleCommandHandler::submitData(const list<string>& cmdlist)
{
    if (cmdlist.size() == 1) {
        _ostream << "Usage: submit <data>\n";
        return;
    }

    RestApi api;
    SubmitData data;
    auto strdata = *(++cmdlist.begin());

    data.payload = strdata;
    http::status_code code;
    json::value vRet = api.MakeRegistration(data, code);

    string ret = t2s(vRet[_XPLATSTR("requestid")].as_string());
    _ostream << StringFormat("requestid: %s\n", ret);

}

void ConsoleCommandHandler::queryOnchainState(const list<string>& cmdlist)
{
    if (cmdlist.size() == 1) {
        _ostream << "Usage: query <requestid>\n";
        return;
    }

    auto requestid = ++cmdlist.begin();
    T_LOCALBLOCKADDRESS blockaddr;
    RestApi api;
    string s = api.getOnchainState(*requestid, &blockaddr);

    if (blockaddr.isValid()) {
        _ostream << StringFormat("%s %s\n", s.c_str(), blockaddr.tostring().c_str());
    }
    else {
        _ostream << StringFormat("%s\n", s.c_str());
    }
}



void ConsoleCommandHandler::switchRemoteServer(const list<string>& cmdlist)
{
    string ipaddr;
    int port;
    SocketClientStreamBuf* sockbuf = dynamic_cast<SocketClientStreamBuf*>(_ostream.rdbuf());

    auto childcmd = ++cmdlist.begin();
    string ccmd;

    if (cmdlist.size() == 1) {
        goto usage;
    }
    ccmd = *childcmd;

    if (ccmd == "-") {
        if (++childcmd == cmdlist.end()) {
            goto usage;
        }

        if (_mapSettings.count(*childcmd)) {
            char ipaddress[128] = {0};
            if (std::sscanf(_mapSettings[*childcmd].c_str(), "%64s %d", ipaddress, &port) == 2) {
                sockbuf->set(ipaddress, port);
                return;
            }
            cout << StringFormat("Invalid remote server string: %d\n", *childcmd);
        }
        return;
    }
    else if (ccmd == "l") {

        if (_mapSettings.size() == 0) {
            goto usage;
        }
        for (auto& elm : _mapSettings) {
            cout << StringFormat("%s %s\n", elm.first, elm.second);
        }
        cout << endl;
        return;
    }
    else if (cmdlist.size() < 3) {
        goto usage;
    }

    //HCE: a new remote server
    ipaddr = ccmd;
    port = std::atoi((++childcmd)->c_str());

    cout << StringFormat("Switch to %s:%d\n", ipaddr, port);

    sockbuf->set(ipaddr, port);
    insertRemoteServer(ipaddr, port);

    return;

usage:
    cout << "Usage: su <IPAddress> <Port>\n";
    cout << "       su - <id>\n";
    cout << "       su l\n\n";

    sockbuf->get(ipaddr, port);
    cout << StringFormat("Current remote server: %s:%d\n", ipaddr, port);

    return;
}

void ConsoleCommandHandler::showVMUsage()
{
    _ostream << "Usage: vm test <-f filename | js source code>          : estimate a Smart Contract, and return result\n";
    _ostream << "       vm call <hId chainId localId>                   : call a executable Smart Contract, and return result\n";
    _ostream << "       vm add/addmodule <-f filename | js source code> : submit a Smart Contract into chain\n";
}

string ConsoleCommandHandler::extractScriptDataFromFile(const string &filename)
{
    std::ifstream streamjscode(filename, std::ios_base::in | std::ios_base::ate | std::ios_base::binary);
    if (!streamjscode.is_open()) {
        _ostream << StringFormat("cannot open file: %s\n", filename.c_str());
        return "";
    }
    //streamjscode.seekg(0, std::ios_base::end);
    auto pos = streamjscode.tellg();
    std::size_t len = ::streamoff(pos);

    streamjscode.seekg(0, std::ios_base::beg);

    string jssourcecode;
    jssourcecode.resize(len);
    streamjscode.read(jssourcecode.data(), len);
    return jssourcecode;
}

void ConsoleCommandHandler::handleVM(const list<string>& vmcmdlist)
{
    if (vmcmdlist.size() == 1) {
        showVMUsage();
        return;
    }

    SubmitData data;
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();

    auto cmd = ++vmcmdlist.begin();
    string childcmd = *cmd;

    if (childcmd != "call") {

        auto jscode = ++cmd;
        if (jscode != vmcmdlist.end() && *jscode == "-f") {
            auto jscodefile = ++cmd;
            if (jscodefile != vmcmdlist.end()) {
                data.jssourcecode = extractScriptDataFromFile(*jscodefile);
            }
        }
        else {
            for (; cmd != vmcmdlist.end(); ++cmd) {
                data.jssourcecode += " ";
                data.jssourcecode += *cmd;
            }
        }

        if (data.jssourcecode.empty()) {
            _ostream << "Script cannot be empty\n";
            goto VMUsage;
        }
    }

    if (childcmd == "addmodule" || childcmd == "add") {
        string requestid;
        uint32 nOrder;
        string excp_desc;

        bool isaddmodule = false;
        if (childcmd == "addmodule")  {
            isaddmodule = true;
        }

        qjs::VM vm;
        if (isaddmodule) {
            if (!vm.compileModule(data.jssourcecode, data.jsbytecode, excp_desc)) {
                _ostream << StringFormat("Script error when compile module: %s\n", excp_desc.c_str());
                return;
            }
        }
        else {
            if (!vm.compile(data.jssourcecode, data.jsbytecode, excp_desc)) {
                _ostream << StringFormat("Script error when compile: %s\n", excp_desc.c_str());
                return;
            }
            string jscoderesult;
            if (!vm.execute(data.jsbytecode, jscoderesult, excp_desc)) {
                _ostream << StringFormat("Execution error: %s\n", excp_desc);
                return;
            }
            _ostream << StringFormat("Execution result: %s\n", jscoderesult);
            data.payload = jscoderesult;
        }

        data.app = T_APPTYPE(APPTYPE::smartcontract);
        if (!consensuseng->AddNewBlockEx(data, requestid, nOrder, excp_desc)) {
            _ostream << StringFormat("%s\n", excp_desc.c_str());
            return;
        }
        _ostream << StringFormat("Smart Contract is committed, requestId: %s, queue No.: %d\n", requestid.c_str(), nOrder);
    }
    else if (childcmd == "test") {
        qjs::VM vm;
        string result;
        string excp;
        if (!vm.compile(data.jssourcecode, data.jsbytecode, excp)) {
            _ostream << StringFormat("Compile error, %s\n", excp.c_str());
            return;
        }

        if (vm.execute(data.jsbytecode, result, excp)) {
            //HCE: Result of Smart Contract
            _ostream << StringFormat("%s\n", result.c_str());
        }
        else {
            _ostream << StringFormat("Failed to execute, %s\n", excp.c_str());
        }
    }
    else if (childcmd == "call") {
        T_LOCALBLOCKADDRESS addr;

        if (vmcmdlist.size() < 5)
            goto VMUsage;
        auto hid = std::stol(*++cmd);
        auto chainid = std::stol(*++cmd);
        auto localid = std::stol(*++cmd);
        addr.set(hid, chainid, localid);

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        T_LOCALBLOCK localblock;
        if (!hyperchainspace->GetLocalBlock(addr, localblock)) {
            _ostream << StringFormat("The block: %s doesn't exist\n", addr.tostring().c_str());
            return;
        }

        qjs::VM vm;
        string result;
        string excp;
        if (vm.execute(localblock.GetScript(), result, excp)) {
            _ostream << StringFormat("%s\n", result.c_str());
        }
        else {
            _ostream << StringFormat("Failed to execute, %s\n", excp.c_str());
        }
    }
    else {
        goto VMUsage;
    }

    return;

VMUsage:
    showVMUsage();
}

void ConsoleCommandHandler::getChainAddr(const list<string>& cmdlist)
{
    if (cmdlist.size() < 5) {
        _ostream << "Usage: getchainaddr <hid> <chainid> <localid> <targetgenesisblockhash> : generate a target chain address\n";
        return;
    }

    auto cmd = ++cmdlist.begin();

    map<string, string> mapparams;
    mapparams["hid"] = *cmd;
    mapparams["chainid"] = *++cmd;
    mapparams["localid"] = *++cmd;
    mapparams["target_genesis_hash"] = *++cmd; 

    //if (++cmd != cmdlist.end())
    //    mapparams["recv_address"] = *cmd; //HC: account address of target chain

    string result;
    string strerr;
    bool ret = AppPlugins::callFunction<bool>("paracoin", "getchainaddress", mapparams, result, strerr);
    if (!ret) {
        _ostream << StringFormat("Error occurred: %s\n", strerr);
        return;
    }
    _ostream << result << endl;
}

static string cmd_desc_swap2eth =
        "swap p2e <name> <fromaccount> <tochain> <amount> [toaddress] : send a cross-chain transaction, <tochain> refer to command 'getchainaddr'\n";
void ConsoleCommandHandler::swap2Eth(const list<string>& cmdlist)
{
    if (cmdlist.size() < 4) {
        _ostream << "Usage: " << cmd_desc_swap2eth;
        return;
    }

    auto txcmdlist = cmdlist;

    auto cmd = cmdlist.begin();
    string name = *cmd;
    string fromaccount = *++cmd;
    if (fromaccount == "\"\"" || fromaccount == "\'\'") {
        fromaccount = "";
    }

    string chainaddress = *++cmd;
    string amount = *++cmd;

    string accountaddress;

    if (++cmd != cmdlist.end())
        accountaddress = *cmd; //HC: account address of target chain


    crosschain::ParaToEthExecutor ctx(name);
    ctx.initEnv(fromaccount, chainaddress, accountaddress, amount);

    _ostream << ctx.details();
    _ostream << "Are you sure you want to continue(y/n, default:n)?";

    char c_action;
    cin >> std::noskipws >> c_action;
    if (c_action != '\n') {
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    if (c_action == '\n' || (c_action != 'y' && c_action != 'Y')) {
        _ostream << "canceled\n";
        return;
    }

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
    string result = consensuseng->Swap2Eth(fromaccount, chainaddress, accountaddress, amount, name);
    _ostream << result << endl;

    return;
}


//HC: 跨链交易，以太坊转到Para
static const string cmd_desc_swap2Para = "swap e2p <name> <from> <to> <amount> : send a cross-chain transaction, <to> is address of Para account\n";
void ConsoleCommandHandler::swap2Para(const list<string>& cmdlist)
{
    if (cmdlist.size() < 4) {
        _ostream << cmd_desc_swap2Para;
        return;
    }

    auto txcmdlist  = cmdlist;

    auto cmd = cmdlist.begin();

    string name = *cmd;
    string fromaddress = *++cmd;
    string paraaddress = *++cmd;
    string amount = *++cmd;

    crosschain::EthToParaExecutor ctx(name);
    ctx.initEnv(fromaddress, paraaddress, amount);

    _ostream << ctx.details();
    _ostream << "Are you sure you want to continue(y/n, default:n)?";

    char c_action;
    cin >> std::noskipws >> c_action;
    if (c_action != '\n') {
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    if (c_action == '\n' || (c_action != 'y' && c_action != 'Y')) {
        _ostream << "canceled\n";
        return;
    }

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
    string result = consensuseng->Swap2Para(fromaddress, paraaddress, amount, name);
    _ostream << result << endl;
}

void ConsoleCommandHandler::swap(const list<string>& cmdlist)
{
    if (cmdlist.size() <= 1) {
        _ostream << "The usage is shown as below: \n";
        _ostream << "       " << cmd_desc_swap2eth;
        _ostream << "       " << cmd_desc_swap2Para;
        _ostream << "       swap status(s) [No.]               : query status of the cross-chain transaction\n";
        _ostream << "       swap list(l)                    : list all available the cross-chain transactions\n";
        _ostream << "       swap import(i) [hash of Tx]     : import a cross-chain transaction\n";
        _ostream << "       swap importse(ise) [hash of Tx]    : import a settlement cross-chain transaction\n";
        _ostream << "       swap rename(r) <No.> <new name>    : change name of a available cross-chain transaction\n";
        _ostream << "       swap delete(d) <No.>               : stop monitoring the cross-chain transaction\n";
        return;
    }
    auto cmd = ++cmdlist.begin();
    string action = *cmd;

    if (action == "p2e") {
        list<string> newcmdlist(++cmd, cmdlist.end());
        swap2Eth(newcmdlist);
        return;
    }
    else if (action == "e2p") {
        list<string> newcmdlist(++cmd, cmdlist.end());
        swap2Para(newcmdlist);
        return;
    }

    string param1;
    string param2;
    if (++cmd != cmdlist.end()) {
        param1 = *cmd;
        if (++cmd != cmdlist.end()) {
            param2 = *cmd;
        }
    }

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();
    string ret = consensuseng->Swap(action, param1, param2);
    _ostream << ret << endl;
}

void ConsoleCommandHandler::appConsoleCmd(const string& appname, const list<string>& cmdlist, string& savingcommand)
{
    auto f = (*g_appPlugin)[appname];
    if (!f) {
        _ostream << StringFormat("The '%s' module hasn't loaded, use 'start %s' to load\n", appname, appname);
        return;
    }

    string info;
    f->appConsoleCmd(cmdlist, info, savingcommand);
    _ostream << StringFormat("%s\n", info.c_str());
}


void ConsoleCommandHandler::handleToken(const list<string>& cmdlist, string& savingcommand)
{
    appConsoleCmd("ledger", cmdlist, savingcommand);
}

void ConsoleCommandHandler::handleCoin(const list<string>& cmdlist, string& savingcommand)
{
    appConsoleCmd("paracoin", cmdlist, savingcommand);
}

void ConsoleCommandHandler::handleEth(const list<string>& cmdlist, string& savingcommand)
{
    appConsoleCmd("aleth", cmdlist, savingcommand);
}

void ConsoleCommandHandler::simulateHyperBlkUpdated(const list<string>& cmdlist)
{
    if (cmdlist.size() < 2) {
        _ostream << "simulate HyperBlockId\n";
        return;
    }

    auto cmd = ++cmdlist.begin();

    uint32_t hid = std::atoi(cmd->c_str());
    T_HYPERBLOCK hblk;
    if (CHyperchainDB::getHyperBlock(hblk, hid)) {
        ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::instance();

        _tp2pmanagerstatus *t = consensuseng->GetConsunsusState();
        t->ApplicationAccept(hid - 1, hblk, true);
    }
}

