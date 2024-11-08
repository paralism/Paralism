// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2018-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include <libdevcore/FileSystem.h>
#include <libdevcore/LoggingProgramOptions.h>
#include <libethcore/Common.h>
#include <libp2p/Common.h>
#include <libp2p/Host.h>
#include <boost/program_options.hpp>
#include <boost/program_options/options_description.hpp>
#include <iostream>
#include <thread>

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace bi = boost::asio::ip;

using namespace dev;
using namespace dev::p2p;
using namespace dev::eth;
using namespace std;

namespace
{
string const c_programName = "aleth-bootnode";
string const c_networkConfigFileName_Formal = c_programName + "-formal-network.rlp";
string const c_networkConfigFileName_Informal = c_programName + "-informal-network.rlp";
string const c_networkConfigFileName_SandBox = c_programName + "-sandbox-network.rlp";
}  // namespace

//HC:
class NetworkModel {
public:
    NetworkModel(po::variables_map vm) {

        m_networkcfg = c_programName + "-private-network.rlp";
        m_name = "Private";
        m_nodes.clear();
        m_netflag = NetFlags::priva;
        if (vm.count("model")) {
            string model = vm["model"].as<string>();
            if (model == "sandbox") {
                m_name = "Sandbox";
                m_netflag = NetFlags::sandbox;
                m_networkcfg = c_networkConfigFileName_SandBox;
                m_nodes = defaultBootNodes_Sandbox();
            }
            else if (model == "informal") {
                m_name = "Informal";
                m_netflag = NetFlags::informal;
                m_networkcfg = c_networkConfigFileName_Informal;
                m_nodes = defaultBootNodes_Informal();
            }
            else if (model == "formal") {
                m_name = "Formal";
                m_netflag = NetFlags::formal;
                m_networkcfg = c_networkConfigFileName_Formal;
                m_nodes = defaultBootNodes();
            }
        }
    }

    string getName() {
        return m_name;
    }

    string getCfg() {
        return m_networkcfg;
    }

    std::vector<std::pair<Public, const char*>> getNodes() {
        return m_nodes;
    }

private:
    enum class NetFlags : char {
        priva, //private
        sandbox,
        informal,
        formal
    };

    string m_name;
    string m_networkcfg;
    NetFlags m_netflag;
    std::vector<std::pair<Public, const char*>> m_nodes;
};

int main(int argc, char** argv)
{
    setDefaultOrCLocale();

    bool allowLocalDiscovery = false;
    bool noBootstrap = false;

    po::options_description generalOptions("GENERAL OPTIONS", c_lineWidth);
    auto addGeneralOption = generalOptions.add_options();
    addGeneralOption("help,h", "Show this help message and exit\n");

    LoggingOptions loggingOptions;
    po::options_description loggingProgramOptions(
        createLoggingProgramOptions(c_lineWidth, loggingOptions));

    po::options_description clientNetworking("NETWORKING", c_lineWidth);
    auto addNetworkingOption = clientNetworking.add_options();
#if ETH_MINIUPNPC
    addNetworkingOption(
        "upnp", po::value<string>()->value_name("<on/off>"), "Use UPnP for NAT (default: on)");
#endif
    addNetworkingOption("model", po::value<string>()->value_name("<network>"),
        "Provide service for which network: sandbox, informal, formal");
    addNetworkingOption("public-ip", po::value<string>()->value_name("<ip>"),
        "Force advertised public IP to the given IP (default: auto)");
    addNetworkingOption("listen-ip", po::value<string>()->value_name("<ip>(:<port>)"),
        "Listen on the given IP for incoming connections (default: 0.0.0.0)");
    addNetworkingOption("listen", po::value<unsigned short>()->value_name("<port>"),
        "Listen on the given port for incoming connections (default: 30303)");
    addNetworkingOption("allow-local-discovery", po::bool_switch(&allowLocalDiscovery),
        "Include local addresses in the discovery process. Used for testing purposes.");
    addNetworkingOption("no-bootstrap", po::bool_switch(&noBootstrap),
        "Do not connect to the default Ethereum bootnode servers");
    po::options_description allowedOptions("Allowed options");
    allowedOptions.add(generalOptions).add(loggingProgramOptions).add(clientNetworking);

    po::variables_map vm;
    try
    {
        po::parsed_options parsed = po::parse_command_line(argc, argv, allowedOptions);
        po::store(parsed, vm);
        po::notify(vm);
    }
    catch (po::error const& e)
    {
        cout << e.what() << "\n";
        return AlethErrors::ArgumentProcessingFailure;
    }

    if (vm.count("help"))
    {
        cout << "NAME:\n"
             << "   " << c_programName << "\n"
             << "USAGE:\n"
             << "   " << c_programName << " [options]\n\n";
        cout << generalOptions << clientNetworking << loggingProgramOptions;
        return AlethErrors::Success;
    }

    /// Networking params.
    string listenIP;
    unsigned short listenPort = c_defaultListenPort;
    string publicIP;
    bool upnp = true;

#if ETH_MINIUPNPC
    if (vm.count("upnp"))
    {
        string m = vm["upnp"].as<string>();
        if (isTrue(m))
            upnp = true;
        else if (isFalse(m))
            upnp = false;
        else
        {
            cerr << "Bad "
                 << "--upnp"
                 << " option: " << m << "\n";
            return -1;
        }
    }
#endif

    if (vm.count("public-ip"))
        publicIP = vm["public-ip"].as<string>();
    if (vm.count("listen-ip"))
        listenIP = vm["listen-ip"].as<string>();
    if (vm.count("listen"))
        listenPort = vm["listen"].as<unsigned short>();

    setupLogging(loggingOptions);
    if (loggingOptions.verbosity > 0)
        cout << EthGrayBold << c_programName << ", a C++ Ethereum bootnode implementation" EthReset
             << "\n";

    auto netPrefs = publicIP.empty() ? NetworkConfig(listenIP, listenPort, upnp) :
                                       NetworkConfig(publicIP, listenIP, listenPort, upnp);
    netPrefs.allowLocalDiscovery = allowLocalDiscovery;

    NetworkModel networkmodel(vm);
    auto netData = contents(getDataDir() / fs::path(networkmodel.getCfg()));

    Host h(c_programName, netPrefs, &netData);
    h.start();
    if (!h.haveNetwork())
        return AlethErrors::NetworkStartFailure;

    cout << "Node ID: " << h.enode() << endl;

    string runInNetwork = networkmodel.getName();
    cout << "Providing boot service for network: " << runInNetwork << endl;
    if (!noBootstrap)
    {
        //HCE: Add nodes for different network
        std::vector<std::pair<Public, const char*>> nodes = networkmodel.getNodes();
        cout << "Add the default boot nodes for network" << endl;
        for (auto const& bn : nodes)
        {
            bi::tcp::endpoint ep = Network::resolveHost(bn.second);
            h.addNode(
                bn.first, NodeIPEndpoint{ep.address(), ep.port() /* udp */, ep.port() /* tcp */});
        }
    }

    ExitHandler exitHandler;

    signal(SIGTERM, &ExitHandler::exitHandler);
    signal(SIGABRT, &ExitHandler::exitHandler);
    signal(SIGINT, &ExitHandler::exitHandler);

    while (!exitHandler.shouldExit())
        this_thread::sleep_for(chrono::seconds(1));

    h.stop();

    netData = h.saveNetwork();
    if (!netData.empty())
        writeFile(getDataDir() / fs::path(networkmodel.getCfg()), &netData);

    return AlethErrors::Success;
}
