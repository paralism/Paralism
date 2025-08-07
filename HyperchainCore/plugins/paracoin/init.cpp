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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


#include "node/Singleton.h"
#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"
#include "util/threadname.h"

#include "headers.h"
#include "db.h"
#include "para_rpc.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "../PluginContext.h"
#include "cryptocurrency.h"
#include "dllmain.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

using namespace std;

extern bool HandleGenesisBlockCb(vector<T_PAYLOADADDR>& vecPA);
extern bool PutChainCb();
extern bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA);
extern bool AcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>&, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest);
extern bool CheckChainCbWhenOnChaining(vector<T_PAYLOADADDR>& vecPA, uint32_t prevhid, T_SHA256& tprevhhash);
extern bool ValidateLedgerDataCb(T_PAYLOADADDR& payloadaddr, map<boost::any, T_LOCALBLOCKADDRESS>& mapOutPt, boost::any& hashPrevBlock);
extern bool BlockUUIDCb(string& payload, string& uuidpayload);
extern bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath);
extern bool GetNeighborNodes(list<string>& listNodes);

extern void ThreadGetNeighbourChkBlockInfo(void* parg);
extern void StartRPCServer();
extern void StopRPCServer();
extern void StartLightNodeWork(const string& server);
extern void FreeGlobalMemeory();

extern void StartMQHandler();
extern void StopMQHandler();

//HCE: SegWit
extern void SelectParams();
extern void RandomInit();
extern void ECC_Start();
extern void ECC_Stop();

void StopAllLightNodesWork();


static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;

CWallet* pwalletMain = nullptr;
bool fExit = true;
extern SeedServers g_seedserver;
extern ParaMQCenter paramqcenter;

string GetHyperChainDataDirInApp()
{
    string datapath;
    boost::filesystem::path pathDataDir;
    if (mapArgs.count("-datadir")) {
        pathDataDir = boost::filesystem::system_complete(mapArgs["-datadir"]);
        if (!boost::filesystem::exists(pathDataDir))
            if (!boost::filesystem::create_directories(pathDataDir)) {
                cerr << "can not create directory: " << pathDataDir << endl;
                pathDataDir = boost::filesystem::system_complete(".");
            }
    }
    else
        pathDataDir = boost::filesystem::system_complete(".");

    if (mapArgs.count("-model") && mapArgs["-model"] == "informal")
        pathDataDir /= "informal";
    else if (mapArgs.count("-model") && mapArgs["-model"] == "formal")
        pathDataDir /= "formal";
    else
        pathDataDir /= "sandbox";

    if (!boost::filesystem::exists(pathDataDir))
        boost::filesystem::create_directories(pathDataDir);

    return pathDataDir.string();
}

string CreateChildDir(const string& childdir)
{
    string log_path = GetHyperChainDataDirInApp();
    boost::filesystem::path logpath(log_path);
    logpath /= childdir;
    if (!boost::filesystem::exists(logpath)) {
        boost::filesystem::create_directories(logpath);
    }
    return logpath.string();
}

void ExitTimeout(void* parg)
{
#ifdef __WXMSW__
    Sleep(5000);
    ExitProcess(0);
#endif
}

string GetLockFile()
{
    return GetDataDir() + "/.lock";
}

static std::shared_ptr<boost::interprocess::file_lock> g_pLock;

//HC: 调用二次退出，第一次置位, 第二次执行全面退出
void StopApplication(bool isFirst)
{
    if (isFirst) {
        fShutdown = true;
        return;
    }

    fShutdown = true;
    Shutdown(nullptr);
}

bool IsStopped()
{
    return fShutdown || fExit;
}


void ShutdownExcludeRPCServer()
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::paracoin, 0, 0, 0));
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::paracoin,
            g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID()));
    }

    //HC: 模块unregistered后，才能stop MQ
    g_sys_interrupted = 1;

    if (g_pLock) {
        g_pLock->unlock();
    }

    fShutdown = true;
    nTransactionsUpdated++;
    StopAllLightNodesWork();
    StopMQHandler();
    DBFlush(false);
    StopNode(false);
    DBFlush(true);
    boost::filesystem::remove(GetPidFile());
    UnregisterWallet(pwalletMain);
    delete pwalletMain;
    pwalletMain = nullptr;

    //HCE: CRITICAL_BLOCK(cs_vNodes)
    //{
    vNodes.clear();
    //}
    //CreateThread(ExitTimeout, NULL);
    Sleep(50);

}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;
    bool fFirstThread;
    CRITICAL_BLOCK(cs_Shutdown)
    {
        fFirstThread = !fTaken;
        fTaken = true;
    }

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::paracoin, 0, 0, 0));
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::paracoin,
            g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID()));
    }

    //HC: 模块unregistered后，才能stop MQ
    g_sys_interrupted = 1;

    if (g_pLock) {
        g_pLock->unlock();
    }

    if (fFirstThread) {
        INFO_FL("Stopping Hyperchain Paracoin...\n");

        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            //HC: 获取cs_main锁，确保没有来自共识层的回调通知消息在处理链数据中, 否则可能会导致程序崩溃
            //HCE: Acquire cs_main locks to ensure that no callback notification messages from the consensus layer are in the processing chain data, otherwise it may cause the program to crash
        }
        StopAllLightNodesWork();
        StopRPCServer();
        nTransactionsUpdated++;
        DBFlush(false);
        StopNode();
        DBFlush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        //CreateThread(ExitTimeout, NULL);

        //HCE: To avoid deadlock, It is very important to select a position to stop MQ
        StopMQHandler();

        FreeGlobalMemeory();
        globalVerifyHandle.reset();
        ECC_Stop();

        Sleep(50);
        fExit = true;
    }
}

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

bool LoadCryptoCurrency()
{
    //HCE: which coin will be used?
    CApplicationSettings appini;
    string defaultAppHash;
    appini.ReadDefaultApp(defaultAppHash);

    string coinhash = GetArg("-coinhash", "");

    if (coinhash.empty()) {
        coinhash = defaultAppHash;
    }

    g_cryptoCurrency.SelectNetWorkParas();
    if (!CryptoCurrency::ContainCurrency(coinhash)) {

        cerr << strprintf("Invalid Cryptocurrency: %s\n", coinhash.c_str());
        ERROR_FL("Invalid Cryptocurrency: %s\n", coinhash.c_str());
        if (CryptoCurrency::ContainCurrency(defaultAppHash)) {
            coinhash = defaultAppHash;
        }
        else {
            //HCE: use built-in currency
            coinhash = g_cryptoCurrency.GetHashPrefixOfGenesis();
        }
    }

    if (defaultAppHash != coinhash) {
        appini.WriteDefaultApp(coinhash);
    }

    //HCE: load currency
    if (g_cryptoCurrency.GetHashPrefixOfGenesis() != coinhash) {

        string errmsg;
        if (!g_cryptoCurrency.ReadCoinFile("", coinhash, errmsg)) {
            return WARNING_FL("Not found cryptocurrency: %s", coinhash.c_str());
        }
    }
    hashGenesisBlock = g_cryptoCurrency.GetHashGenesisBlock();

    //HCE: change data directory
    string strLedgerDir = CreateChildDir(g_cryptoCurrency.GetCurrencyConfigPath());
    strlcpy(pszSetDataDir, strLedgerDir.c_str(), sizeof(pszSetDataDir));

    cout << strprintf("Current coin : %s %s [%u,%u,%u]\n",
        g_cryptoCurrency.GetName().c_str(),
        g_cryptoCurrency.GetHashPrefixOfGenesis().c_str(),
        g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());
    return true;
}


bool StartApplication(PluginContext* context)
{
    bool fRet = false;
    fShutdown = false;
    try {
        context->SetPluginContext();
        fRet = AppInit2(context->pc_argc, context->pc_argv);
        fExit = !fRet;
    }
    catch (std::exception& e) {
        PrintException(&e, "AppInit2()");
    }
    catch (...) {
        PrintException(NULL, "AppInit2()");
    }
    if (!fRet) {
        PrintException(NULL, "AppInit2(), Failed to start Paracoin");
        Shutdown(NULL);
    }

    return fRet;
}


bool AppInit2(int argc, char* argv[])
{
#ifdef _MSC_VER
    // Turn off microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, ctrl-c
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifndef __WXMSW__
    umask(077);
#endif
#ifndef __WXMSW__
    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
#endif

    AppParseParameters(argc, argv);
    ReadConfigFile(mapArgs, mapMultiArgs); // Must be done after processing datadir

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams();
    }
    catch (const std::exception& e) {
        fprintf(stderr, "Paracoin error: %s      \n", e.what());
        return false;
    }

    RandomInit();
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());


    fDebug = GetBoolArg("-debug");
    fAllowDNS = GetBoolArg("-dns");

#ifndef __WXMSW__
    fDaemon = GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running */
    fServer = true;

    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fPrintToDebugFile = GetBoolArg("-printtofile");

    fTestNet = GetBoolArg("-testnet");
    bool fTOR = (fUseProxy && addrProxy.port == htons(9050));
    fNoListen = GetBoolArg("-nolisten") || fTOR;
    fLogTimestamps = GetBoolArg("-logtimestamps");

    for (int i = 1; i < argc; i++)
        if (!IsSwitchChar(argv[i][0]))
            fCommandLine = true;

    if (fCommandLine) {
        int ret = CommandLineRPC(argc, argv);
        exit(ret);
    }

    NodeManager* mgr = Singleton<NodeManager>::getInstance();

    if (mgr->isSpecifySeedServer()) {
        vector<HCNodeSH>& seedss = mgr->seedServers();

        for (auto& seedser : seedss) {
            string seedserIP;
            int nport;
            if (seedser && seedser->getUDPAP(seedserIP, nport)) {
                g_seedserver.addServer(seedserIP, nport);

                if (g_seedserver.size() > 5) {
                    break;
                }
            }
        }
    }

    pro_ver = ProtocolVer::NET::SAND_BOX;
    if (mapArgs.count("-model") && mapArgs["-model"] == "informal")
        pro_ver = ProtocolVer::NET::INFORMAL_NET;

    //HCE: which coin will be used?
    LoadCryptoCurrency();

    if (!fDebug && !pszSetDataDir[0])
        ShrinkDebugFile();
    INFO_FL("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    INFO_FL("Hyperchain version %s\n", FormatFullVersion().c_str());

    if (GetBoolArg("-loadblockindextest")) {
        CTxDB_Wrapper txdb("r+");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    }

    // Make sure only a single bitcoin process is using the data directory.
    string strLockFile = GetLockFile();

    FILE* file = fopen(strLockFile.c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    g_pLock = make_shared<boost::interprocess::file_lock>(strLockFile.c_str());

    if (!g_pLock->try_lock()) {
        wxMessageBox(strprintf(_("Cannot obtain a lock on data directory %s. Paracoin is probably already running."), GetDataDir().c_str()), "Hyperchain");
        return false;
    }

    // Bind to the port early so we can tell if another instance is already running.
    string strErrors;
    //if (!fNoListen)
    //{
        //if (!BindListenPort(strErrors))
        //{
        //    wxMessageBox(strErrors, "Hyperchain");
        //    return false;
        //}
    //}

    //
    // Load data files
    //
    if (fDaemon)
        fprintf(stdout, "Paracoin server starting\n");
    strErrors = "";
    int64 nStart;

    INFO_FL("Loading addresses...\n");
    nStart = GetTimeMillis();
    if (!LoadAddresses())
        strErrors += _("Error loading addr.dat      \n");
    TRACE_FL(" addresses   %15" PRI64d " ms\n", GetTimeMillis() - nStart);

    //HCE:
    INFO_FL("Loading blocks will to do global buddy consensus...\n");
    LoadBlockUnChained();

    fprintf(stdout, "Loading block index...\n");
    nStart = GetTimeMillis();
    if (!LoadBlockIndex()) {
        fprintf(stderr, "Error loading blkindex.dat      \n");
        return false;
    }

    TRACE_FL(" block index %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    fprintf(stdout, "Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun;
    if (!pwalletMain) {
        pwalletMain = new CWallet("wallet.dat");
    }
    int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK) {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors += _("Error loading wallet.dat: Wallet corrupted      \n");
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors += _("Error loading wallet.dat: Wallet requires newer version of Paracoin      \n");
        else
            strErrors += _("Error loading wallet.dat      \n");
    }

    TRACE_FL(" wallet      %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    RegisterWallet(pwalletMain);
    CBlockIndexSP pindexRescan = pindexBest;
    if (GetBoolArg("-rescan"))
        pindexRescan = pindexGenesisBlock;
    else {
        CWalletDB_Wrapper walletdb("wallet.dat");
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    }
    if (pindexBest != pindexRescan) {
        //HC: 让钱包和最优链保持一致
        //HCE: Keep wallets consistent with optimal chains
        fprintf(stdout, "Para: Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);

        TRACE_FL(" rescan      %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    }

    TRACE_FL("Done loading\n");

    //// debug print
    TRACE_FL("mapBlockIndex.size() = %d\n", mapBlockIndex.size());

    TRACE_FL("nBestHeight = %d\n", nBestHeight);
    TRACE_FL("setKeyPool.size() = %d\n", pwalletMain->setKeyPool.size());
    TRACE_FL("mapWallet.size() = %d\n", pwalletMain->mapWallet.size());
    TRACE_FL("mapAddressBook.size() = %d\n", pwalletMain->mapAddressBook.size());

    if (!strErrors.empty()) {
        wxMessageBox(strErrors, "Paracoin", wxOK | wxICON_ERROR);
        return false;
    }

    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

    //
    // Parameters
    //
    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree")) {
        PrintBlockTree();
        return false;
    }

    if (mapArgs.count("-timeout")) {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    }

    if (mapArgs.count("-printblock")) {
        string strMatch = mapArgs["-printblock"];
        int nFound = 0;
        for (auto mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi) {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0) {
                auto pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    }

    fGenerateBitcoins = GetBoolArg("-gen");

    if (mapArgs.count("-proxy")) {
        fUseProxy = true;
        addrProxy = CAddress(mapArgs["-proxy"]);
        if (!addrProxy.IsValid()) {
            wxMessageBox(_("Invalid -proxy address"), "Paracoin");
            return false;
        }
    }

    if (mapArgs.count("-addnode")) {
        BOOST_FOREACH(string strAddr, mapMultiArgs["-addnode"])
        {
            CAddress addr(strAddr, fAllowDNS);
            addr.nTime = 0; // so it won't relay unless successfully connected
            if (addr.IsValid())
                AddAddress(addr);
        }
    }
    //HCE: remove dns seed
    //if (GetBoolArg("-nodnsseed"))
    //    printf("DNS seeding disabled\n");
    //else
    //    DNSAddressSeed();

    if (mapArgs.count("-paytxfee")) {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee)) {
            wxMessageBox(_("Invalid amount for -paytxfee=<amount>"), "Paracoin");
            return false;
        }
        if (nTransactionFee > 0.25 * COIN)
            wxMessageBox(_("Warning: -paytxfee is set very high.  This is the transaction fee you will pay if you send a transaction."), "Hyperchain", wxOK | wxICON_EXCLAMATION);
    }

    if (fHaveUPnP) {
#if USE_UPNP
        if (GetBoolArg("-noupnp"))
            fUseUPnP = false;
#else
        if (GetBoolArg("-upnp"))
            fUseUPnP = true;
#endif
    }

    if (!CheckDiskSpace())
        return false;

    RandAddSeedPerfmon();

    //HCE: Output my public key and put it into wallet
    if (mapArgs.count("-publickey")) {
        CReserveKey reservekey(pwalletMain);
        std::vector<unsigned char> vchPubKey = reservekey.GetReservedKey();
        cout << "PublicKey:" << ToHexString(vchPubKey) << endl;
        //HCE: Remove key from key pool
        reservekey.KeepKey();
        return 0;
    }


    //HCE: Register application callbacks,for example when a new block become onchained,one of callbacks is called.
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {

        CONSENSUSNOTIFY paracoinGenesisCallback =
            std::make_tuple(HandleGenesisBlockCb, nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);

        consensuseng->RegisterAppCallback(T_APPTYPE(APPTYPE::paracoin, 0, 0, 0), paracoinGenesisCallback);

        CONSENSUSNOTIFY paracoinCallback =
            std::make_tuple(nullptr, nullptr,
                PutChainCb,
                nullptr,
                nullptr,
                CheckChainCb,
                AcceptChainCb,
                CheckChainCbWhenOnChaining,
                nullptr,
                GetVPath,
                GetNeighborNodes);
        consensuseng->RegisterAppCallback(
            T_APPTYPE(APPTYPE::paracoin, g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID()),
            paracoinCallback);
        TRACE_FL("Registered Paracoin callback\n");
    }

    LatestHyperBlock::Sync();

    StartMQHandler();

    hc::CreateThread("StartNode", StartNode, NULL);

    if (fServer && !fRPCServerRunning) {
        StartRPCServer();
    }

    if (mapArgs.count("-getwork")) {
        BOOST_FOREACH(string strServer, mapMultiArgs["-getwork"])
        {
            StartLightNodeWork(strServer);
        }
    }


    hc::CreateThread("GetNeighbourChkBlockInfo", ThreadGetNeighbourChkBlockInfo, NULL);

    return true;
}

