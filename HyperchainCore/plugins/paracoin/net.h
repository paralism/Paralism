/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanyingggo
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H


#include <deque>
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#include <openssl/rand.h>


#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>

using namespace boost::multi_index;

#ifndef __WXMSW__
#include <arpa/inet.h>
#endif

#include "protocol.h"
#include "block.h"

class CAddrDB;
class CRequestTracker;
class CNode;
class CBlockIndex;
class CBlockLocatorEx;

template<class T>
class shared_ptr_proxy;

extern int nBestHeight;
extern int nConnectTimeout;

#if !defined CBlockIndexSP
using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;
#endif

//HCE: Amule is 1300 for a slice
inline unsigned int ReceiveBufferSize() { return 1000 * GetArg("-maxreceivebuffer", 60 * 1000); }
inline unsigned int SendBufferSize() { return 1000 * GetArg("-maxsendbuffer", 60 * 1000); }
static const unsigned int PUBLISH_HOPS = 5;

bool ConnectSocket(const CAddress& addrConnect, SOCKET& hSocketRet, int nTimeout = nConnectTimeout);
bool Lookup(const char* pszName, std::vector<CAddress>& vaddr, int nServices, int nMaxSolutions, bool fAllowLookup = false, int portDefault = 0, bool fAllowPort = false);
bool Lookup(const char* pszName, CAddress& addr, int nServices, bool fAllowLookup = false, int portDefault = 0, bool fAllowPort = false);
bool GetMyExternalIP(unsigned int& ipRet);
bool AddAddress(CAddress addr, int64 nTimePenalty = 0, CAddrDB* pAddrDB = NULL);
void AddressCurrentlyConnected(const CAddress& addr);
CNode* FindNode(unsigned int ip);
CNode* ConnectNode(CAddress addrConnect, int64 nTimeout = 0);
void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1);
bool AnySubscribed(unsigned int nChannel);
void MapPort(bool fMapPort);
void DNSAddressSeed();
bool BindListenPort(std::string &strError = REF(std::string()));
void StartNode(void* parg);
bool StopNode(bool isStopRPC = true);

enum
{
    MSG_TX = 1,
    MSG_BLOCK,
    MSG_BLOCKEX,    //HCE: reply type of "fgetblocks"
    MSG_BLOCKEX_R,  //HCE: reply type of "rgetblocks"
};

class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&);
    void* param1;

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&) = NULL, void* param1In = NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull()
    {
        return fn == NULL;
    }
};





extern bool fClient;
extern bool fAllowDNS;
extern uint64 nLocalServices;
extern CAddress addrLocalHost;
extern uint64 nLocalHostNonce;
extern boost::array<int, 10> vnThreadsRunning;

extern CCriticalSection cs_main;
extern std::vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern std::map<std::vector<unsigned char>, CAddress> mapAddresses;
extern CCriticalSection cs_mapAddresses;
extern std::map<CInv, CDataStream> mapRelay;
extern std::deque<std::pair<int64, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;

extern std::map<CInv, int64> mapAlreadyAskedFor;
extern CCriticalSection cs_mapAlreadyAskFor;

// Settings
extern int fUseProxy;
extern CAddress addrProxy;

struct ChkPointInc;
typedef struct ChkPoint
{
    int32 nChkPointHeight = 0;
    uint256 chkPointHash;
    int32 nBstH = 0;
    uint256 bestHash;
    CBlockLocatorEx chainloc;


    ChkPoint()
    { }

    static bool GetCurrent(ChkPoint &cp);
    void Merge(const ChkPointInc &cpincr);

    IMPLEMENT_SERIALIZE
    (
        //HCE: we can use parameter:nVersion to distinguish any change of type define
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(nChkPointHeight);
        READWRITE(chkPointHash);
        READWRITE(nBstH);
        READWRITE(bestHash);
        READWRITE(chainloc);
    )

    string ToString()
    {
        uint256 hash1 = chainloc.vHave.size() > 0 ? chainloc.vHave.back() : 0;

        return strprintf("chkpoint: %d(%s) best: %d(%s)",
            nChkPointHeight, chkPointHash.ToPreViewString().c_str(),
            nBstH, bestHash.ToPreViewString().c_str());
    }
} ChkPoint;

typedef struct ChkPointInc
{
    CBlockLocatorExIncr* blocklocincr;
    ChkPoint chkP;

    ChkPointInc(ChkPoint& chkp, CBlockLocatorExIncr* locincr) : chkP(chkp), blocklocincr(locincr)
    { }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(chkP.nChkPointHeight);
        READWRITE(chkP.chkPointHash);
        READWRITE(chkP.nBstH);
        READWRITE(chkP.bestHash);
        READWRITE(*blocklocincr);
    )
} ChkPointInc;



class CNode
{
public:
    // socket
    uint64 nServices;
    SOCKET hSocket;
    CDataStream vSend;
    CDataStream vRecv;
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    int64 nLastSend;
    int64 nLastRecv;
    int64 nLastSendEmpty;
    int64 nTimeConnected;
    //HCE: PushMessage(getchkblock) time
    int64 nLastGetchkblk = 0;
    unsigned int nHeaderStart;
    unsigned int nMessageStart;
    CAddress addr;
    int nVersion;
    std::string strSubVer;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    std::string nodeid;

    //HC: 节点应答速率，值越大越好
    int64 m_rating = 0;

    //HC: 单位ms
    //HCE: Unit is ms
    deque<int> networkPingPongCost = {-1, -1, -1};
    uint nPingTimes = 0;
    uint nPingPongTimes = 0;
    int64 tmLastPing = 0;
    int64 tmLastPong = 0;

    void SetRating(int64 rating) {
        m_rating = rating;
    }

    int64 GetRating() const {
        return m_rating;
    }

    void UpdateNodeRating(int _r) {
        m_rating += _r;
    };

    //HC：发起ping
    void Ping();
    void Pong(int64 tmReq);
    string PingPongInfo();


    vector<CInv> vfgetblocksInv;
    set<uint256> setfgetblocksInv;

    //HC: 最后一次收到块清单时间
    //HCE: The last time the block inventory was received
    time_t tmlastrecvfgetblock = 0;

    CInv fgetInvContinue;
    time_t tmlastfget = 0;
    uint256 hashlastfget;
    int nfgetRetry = 0;
    int nfAskFor = 0;

    enum class GetFBlocksState : char
    {
        PullingInventory,
        PullingBlocks,
        Completed,
    };

    GetFBlocksState OnGetFBlocksCompleted(int &nHaving, vector<CInv>& vecHaveNot);
    int64 FPullBlocks(const uint256 &hashfork);
    void FPullBlockReached(const CInv &inv);

    bool IsNotHavingInvReply()
    {
        if (nfgetRetry >= 3 && hashlastfget == fgetInvContinue.hash) {
            return true;
        }
        return false;
    }

    time_t tmlastProcessRecv = 0;

private:
    //HC: 最近一次同步区块所用参数
    uint256 lasthashfork;
    uint256 lastInvContinue;
    uint256 lasthash;

protected:
    int nRefCount;
public:
    int64 nReleaseTime;
    std::map<uint256, CRequestTracker> mapRequests;
    CCriticalSection cs_mapRequests;
    uint256 hashContinue;
    CBlockIndexSP pindexLastGetBlocksBegin;
    uint256 hashLastGetBlocksEnd;
    time_t tmRequest = 0;
    int nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    std::set<CAddress> setAddrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;

    // inventory based relay
    std::set<CInv> setInventoryKnown;
    std::vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;


    struct AskFor {
        int64 tmaskfor;
        CInv inv;
    };

    typedef boost::multi_index::multi_index_container<
        AskFor, indexed_by<
            hashed_non_unique<member<AskFor, int64, &AskFor::tmaskfor>>,
            hashed_unique<member<AskFor, CInv, &AskFor::inv>>
        >
    > askfor_multi_index;
    askfor_multi_index mapAskFor;

    CCriticalSection cs_askfor;

    // publish and subscription
    std::vector<char> vfSubscribe;

    //HCE:
    std::map<uint256, std::tuple<int64, uint256>> mapBlockSent;
    std::list<decltype(mapBlockSent.begin())> listBlockSent;

    //HCE:
    ChkPoint chkpoint;

    int64 tmlastgotchkp = 0;

    CNode(SOCKET hSocketIn, CAddress addrIn, bool fInboundIn = false) : nodeid("")
    {
        nServices = 0;
        hSocket = hSocketIn;
        vSend.SetType(SER_NETWORK);
        vSend.SetVersion(0);
        vRecv.SetType(SER_NETWORK);
        vRecv.SetVersion(0);
        // Version 0.2 obsoletes 20 Feb 2012
        if (GetTime() > 1329696000)
        {
            vSend.SetVersion(209);
            vRecv.SetVersion(209);
        }
        nLastSend = 0;
        nLastRecv = 0;
        nLastSendEmpty = GetTime();
        nTimeConnected = GetTime();
        nHeaderStart = -1;
        nMessageStart = -1;
        addr = addrIn;
        nVersion = 0;
        strSubVer = "";
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fSuccessfullyConnected = false;
        fDisconnect = false;
        nRefCount = 0;
        nReleaseTime = 0;
        hashContinue = 0;
        hashLastGetBlocksEnd = 0;
        nStartingHeight = -1;
        fGetAddr = false;
        vfSubscribe.assign(256, false);

        // Be shy and don't send version until we hear
        if (!fInbound)
            PushVersion();
    }

    ~CNode()
    {
        if (hSocket != INVALID_SOCKET)
        {
            closesocket(hSocket);
            hSocket = INVALID_SOCKET;
        }
    }

private:
    CNode(const CNode&);
    void operator=(const CNode&);

    //HC：从孤块集合中寻找不再孤立的合适块延伸最优链
    void MakeChainLonger(const CInv& inv);

public:

    void PushChkBlock();

    int GetRefCount()
    {
        return std::max(nRefCount, 0) + (GetTime() < nReleaseTime ? 1 : 0);
    }

    CNode* AddRef(int64 nTimeout = 0)
    {
        if (nTimeout != 0)
            nReleaseTime = std::max(nReleaseTime, GetTime() + nTimeout);
        else
            nRefCount++;
        return this;
    }

    void Release()
    {
        nRefCount--;
    }



    void AddAddressKnown(const CAddress& addr)
    {
        setAddrKnown.insert(addr);
    }

    void PushAddress(const CAddress& addr)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (addr.IsValid() && !setAddrKnown.count(addr))
            vAddrToSend.push_back(addr);
    }


    void AddInventoryKnown(const CInv& inv)
    {
        //HCE: do nothing
        return;
        CRITICAL_BLOCK(cs_inventory)
            setInventoryKnown.insert(inv);
    }

    void PushInventory(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
        {
            //HCE: Don't put into setInventoryKnown
            //if (!setInventoryKnown.count(inv))
            vInventoryToSend.push_back(inv);
        }
    }

    void ClearGot(const vector<CInv>& vfgot)
    {
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            for (auto& inv : vfgot) {
                mapAlreadyAskedFor.erase(inv);
            }
    }

    bool AskForF(const CInv& inv)
    {
        if (AskFor(inv)) {
            nfAskFor++;
            return true;
        }
        return false;
    }

    static bool AlreadyAskFor(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            if (mapAlreadyAskedFor.find(inv) != mapAlreadyAskedFor.end()) {
                if (GetTime() * 1000000 < mapAlreadyAskedFor[inv] + 2 * 60 * 1000000) {
                    //Request have sent in the past of 2 minutes
                    return true;
                }
            }
        return false;
    }

    bool AskingFor(const CInv& inv)
    {
        auto& inv_index = mapAskFor.get<1>();
        CRITICAL_BLOCK(cs_askfor)
            if (inv_index.find(inv) != inv_index.end()) {
                return true;
            }
        return false;
    }


    bool AskFor(const CInv& inv)
    {
        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent

        if (AskingFor(inv) || AlreadyAskFor(inv)) {
            return false;
        }

        int64 nRequestTime;
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            nRequestTime = mapAlreadyAskedFor[inv];

        // Make sure not to reuse time indexes to keep things in the same order
        int64 nNow = (GetTime() - 1) * 1000000;
        static int64 nLastTime = 0;
        nLastTime = nNow = std::max(nNow, ++nLastTime);

        // Each retry is 2 minutes after the last
        nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);

        TRACE_FL("ask %s(%u) for %s   %" PRI64d "\n",
            addr.ToString().c_str(), mapAskFor.size(),
            inv.ToString().c_str(), nRequestTime);

        CRITICAL_BLOCK(cs_askfor)
            //mapAskFor.insert(std::make_pair(nRequestTime, inv));
            mapAskFor.insert({nRequestTime, inv});
        return true;
    }



    void BeginMessage(const char* pszCommand)
    {
        cs_vSend.Enter("cs_vSend", __FILE__, __LINE__);
        if (nHeaderStart != -1)
            AbortMessage();
        nHeaderStart = vSend.size();
        vSend << CMessageHeader(pszCommand, 0);
        nMessageStart = vSend.size();
        TRACE_FL("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
        TRACE_FL("sending: %s ", pszCommand);
    }

    void AbortMessage()
    {
        if (nHeaderStart == -1)
            return;
        vSend.resize(nHeaderStart);
        nHeaderStart = -1;
        nMessageStart = -1;
        cs_vSend.Leave();

        TRACE_FL("(aborted)\n");
    }

    void EndMessage()
    {
        if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
        {
            TRACE_FL("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nHeaderStart == -1)
            return;

        // Set the size
        unsigned int nSize = vSend.size() - nMessageStart;
        memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));

        // Set the checksum
        if (vSend.GetVersion() >= 209)
        {
            uint256 hash = Hash(vSend.begin() + nMessageStart, vSend.end());
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            assert(nMessageStart - nHeaderStart >= offsetof(CMessageHeader, nChecksum) + sizeof(nChecksum));
            memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nChecksum), &nChecksum, sizeof(nChecksum));
        }

        TRACE_FL("(%d bytes)\n", nSize);
        nHeaderStart = -1;
        nMessageStart = -1;
        cs_vSend.Leave();
    }

    void EndMessageAbortIfEmpty()
    {
        if (nHeaderStart == -1)
            return;
        int nSize = vSend.size() - nMessageStart;
        if (nSize > 0)
            EndMessage();
        else
            AbortMessage();
    }



    void PushVersion()
    {
        /// when NTP implemented, change to just nTime = GetAdjustedTime()
        int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());
        CAddress addrYou = (fUseProxy ? CAddress("0.0.0.0") : addr);
        CAddress addrMe = (fUseProxy ? CAddress("0.0.0.0") : addrLocalHost);
        RAND_bytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
        PushMessage("version", VERSION, nLocalServices, nTime, addrYou, addrMe,
            nLocalHostNonce, std::string(pszSubVer), nBestHeight);
    }



    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename... Args>
    void PushMessage(const char* pszCommand, const Args&... args)
    {
        try {
            BeginMessage(pszCommand);
            int arr[] = { (vSend << args, 0)... };
            (void)(arr);
            EndMessage();
        }
        catch (...) {
            AbortMessage();
            throw;
        }
    }


    void PushRequest(const char* pszCommand,
        void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char* pszCommand, const T1& a1,
        void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char* pszCommand, const T1& a1, const T2& a2,
        void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1, a2);
    }



    void PushGetBlocks(CBlockIndexSP pindexBegin, uint256 hashEnd);
    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops = 0);
    void CancelSubscribe(unsigned int nChannel);
    void CloseSocketDisconnect();
    void Cleanup();
};










inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
            pnode->PushInventory(inv);
}

template<typename T>
void RelayMessage(const CInv& inv, const T& a)
{
    CDataStream ss(SER_NETWORK);
    ss.reserve(10000);
    ss << a;
    RelayMessage(inv, ss);
}

template<>
inline void RelayMessage<>(const CInv& inv, const CDataStream& ss)
{
    CRITICAL_BLOCK(cs_mapRelay)
    {
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay[inv] = ss;
        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}








//
// Templates for the publish and subscription system.
// The object being published as T& obj needs to have:
//   a set<unsigned int> setSources member
//   specializations of AdvertInsert and AdvertErase
// Currently implemented for CTable and CProduct.
//

template<typename T>
void AdvertStartPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Add to sources
    obj.setSources.insert(pfrom->addr.ip);

    if (!AdvertInsert(obj))
        return;

    // Relay
    CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("publish", nChannel, nHops, obj);
}

template<typename T>
void AdvertStopPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    uint256 hash = obj.GetHash();

    CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("pub-cancel", nChannel, nHops, hash);

    AdvertErase(obj);
}

template<typename T>
void AdvertRemoveSource(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Remove a source
    obj.setSources.erase(pfrom->addr.ip);

    // If no longer supported by any sources, cancel it
    if (obj.setSources.empty())
        AdvertStopPublish(pfrom, nChannel, nHops, obj);
}


typedef map<T_APPTYPE, vector<T_PAYLOADADDR>> M_APP_PAYLOADADDR;
typedef struct tagCHAINCBDATA
{
    tagCHAINCBDATA(const M_APP_PAYLOADADDR& m, uint32_t hidFork, uint32_t hid, const T_SHA256& thhash, bool isLatest) :
        m_mapPayload(m), m_hidFork(hidFork), m_hid(hid), m_thhash(thhash), m_isLatest(isLatest)
    {
    }

    M_APP_PAYLOADADDR m_mapPayload;
    uint32_t m_hidFork;
    uint32_t m_hid;
    T_SHA256 m_thhash;
    bool m_isLatest;
} CHAINCBDATA;

class HyperBlockMsgs
{
public:
    void insert(CHAINCBDATA&& cb);
    void process();
    size_t size();
private:
    CCriticalSection m_cs_list;
    std::list<CHAINCBDATA> m_list;
};


class NodesCopy
{
public:
    NodesCopy(vector<CNode*>& vCopy) : _vNodesCopy(vCopy)
    {
        CRITICAL_BLOCK(cs_vNodes)
        {
            _vNodesCopy = vNodes;
            BOOST_FOREACH(CNode * pnode, _vNodesCopy)
                pnode->AddRef();
        }
    }
    ~NodesCopy()
    {
        Release();
    }

    void Release()
    {
        if (!isReleased) {
            CRITICAL_BLOCK(cs_vNodes)
            {
                BOOST_FOREACH(CNode * pnode, _vNodesCopy)
                    pnode->Release();
            }
        }
        isReleased = true;
    }

private:
    vector<CNode*>& _vNodesCopy;
    bool isReleased = false;
};

#endif
