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
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "bignum.h"
#include "net.h"
#include "key.h"
#include "script.h"
#include "db.h"
#include "util.h"

#include "block.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "headers/inter_public.h"


#include <list>

class CBlock;
class CBlockIndex;
class CWalletTx;
class CWallet;
class CKeyItem;
class CReserveKey;
class CWalletDB;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;


#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif

extern CCriticalSection cs_main;

extern uint256 hashGenesisBlock;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern int fLimitProcessors;
extern int nLimitProcessors;
extern int fMinimizeToTray;
extern int fMinimizeOnClose;
extern int fUseUPnP;

class CReserveKey;
class CTxDB;
class CTxIndex;
class CBlockIndexSimplified;

CBlockIndex* LatestBlockIndexOnChained();
void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
bool CheckDiskSpace(uint64 nAdditionalBytes = 0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode = "rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew = true);
bool LoadBlockUnChained();
void PrintBlockTree();
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
CBlock* CreateNewBlock(CReserveKey& reservekey);
bool CommitChainToConsensus(vector<CBlock>& vblock, string& requestid, string& errmsg);

CBlockSP CreateInitBlock(uint64 amount, const CBitcoinAddress& address);
bool CommitGenesisToConsensus(CBlock* pblock, std::string& requestid, std::string& errmsg);

void IncrementExtraNonce(CBlock* pblock, unsigned int& nExtraNonce);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
int GetTotalBlocksEstimate();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);

bool ProcessBlockWithTriaddr(CNode* pfrom, CBlock* pblock, BLOCKTRIPLEADDRESS* pblockaddr);

bool GetWalletFile(CWallet* pwallet, std::string& strWalletFileOut);
bool GetBlockData(const uint256& hashBlock, CBlock& block, BLOCKTRIPLEADDRESS& addrblock, char** pWhere);

template<typename T>
bool WriteSetting(const std::string& strKey, const T& value)
{
    bool fOk = false;
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
    {
        std::string strWalletFile;
        if (!GetWalletFile(pwallet, strWalletFile))
            continue;
        fOk |= CWalletDB(strWalletFile).WriteSetting(strKey, value);
    }
    return fOk;
}


//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock);

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
    READWRITE(vHave);
    )

        void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(hashGenesisBlock);
    }

    int GetDistanceBack();

    CBlockIndex* GetBlockIndex();

    uint256 GetBlockHash();

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->Height();
    }
};

//
// Alerts are for notifying old versions if they become too obsolete and
// need to upgrade.  The message is displayed in the status bar.
// Alert messages are broadcast as a vector of signed data.  Unserializing may
// not read the entire buffer if the alert is for a newer version, but older
// versions can still relay the original data.
//
class CUnsignedAlert
{
public:
    int nVersion;
    int64 nRelayUntil;      // when newer nodes stop relaying to newer nodes
    int64 nExpiration;
    int nID;
    int nCancel;
    std::set<int> setCancel;
    int nMinVer;            // lowest version inclusive
    int nMaxVer;            // highest version inclusive
    std::set<std::string> setSubVer;  // empty matches all
    int nPriority;

    // Actions
    std::string strComment;
    std::string strStatusBar;
    std::string strReserved;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
    nVersion = this->nVersion;
    READWRITE(nRelayUntil);
    READWRITE(nExpiration);
    READWRITE(nID);
    READWRITE(nCancel);
    READWRITE(setCancel);
    READWRITE(nMinVer);
    READWRITE(nMaxVer);
    READWRITE(setSubVer);
    READWRITE(nPriority);

    READWRITE(strComment);
    READWRITE(strStatusBar);
    READWRITE(strReserved);
    )

        void SetNull()
    {
        nVersion = 1;
        nRelayUntil = 0;
        nExpiration = 0;
        nID = 0;
        nCancel = 0;
        setCancel.clear();
        nMinVer = 0;
        nMaxVer = 0;
        setSubVer.clear();
        nPriority = 0;

        strComment.clear();
        strStatusBar.clear();
        strReserved.clear();
    }

    std::string ToString() const
    {
        std::string strSetCancel;
        BOOST_FOREACH(int n, setCancel)
            strSetCancel += strprintf("%d ", n);
        std::string strSetSubVer;
        BOOST_FOREACH(std::string str, setSubVer)
            strSetSubVer += "\"" + str + "\" ";
        return strprintf(
            "CAlert(\n"
            "    nVersion     = %d\n"

            "    nRelayUntil  = %" PRI64d "\n"
            "    nExpiration  = %" PRI64d "\n"
            "    nID          = %d\n"
            "    nCancel      = %d\n"
            "    setCancel    = %s\n"
            "    nMinVer      = %d\n"
            "    nMaxVer      = %d\n"
            "    setSubVer    = %s\n"
            "    nPriority    = %d\n"
            "    strComment   = \"%s\"\n"
            "    strStatusBar = \"%s\"\n"
            ")\n",
            nVersion,
            nRelayUntil,
            nExpiration,
            nID,
            nCancel,
            strSetCancel.c_str(),
            nMinVer,
            nMaxVer,
            strSetSubVer.c_str(),
            nPriority,
            strComment.c_str(),
            strStatusBar.c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CAlert : public CUnsignedAlert
{
public:
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAlert()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
    READWRITE(vchSig);
    )

        void SetNull()
    {
        CUnsignedAlert::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (nExpiration == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsInEffect() const
    {
        return (GetAdjustedTime() < nExpiration);
    }

    bool Cancels(const CAlert& alert) const
    {
        if (!IsInEffect())
            return false; // this was a no-op before 31403
        return (alert.nID <= nCancel || setCancel.count(alert.nID));
    }

    bool AppliesTo(int nVersion, std::string strSubVerIn) const
    {
        return (IsInEffect() &&
            nMinVer <= nVersion && nVersion <= nMaxVer &&
            (setSubVer.empty() || setSubVer.count(strSubVerIn)));
    }

    bool AppliesToMe() const
    {
        return AppliesTo(VERSION, ::pszSubVer);
    }

    bool RelayTo(CNode* pnode) const
    {
        if (!IsInEffect())
            return false;
        // returns true if wasn't already contained in the set
        if (pnode->setKnown.insert(GetHash()).second)
        {
            if (AppliesTo(pnode->nVersion, pnode->strSubVer) ||
                AppliesToMe() ||
                GetAdjustedTime() < nRelayUntil)
            {
                pnode->PushMessage("alert", *this);
                return true;
            }
        }
        return false;
    }

    bool CheckSignature()
    {
        CKey key;
        if (!key.SetPubKey(ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284")))
            return ERROR_FL("SetPubKey failed");
        if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
            return ERROR_FL("verify signature failed");

        // Now unserialize the data
        CDataStream sMsg(vchMsg);
        sMsg >> *(CUnsignedAlert*)this;
        return true;
    }

    bool ProcessAlert();
};

class PBFT
{
public:
    PBFT();
    ~PBFT();

    void Init();

    //HC: Pre-prepare phase, 执行至少2个区块，产生签名，并将签名后的区块广播给所有共识节点
    bool Preprepare(vector<CBlock>&& vblock);

    //HC: Prepare phase, 负责收集签名包，某节点收集满2 * _f + 1的签名包后，表明自身达到可以提交区块的状态
    bool Prepare(int pkidx, const vector<unsigned char>& vchSig);

    //HC: 节点收集满2 * _f + 1后，等待共识层通知到来，将本地缓存的最新区块提交到共识层
    bool Commit();

    bool IsSignEnough()
    {
        //HC: must add myself，so should be (2 * _f + 1 - 1)
        return _s_verified.size() >= (2 * _f + 1 - 1);
    }

private:
    size_t _f;
    size_t _n;
    vector<CBlock> _vblock;
    std::set<size_t> _s_verified;
    bool _waitforcommit = false;
};

extern PBFT g_PBFT;
#endif
