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

#include "cryptopp/sha.h"
#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"
#include "node/NodeManager.h"
#include "node/defer.h"

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "random.h"
#include "dllmain.h"
#include "key_io.h"

#include "cryptocurrency.h"
#include "utilc.h"

#include <random>
#include <algorithm>
#include <stack>


#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <cstdio>

#define COST_PARSE

using namespace std;
using namespace boost;

#ifdef WIN32
//#include "E:/Visual_Leak_Detector/include/vld.h"
//#pragma comment(lib, "vld.lib")
#endif

//
// Global state
//
CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

//HCE: blocks will do global consensus
CBlockCacheLocator mapBlocks;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;

//HC: 用于代替交易功能
//HCE: Used in place of trading functions
map<COutPoint, CInPoint> mapNextTx;

//CCacheLocator<CBlockIndex, CTxDB_Wrapper> mapBlockIndex;
CCacheLocator<CTxDB_Wrapper> mapBlockIndex;

ParaMQCenter paramqcenter;

//map<uint256, CBlockIndex*> mapBlockIndex;

//HCE: The following is target.
uint256 hashGenesisBlock;

//static CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 4);
const int nTotalBlocksEstimate = 0;     //HCE: Conservative estimate of total nr of blocks on main chain
const int nInitialBlockThreshold = 30;  //HCE: Regard blocks up until N-threshold as "initial download"
CBlockIndexSP pindexGenesisBlock;
int nBestHeight = -1;
CBigNum bnBestChainWork = 0;
CBigNum bnBestInvalidWork = 0;
uint256 hashBestChain = 0;

CBlockIndexSP pindexBest;

int64 nTimeBestReceived = 0;

map<uint256, CBlockSP> mapOrphanBlocks;
multimap<uint256, CBlockSP> mapOrphanBlocksByPrev;

map<uint256, CDataStream*> mapOrphanTransactions;
multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;


double dHashesPerSec;
int64 nHPSTimerStart;

// Settings
int fGenerateBitcoins = false;
int64 nTransactionFee = 0;
int fLimitProcessors = false;
int nLimitProcessors = 1;
int fMinimizeToTray = true;
int fMinimizeOnClose = true;
#if USE_UPNP
int fUseUPnP = true;
#else
int fUseUPnP = false;
#endif

static CCriticalSection cs_cpRefresh;
ChkPoint mychkp;

MiningCondition g_miningCond;
extern HyperBlockMsgs hyperblockMsgs;

std::atomic_bool g_isBuiltInBlocksReady{ false };


void RequestBlockSpace(CNode* pfrom);
extern void CheckBlockIndex(CTxDB* txdb);
extern bool SwitchChainToBlock(CBlock& block, CBlockIndexSP pindexBlock);
extern bool SwitchChainTo(CBlockIndexSP pindexBlock);
extern void RSyncRemotePullHyperBlock(uint32_t starthid, uint32_t endhid, string nodeid = "");

extern void outputlog(const string& msg);

uint32_t LatestHyperBlock::_hid  = 0;
uint256 LatestHyperBlock::_hhash = 0;
CCriticalSection LatestHyperBlock::_cs_latestHyperBlock;

bool GetBlockData(const uint256& hashBlock, CBlock& block, BLOCKTRIPLEADDRESS& addrblock, char** pWhere);

//HCE: convert uint256 to T_SHA256
T_SHA256 to_T_SHA256(const uint256 &uhash)
{
    unsigned char tmp[DEF_SHA256_LEN];
    memcpy(tmp, uhash.begin(), DEF_SHA256_LEN);
    std::reverse(std::begin(tmp), std::end(tmp));

    return T_SHA256(tmp);
}

uint256 to_uint256(const T_SHA256 &hash)
{
    return uint256S(hash.toHexString());
}

bool isInformalNetwork()
{
    string model = "sandbox";
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "informal") {
            return true;
        }
    }
    return false;
}

bool isFormalNetwork()
{
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "formal") {
            return true;
        }
    }
    return false;
}

bool isSandboxNetwork()
{
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "sandbox") {
            return true;
        }
        return false;
    }
    return true;
}

//HC: 如何判断para块在超块链上, 最可靠的办法是hash比对
//HCE: How to determine that the para block is on the Hyperchain, the most reliable way is hash comparison
CBlockIndexSP LatestBlockIndexOnChained()
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    CBlockIndexSP pIndex = pindexBest;
    while (pIndex) {
        if (pIndex->triaddr.isValid()) {
            if(hyperchainspace->CheckHyperBlockHash(pIndex->triaddr.hid, to_T_SHA256(pIndex->triaddr.hhash), true)) {
                return pIndex;
            } else {
                INFO_FL("CheckHyperBlockHash cannot pass: %d(%s) (Triaddr: %s)", pIndex->nHeight, pIndex->hashBlock.ToPreViewString().c_str(),
                    pIndex->triaddr.ToString().c_str());
            }
        } else if(pIndex->triaddr.ToAddr().isValid()){
            CBlock block;
            if (block.ReadFromDisk(pIndex->triaddr)) {
                if (block.GetHash() == pIndex->GetBlockHash()) {
                    //HCE: To be done: need to update pIndex triaddr,but how to simplify to get hhash?
                    return pIndex;
                }
            }
        }
        pIndex = pIndex->pprev();
    }

    if (!pIndex) {
        pIndex = pindexGenesisBlock;
    }
    return pIndex;
}

void RegisterWallet(CWallet* pwalletIn)
{
    CRITICAL_BLOCK(cs_setpwalletRegistered)
    {
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    CRITICAL_BLOCK(cs_setpwalletRegistered)
    {
        setpwalletRegistered.erase(pwalletIn);
    }
}

bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx, wtx))
            return true;
    return false;
}

void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}

void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

void static ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}


//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void static AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return;
    CDataStream* pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
            mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);)
        {
            if ((*mi).second == pvMsg)
                mapOrphanTransactionsByPrev.erase(mi++);
            else
                mi++;
        }
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}


//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

std::string CTransaction::ToString() const
{
    uint256 hash = GetHash();
    string strTxHash = hash.ToString();
    TRY_CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        if (pwalletMain->mapWallet.count(hash)) {
            strTxHash += "(mine)";
        }
        else {
            strTxHash += "(other)";
        }
    }
    std::string str;
    str += strprintf("CTransaction hash=%s\n"
        "\tver=%d, vin.size=%d, vout.size=%d, nLockTime=%d\n",
        strTxHash.c_str(),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (size_t i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    //for (const auto& tx_in : vin)
    //    str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (size_t i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

//bool CTransaction::ReadFromDisk(CDiskTxPos pos)
//{
//    string payload;
//    if (pos.addr.isValid()) {
//        //HCE: Read data from chain space
//        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
//
//        if (!hyperchainspace->GetLocalBlockPayload(pos.addr, payload)) {
//            DEBUG_FL("block(%s) isn't found in my local storage", pos.addr.tostring().c_str());
//            return false;
//        }
//    }
//    else {
//        //HCE: Alternative way is calling SearchTxInTransactions()
//        //HCE: Read data from block cache
//        CBlockIndexSP pIndex = pindexBest;
//        bool tx_ok = false;
//        while (pIndex && pIndex->nHeight >= pos.nHeight) {
//            if (pIndex->nHeight == pos.nHeight) {
//                CBlockDB_Wrapper blockdb;
//                uint256 hash;
//                blockdb.LoadBlockUnChained(pIndex->hashBlock, [&payload, &hash](CDataStream& ssKey, CDataStream& ssValue) -> bool {
//                    payload = ssValue.str();
//                    ssKey >> hash;
//                    return false; //HCE: break from load loop
//                });
//
//                if (hash == pIndex->hashBlock) {
//                    tx_ok = true;
//                }
//                break;
//            }
//            pIndex = pIndex->pprev();
//        }
//        if (!tx_ok)
//            return ERROR_FL("Tx(%d, %d) isn't found in my local storage", pos.nHeight, pos.nTxPos);
//    }
//
//    try {
//        CAutoBuffer autobuff(std::move(payload));
//        autobuff.seekg(pos.nTxPos);
//        autobuff >> *this;
//    }
//    catch (std::ios_base::failure& e) {
//        return ERROR_FL("CTransaction::ReadFromDisk() : %s", e.what());
//    }
//    return true;
//}

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
    //HCE: Alternative way is calling SearchTxInTransactions()
    CBlock block;
    BLOCKTRIPLEADDRESS addrblock;
    char* pWhere = nullptr;
    if (!GetBlockData(pos.hashBlk, block, addrblock, &pWhere)) {
        return ERROR_FL("Tx(%d(%s), %d) isn't found in my local storage",
            pos.nHeightBlk,
            pos.hashBlk.ToPreViewString().c_str(), pos.nTxPos);
    }

    try {
        //CAutoBuffer autobuff;
        CDataStream autobuff;
        autobuff << block;
        autobuff.ignore(pos.nTxPos);
        //autobuff.seekg(pos.nTxPos);
        autobuff >> *this;
    }
    catch (std::ios_base::failure & e) {
        return ERROR_FL("CTransaction::ReadFromDisk() : %s", e.what());
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient) {
        if (hashBlock == 0)
            return 0;
    }
    else {
        CBlock blockTmp;
        if (pblock == NULL) {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB_Wrapper().ReadTxIndex(GetHash(), txindex))
                return 0;

            BLOCKTRIPLEADDRESS addrblock;
            char* pWhere = nullptr;
            if(!GetBlockData(txindex.pos.hashBlk, blockTmp, addrblock, &pWhere))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;

        if (nIndex == pblock->vtx.size()) {
            vMerkleBranch.clear();
            nIndex = -1;
            WARNING_FL("couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    auto mi = mapBlockIndex[hashBlock];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}


bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return ERROR_FL("vin empty");
    if (vout.empty())
        return ERROR_FL("vout empty");
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
        return ERROR_FL("size limits failed");

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (txout.nValue < 0)
            return ERROR_FL("txout.nValue negative");
        if (txout.nValue > MAX_MONEY)
            return ERROR_FL("txout.nValue too high");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return ERROR_FL("txout total out of range");
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return ERROR_FL("prevout is null");
    }

    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction()) {
        m_strRunTimeErr = "CheckTransaction failed";
        return ERROR_FL("%s", m_strRunTimeErr.c_str());
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase()) {
        m_strRunTimeErr = "coinbase as individual tx";
        return ERROR_FL("%s", m_strRunTimeErr.c_str());
    }

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)nLockTime > INT_MAX) {
        m_strRunTimeErr = "not accepting nLockTime beyond 2038 yet";
        return ERROR_FL("%s", m_strRunTimeErr.c_str());
    }

    // Safety limits
    int nSize = static_cast<int>(::GetSerializeSize(*this, SER_NETWORK));
    // Checking ECDSA signatures is a CPU bottleneck, so to avoid denial-of-service
    // attacks disallow transactions with more than one SigOp per 34 bytes.
    // 34 bytes because a TxOut is:
    //   20-byte address + 8 byte bitcoin amount + 5 bytes of ops + 1 byte script length
    if (GetSigOpCount() > nSize / 34 || nSize < 100) {
        //return ERROR_FL("nonstandard transaction");
        m_strRunTimeErr = "nonstandard transaction";
        return ERROR_FL("%s", m_strRunTimeErr.c_str());
    }

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !IsStandard()) {
        m_strRunTimeErr = "nonstandard transaction type";
        return ERROR_FL("%s", m_strRunTimeErr.c_str());
    }

    // Do we already have it?
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash)) {
            m_strRunTimeErr = "already exist in transaction pool";
            return ERROR_FL("%s", m_strRunTimeErr.c_str());
        }
    if (fCheckInputs)
        if (txdb.ContainsTx(hash)) {
            m_strRunTimeErr = "already exist in transaction cache";
            return ERROR_FL("%s", m_strRunTimeErr.c_str());
        }

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            m_strRunTimeErr = " conflicts with in-memory transactions";
            return ERROR_FL("%s", m_strRunTimeErr.c_str());

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!IsNewerThan(*ptxOld))
                return false;
            for (int i = 0; i < vin.size(); i++)
            {
                COutPoint outpoint = vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        // Check against previous transactions
        map<uint256, std::tuple<CTxIndex, CTransaction>> mapUnused;
        map<uint256, CCrossChainTxIndex> mapCCUnused;
        int64 nFees = 0;
        string strErr;
        if (!ConnectInputs(txdb, mapUnused, mapCCUnused, CDiskTxPos(1), pindexBest, nFees, false, false, 0, &strErr))
        {
            if (pfMissingInputs)
                *pfMissingInputs = true;
            m_strRunTimeErr = "ConnectInputs failed: " + strErr;
            return ERROR_FL("%s", m_strRunTimeErr.c_str());
        }

        // Don't accept it if it can't get into a block
        int64 nMinFee = GetMinFee(1000, true, true);
        if (nFees < nMinFee) {
            //HC:  1 mPara = 1000 uPara 微，nMinFee和nFees用的是最小的单位聪: 10^8，  1 uPara = 100聪
            //HCE: 1 mPara = 1000 uPara micro, nMinFee and nFees use the smallest unit satoshi: 10^8, 1 uPara = 100 satoshis

            m_strRunTimeErr = strprintf("not enough fees, at least %" PRI64d ", but provide %" PRI64d, nMinFee, nFees);
            return ERROR_FL("%s", m_strRunTimeErr.c_str());
        }

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make other's transactions take longer to confirm.
        if (nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection cs;
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            CRITICAL_BLOCK(cs)
            {
                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15) * 10 * 1000 && !IsFromMe(*this)) {
                    m_strRunTimeErr = "free transaction rejected by rate limiter";
                    return ERROR_FL("%s", m_strRunTimeErr.c_str());
                }
                DEBUG_FL("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
                dFreeCount += nSize;
            }
        }
    }

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            TRACE_FL("AcceptToMemoryPool() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            ptxOld->RemoveFromMemoryPool();
        }
        AddToMemoryPoolUnchecked();
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    TRACE_FL("AcceptToMemoryPool(): accepted %s\n", hash.ToString().substr(0, 10).c_str());
    return true;
}

bool CTransaction::AcceptToMemoryPool(bool fCheckInputs, bool* pfMissingInputs)
{
    CTxDB_Wrapper txdb;
    return AcceptToMemoryPool(txdb, fCheckInputs, pfMissingInputs);
}

bool CTransaction::AddToMemoryPoolUnchecked()
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptToMemoryPool to properly check the transaction first.
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = GetHash();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTransaction::RemoveFromMemoryPool()
{
    // Remove transaction from memory pool
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            mapNextTx.erase(txin.prevout);
        mapTransactions.erase(GetHash());
        nTransactionsUpdated++;
    }
    return true;
}


int CMerkleTx::GetDepthInMainChain(int& nHeightRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    auto mi = mapBlockIndex[hashBlock];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }
    //HCE: to be done
    nHeightRet = pindex->nHeight;
    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    //HCE:for test
    //return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
    return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(txdb, false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB_Wrapper txdb;
    return AcceptToMemoryPool(txdb);
}


bool CWalletTx::AcceptWalletTransaction(CTxDB_Wrapper& txdb, bool fCheckInputs)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        //HCE: Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB_Wrapper txdb;
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    auto mi = mapBlockIndex[pos.hashBlk];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}



//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//
const CUInt128& getMyNodeID()
{
    static CUInt128 myID;
    if (myID.IsZero()) {
        NodeManager* mgr = Singleton<NodeManager>::getInstance();
        HCNodeSH& me = mgr->myself();
        myID = me->getNodeId<CUInt128>();
    }
    return myID;
}

//HCE: Get block header progpow hash based header, nonce and mix hash
uint256 getBlockHeaderProgPowHash(CBlock *pblock)
{
    if (pblock->nSolution.empty()) {
        return 0;
    }

    uint64_t nonce = pblock->nNonce;

    ethash::hash256 header_hash = pblock->GetHeaderHash();

    ethash::hash256 mix;
    //HCE: solution starts with 32 bytes mix hash.
    memcpy(mix.bytes, pblock->nSolution.data(), sizeof(mix.bytes));

    //HCE: ethash::progpow
    ethash::hash256 ret = progpow::verify_final_hash(header_hash, mix, nonce);

    uint256 &r = pblock->hashMyself;
    //HCE: ethash hash is always consider as big endian. uint256 is little endian.
    std::reverse_copy(std::begin(ret.bytes), std::end(ret.bytes), r.begin());

    return r;
}

uint256 CBlock::GetHash() const
{
    if (hashMyself == 0) {
        CBlock* pBlk = const_cast<CBlock*>(this);
        getBlockHeaderProgPowHash(pBlk);
    }
    return hashMyself;
}

void CBlock::SetHyperBlockInfo()
{
    nPrevHID = LatestHyperBlock::GetHID(&hashPrevHyperBlock);

    ownerNodeID = getMyNodeID();

    string owner = ownerNodeID.ToHexString();
    hashExternData = Hash(owner.begin(), owner.end());
}

bool CBlock::IsMine() const
{
    return getMyNodeID() == ownerNodeID;
}

bool CBlock::CheckExternalData() const
{
    string owner = ownerNodeID.ToHexString();
    uint256 h = Hash(owner.begin(), owner.end());
    return h == hashExternData;
}

struct AskHBlock {
    int64 tmAsk;
    uint32_t nHID;
    uint256 hashHyperBlock;
};

typedef boost::multi_index::multi_index_container<
    AskHBlock, indexed_by<
    hashed_unique<member<AskHBlock, uint32_t, &AskHBlock::nHID>>,
    ordered_non_unique<member<AskHBlock, int64, &AskHBlock::tmAsk>>
    >
> askhblock_multi_index;

static askhblock_multi_index askhblocks;

bool CheckHyperBlockByCache(uint32 hid, const uint256& hhash, bool &cachehit)
{
    cachehit = false;
    auto now = GetTime();

    //HC: 删除cache内过期的数据， 过期时间为15秒
    auto& ask_index = askhblocks.get<1>();
    auto itend = ask_index.upper_bound(now - 15);
    auto it = ask_index.begin();
    for (; it != itend;)
        ask_index.erase(it++);

    //HC: cache里寻找
    auto askedhblk = askhblocks.find(hid);
    if (askedhblk != askhblocks.end()) {
        if (hhash == (*askedhblk).hashHyperBlock) {
            cachehit = true;
            return true;
        }
        return false;
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    //HC：一次获取后面连续5个超块的信息, 并压入cache
    vector<T_SHA256> vechash;
    if (!hyperchainspace->GetHyperBlocksHashs(hid, 5, vechash, true)) {
        return false;
    }

    now = GetTime();
    uint32 id = hid;
    for (auto h: vechash) {
        askhblocks.insert({now, id++, to_uint256(h)});
    }

    //HC：检查是否一致
    if (vechash.size() > 0 && vechash[0] == to_T_SHA256(hhash)) {
        return true;
    }
    return false;
}


int CBlock::CheckHyperBlockConsistence(bool &cachehit) const
{
    if (nHeight == 0) {
        return 0;
    }

    if (CheckHyperBlockByCache(nPrevHID, hashPrevHyperBlock, cachehit))
        return 0;
    return -1;
}

bool CBlock::IsLastestHyperBlockMatched() const
{
    uint256 currHyperBlockhash;
    uint64 id = LatestHyperBlock::GetHID(&currHyperBlockhash);

    if (id != nPrevHID) {
        return false;
    }
    if (hashPrevHyperBlock != currHyperBlockhash) {
        return false;
    }
    return true;
}

ethash::hash256 CBlock::GetHeaderHash() const
{
    //HCE: I = the block header minus nonce and solution.
    //HCE: also uses CEquihashInput as custom header
    CEquihashInput I{ *this };
    //HCE: I||V  nonce part should be zeroed
    CDataStream ss(SER_BUDDYCONSENSUS);
    ss << I;

    auto offset = ss.size();
    ss << nNonce;

    //the nonce should be zeroed
    memset((unsigned char*)&ss[offset], 0, sizeof(nNonce));
    return ethash_keccak256((unsigned char*)&ss[0], offset + sizeof(nNonce));
}

//bool CBlock::ReadFromDisk(const CTxIndex& txidx, bool fReadTransactions)
//{
//    if (txidx.pos.addr.isValid()) {
//        return ReadFromDisk(txidx.pos.addr, fReadTransactions);
//    }
//    CBlockIndexSP pIndex = pindexBest;
//    while (pIndex)
//    {
//        if (pIndex->nHeight == txidx.pos.nHeight) {
//            return ReadFromDisk(pIndex, fReadTransactions);
//        }
//        pIndex = pIndex->pprev();
//    }
//    return ERROR_FL("block(%d) isn't found in local node", txidx.pos.nHeight);
//
//}

bool CBlock::NewBlockFromString(const CBlockIndexSP& pindex, string&& payload)
{
    try {
        CAutoBuffer autobuff(std::move(payload));
        autobuff >> *this;
        if (GetHash() == pindex->GetBlockHash()) {
            this->ownerNodeID = pindex->ownerNodeID;
            return true;
        }
    }
    catch (std::ios_base::failure& e) {
        return ERROR_FL("%s", e.what());
    }
    return false;
}

bool CBlock::ReadFromDisk(const CBlockIndexSP &pindex, bool fReadTransactions)
{
    if (!fReadTransactions) {
        *this = pindex->GetBlockHeader();
        return true;
    }

    //HCE: Read from cache at first
    if (ReadFromMemoryPool(pindex->GetBlockHash())) {
        return true;
    }
    else {
        if (!pindex->triaddr.ToAddr().isValid()) {
            return false;
        }

        //HCE: Read data from chain space
        CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        if (pindex->triaddr.isValid()) {
            T_LOCALBLOCK localblock;
            if (hyperchainspace->GetLocalBlockByHyperBlockHash(pindex->triaddr.ToAddr(), to_T_SHA256(pindex->triaddr.hhash), localblock)) {
                if (NewBlockFromString(pindex, std::move(localblock.body.payload)))
                    return true;
            }
        }

        T_LOCALBLOCK lblock;
        if (hyperchainspace->GetLocalBlock(pindex->triaddr.ToAddr(), lblock)) {
            if (NewBlockFromString(pindex, std::move(lblock.body.payload)))
                return true;
        }

        std::list<T_LOCALBLOCK> localblocks;
        if (!hyperchainspace->GetLocalBlocksByAddress(pindex->triaddr.ToAddr(), localblocks)) {
            DEBUG_FL("block(%s) isn't found in my local storage", pindex->triaddr.ToString().c_str());
            return false;
        }

        for (auto& blk : localblocks) {
            if (NewBlockFromString(pindex, std::move(blk.body.payload)))
                return true;
        }
    }

    DEBUG_FL("Doesn't match any block, height: %d, tripleaddr: %s, PreHID: %d(%s)", pindex->nHeight,
        pindex->triaddr.ToString().c_str(), pindex->nPrevHID, pindex->hashPrevHyperBlock.ToPreViewString().c_str());
    return false;
}

CBlockLocator::CBlockLocator(uint256 hashBlock)
{
    auto mi = mapBlockIndex[hashBlock];
    if (mi)
        Set(mi);
}

void CBlockLocator::Set(CBlockIndexSP pindex)
{
    vHave.clear();
    int nStep = 1;

    vHave.push_back(pindex->GetBlockHash());

    vector<uint256> chains;
    paramqcenter.MTC_GetChain(chains);

    for (auto h : chains) {
        vHave.push_back(h);
    }

    vHave.push_back(hashGenesisBlock);
    return;

    CSpentTime ttSpent;
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());

        // Exponentially larger steps back
        for (int i = 0; pindex && i < nStep; i++)
            pindex = pindex->pprev();
        if (vHave.size() > 10)
            nStep *= 2;

        if (!pindex) {
            break;
        }
        if (paramqcenter.MTC_Have(pindex)) {
            break;
        }

        //HCE: don't back too deeply, else performance will be low.
        if (ttSpent.Elapse() > 3000) {
            uint256 hashbegin;
            uint256 hashend;
            if (paramqcenter.MTC_GetRange(pindex->nHeight, hashbegin, hashend)) {
                vHave.push_back(hashbegin);
            }
            break;
        }
    }
    vHave.push_back(hashGenesisBlock);
}


void CBlockLocator::SetBrief(const CBlockIndexSP &pindex, const uint256& hashchk)
{
    vHave.push_back(pindex->GetBlockHash());
    vHave.push_back(hashchk);
    vHave.push_back(hashGenesisBlock);
}

int CBlockLocator::GetDistanceBack()
{
    // Retrace how far back it was in the sender's branch
    int nDistance = 0;
    int nStep = 1;
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndex* pindex = mi.get();
            if (pindex->IsInMainChain())
                return nDistance;
        }
        nDistance += nStep;
        if (nDistance > 10)
            nStep *= 2;
    }
    return nDistance;
}

CBlockIndexSP CBlockLocator::GetBlockIndex()
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndexSP pindex = mi;
            if (pindex->IsInMainChain())
                return pindex;
        }
    }
    return pindexGenesisBlock;
}

uint256 CBlockLocator::GetBlockHash()
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndex* pindex = mi.get();
            if (pindex->IsInMainChain())
                return hash;
        }
    }
    return hashGenesisBlock;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    //HCE: Work back to the first block in the orphan chain
    CBlockSP spblk;
    uint256 hPrevBlk = pblock->hashPrevBlock;
    while (mapOrphanBlocks.count(hPrevBlk)) {
        spblk = mapOrphanBlocks[hPrevBlk];
        hPrevBlk = spblk->hashPrevBlock;
    }
    if (spblk) {
        return spblk->GetHash();
    }
    return pblock->GetHash();
}

int64 static GetBlockValue(int nHeight, int64 nFees)
{
    int64 nSubsidy = g_cryptoCurrency.GetReward() * COIN;

    // Subsidy is cut in half every 4 years
    //nSubsidy >>= (nHeight / 210000);
    nSubsidy >>= (nHeight / 6300000);

    return nSubsidy + nFees;
}

unsigned int static GetNextWorkRequired(const CBlockIndexSP pindexLast)
{
    //const int64 nTargetTimespan = 14 * 24 * 60 * 60; // two weeks
    //const int64 nTargetSpacing = 10 * 60;

    //HCE: 12 block: 144 * 25, 25              formal network
    //HCE: 2016 blocks: 14 * 24 * 60 * 2,  20  informal network
    const int64 nTargetTimespan = 14 * 24 * 60 * 2;
    const int64 nTargetSpacing = 20;                       //HCE: 20 seconds

    //HCE: to a new para chain, 'nTargetTimespan' should be set the following value directly
    //if (pindexLast->nHeight > 10625) {
    //    nTargetTimespan = 14 * 24 * 60 * 2 / 4;      //HCE: every 504 blocks
    //}

#ifdef MinDiff
    nTargetTimespan = 24; // 144; // 14 * 24 * 60 * 2;
    nTargetSpacing = 1; //20;                       //HCE: 20 seconds
#endif
    //HCE: Every 'nInterval' blocks, tune work for Para.
    const int64 nInterval = nTargetTimespan / nTargetSpacing;

    // Genesis block
    if (pindexLast == nullptr)
        return bnProofOfWorkLimit.GetCompact();

    if (pindexLast->nHeight < g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        return g_cryptoCurrency.GetGenesisBits();
    }
    if (pindexLast->nHeight == g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        return g_cryptoCurrency.GetBits();
    }
    //HCE: Only change once per interval
    if ((pindexLast->nHeight + 1) % nInterval != 0) {
        return pindexLast->nBits;
    }
#ifdef MinDiff
    return 0x207fffff;
#endif

    // Go back by what we want to be 14 days worth of blocks
    CBlockIndexSP pindexFirst = pindexLast;
    int i = 0;
    for (; pindexFirst && i < nInterval - 1; i++)
        pindexFirst = pindexFirst->pprev();

    //HCE: cannot exit, it maybe damages database
    //assert(pindexFirst);
    if (!pindexFirst) {
        cerr << StringFormat("Para: %s failed due to block(%d(%s)) %d, chain has errors, unload module...\n",
            __FUNCTION__,
            pindexLast->nHeight, pindexLast->hashBlock.ToString(), i);
        CreateThread(Shutdown, NULL);
        return 1;
    }


    // Limit adjustment step
    int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    TRACE_FL("  nActualTimespan = %" PRI64d "  before bounds\n", nActualTimespan);

    if (nActualTimespan < nTargetTimespan / 4)
        nActualTimespan = nTargetTimespan / 4;
    if (nActualTimespan > nTargetTimespan * 4)
        nActualTimespan = nTargetTimespan * 4;

    // Retarget
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    /// debug print
    TRACE_FL("GetNextWorkRequired RETARGET\n");
    TRACE_FL("nTargetTimespan = %" PRI64d "    nActualTimespan = %" PRI64d "\n", nTargetTimespan, nActualTimespan);

    TRACE_FL("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
    TRACE_FL("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    //if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
    //    return ERROR_FL("nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return ERROR_FL("hash doesn't match nBits");

    return true;
}

// Return conservative estimate of total number of blocks, 0 if unknown
int GetTotalBlocksEstimate()
{
    if (fTestNet)
    {
        return 0;
    }
    else
    {
        return nTotalBlocksEstimate;
    }
}

bool IsInitialBlockDownload()
{
    return false;
    //if (pindexBest == NULL || nBestHeight < (GetTotalBlocksEstimate() - nInitialBlockThreshold))
    //    return true;
    //static int64 nLastUpdate;
    //static CBlockIndex* pindexLastBest;
    //if (pindexBest != pindexLastBest)
    //{
    //    pindexLastBest = pindexBest;
    //    nLastUpdate = GetTime();
    //}
    //return (GetTime() - nLastUpdate < 10 &&
    //    pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60 );
}

void static InvalidChainFound(CBlockIndexSP pindexNew)
{
    if (pindexNew->bnChainWork > bnBestInvalidWork)
    {
        bnBestInvalidWork = pindexNew->bnChainWork;
        CTxDB_Wrapper().WriteBestInvalidWork(bnBestInvalidWork);
        MainFrameRepaint();
    }
    WARNING_FL("InvalidChainFound: invalid block=%s  height=%d  work=%s\n", pindexNew->GetBlockHash().ToString().substr(0, 20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str());
    WARNING_FL("InvalidChainFound:  current best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str());
    //HCE: Bitcoin is 6, to hc, should be 6 * 24 = 144
    if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 144)
        WARNING_FL("InvalidChainFound: WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.\n");
}



bool CTransaction::DisconnectInputs(CTxDB_Wrapper& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return ERROR_FL("ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return ERROR_FL("prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return ERROR_FL("UpdateTxIndex failed");

            //HC: 分析隔离见证脚本，如果是跨链交易，标记索引为未花费
            CCrossChainTxIndex ethtxindex;
            if (ethtxindex.ReadFromScript(txin.scriptWitness)) {

                if (!txdb.ReadTxIndex(ethtxindex.eth_tx_hash, ethtxindex))
                    return ERROR_FL("ReadCrossChainTxIndex failed");

                // Mark outpoint as not spent
                ethtxindex.spent.SetNull();

                // Write back
                if (!txdb.UpdateTxIndex(ethtxindex.eth_tx_hash, ethtxindex))
                    return ERROR_FL("UpdateCrossChainTxIndex failed");
            }
        }
    }

    // Remove transaction from index
    if (!txdb.EraseTxIndex(*this))
        return ERROR_FL("EraseTxPos failed");

    return true;
}

inline bool SearchTxInTransactions(const uint256& hashTx, CTransaction& tx)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (!mapTransactions.count(hashTx))
            return false;
        tx= mapTransactions[hashTx];
    }
    return true;
}

// HC: find the transaction in the in - memory and unchained blocks
bool SearchTxByBlockHeight(CBlockIndexSP pindexBlock, const uint256 & hashTx, int nBlockHeight, CTransaction& tx)
{
    CBlockIndexSP pIndex = pindexBlock;
    while (pIndex) {
        if (pIndex->nHeight > nBlockHeight) {
            pIndex = pIndex->pprev();
            continue;
        }

        if (pIndex->nHeight != nBlockHeight) {
            return false;
        }

        CBlock block;
        if (!block.ReadFromDisk(pIndex)) {
            return ERROR_FL("Failed in block: height %d", pIndex->nHeight);
        }

        for (auto& elmTx : block.vtx) {
            if (elmTx.GetHash() == hashTx) {
                tx = elmTx;
                return true;
            }
        }
        break;
    }
    return ERROR_FL("Cannot find the tx %s in block: %d", hashTx.ToPreViewString().c_str(), nBlockHeight);
}


bool CTransaction::ConnectInputs(CTxDB_Wrapper& txdb, map<uint256, std::tuple<CTxIndex, CTransaction>>& mapTestPool,
    map<uint256, CCrossChainTxIndex>& mapTestCCPool,
    CDiskTxPos posThisTx,
    CBlockIndexSP pindexBlock, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee, string *err_reason)
{
    // Take over previous transactions' spent pointers
    string reason;
    if (!IsCoinBase()) {

        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++) {

            COutPoint prevout = vin[i].prevout;

            // Read txindex
            CTxIndex txindex;
            // Read txPrev
            CTransaction txPrev;

            bool fPreTxInThisBlk = false;
            bool fFound = true;

            if ((fBlock || fMiner) && mapTestPool.count(prevout.hash)) {
                // Get txindex from current proposed changes
                std::tie(txindex, txPrev) = mapTestPool[prevout.hash];
                fPreTxInThisBlk = true;
            }
            else {
                // Read txindex from txdb
                fFound = txdb.ReadTxIndex(prevout.hash, txindex);
            }

            if (!fFound && (fBlock || fMiner)) {
                reason = StringFormat("%s prev tx %s index entry not found", GetHash().ToString(), prevout.hash.ToString());
                goto havingerr;
            }

            if (!fFound || txindex.pos == CDiskTxPos(1)) {
                //HC: 连续交易，本交易的输入交易所在块就是当前块
                //HCE: For continuous trading, the input transaction is in the current block
                // Get prev tx from single transactions in memory
                if (!SearchTxInTransactions(prevout.hash, txPrev)) {
                    reason = StringFormat("%s prev tx %s index entry not found", GetHash().ToString(), prevout.hash.ToString());
                    goto havingerr;
                }
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else {
                do {
                    if (fPreTxInThisBlk || txPrev.ReadFromDisk(txindex.pos)) {
                        break;
                    }

                    //HCE: Search in transaction pool
                    if (!SearchTxInTransactions(prevout.hash, txPrev)) {
                        //if (!SearchTxByBlockHeight(pindexBlock, prevout.hash, txindex.pos.nHeight, txPrev)) {
                        //    return ERROR_FL("%s Transactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                        //}
                        reason = StringFormat("%s Transactions prev not found %s", GetHash().ToString().substr(0, 10), prevout.hash.ToString());
                        goto havingerr;
                    }
                } while (false);
            }

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size()) {
                reason = StringFormat("%s prevout.n out of range %d %d %d prev tx %s\n%s",
                    GetHash().ToString(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString(), txPrev.ToString());
                goto havingerr;
            }

            // If prev is coinbase, check that it's matured
            if (txPrev.IsCoinBase()) {
                if (pindexBlock->nHeight - txindex.pos.nHeightBlk < COINBASE_MATURITY) {
                    reason = StringFormat("tried to spend coinbase at depth %d", pindexBlock->nHeight - txindex.pos.nHeightBlk);
                    goto havingerr;
                }
            }

            // Verify signature
            if (!VerifySignature(txPrev, *this, i)) {
                reason = StringFormat("%s VerifySignature failed : %s", GetHash().ToString(), txindex.pos.ToString());
                goto havingerr;
            }

            // Check for conflicts
            if (!txindex.vSpent[prevout.n].IsNull()) {
                reason = StringFormat("%s prev tx already used at %s", GetHash().ToString(), txindex.vSpent[prevout.n].ToString());
                goto havingerr;
            }

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn)) {
                reason = "txin values out of range";
                goto havingerr;
            }

            CCrossChainTxIndex ethtxindex;
            if (ethtxindex.ReadFromScript(vin[i].scriptWitness)) {
                if (txdb.ReadTxIndex(ethtxindex.eth_tx_hash, ethtxindex)) {
                    if (!ethtxindex.spent.IsNull()) {
                        reason = StringFormat("%s prev tx already used at %s", GetHash().ToString(), txindex.vSpent[prevout.n].ToString());
                        goto havingerr;
                    }
                }
                //HC: Mark cross-chain tx as spent
                ethtxindex.spent = posThisTx;
                if (fBlock || fMiner) {
                    mapTestCCPool[ethtxindex.eth_tx_hash] = ethtxindex;
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner) {
                mapTestPool[prevout.hash] = std::make_tuple(txindex, txPrev);
            }
        }

        if (nValueIn < GetValueOut()) {
            reason = StringFormat("%s value in < value out", GetHash().ToString());
            goto havingerr;
        }

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0) {
            reason = StringFormat("%s nTxFee < 0", GetHash().ToString());
            goto havingerr;
        }
        if (nTxFee < nMinFee) {
            reason = StringFormat("nTxFee < nMinFee(%d)", nTxFee, nMinFee);
            goto havingerr;
        }
        nFees += nTxFee;
        if (!MoneyRange(nFees)) {
            reason = "nFees out of range";
            goto havingerr;
        }
    }

    if (fBlock) {
        // Add transaction to changes
        mapTestPool[GetHash()] = std::make_tuple(CTxIndex(posThisTx, vout.size()), *this);
    }
    else if (fMiner) {
        // Add transaction to test pool
        mapTestPool[GetHash()] = std::make_tuple(CTxIndex(CDiskTxPos(1), vout.size()), *this);
    }

    return true;

havingerr:
    if (err_reason) {
        *err_reason = reason;
    }
    return ERROR_FL("%s", reason.c_str());
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mapTransactions.count(prevout.hash))
                return false;
            CTransaction& txPrev = mapTransactions[prevout.hash];

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return ERROR_FL("VerifySignature failed");

            ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return ERROR_FL("txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}


bool CBlock::DisconnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    auto spprev = pindex->pprev();
    if (spprev)
    {
        CDiskBlockIndex blockindexPrev(spprev.get());
        blockindexPrev.GetBlockIndex()->hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    }

    return true;
}


bool CheckCrossChainEthTx(const CCrossChainTxIndex& ccidx)
{
    //HC: To do
    return true;
}

bool CBlock::ConnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex)
{
    // Check it again in case a previous version let a bad block in
    //HCE: don't check again, it need a lot of time
    //if (!CheckBlock())
    //    return false;

    //// issue here: it doesn't know the version
    //HCE: why -2, because nSolution member of CBlock, even if nSolution's size is 0,it will take 1 byte.
    unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 2 + GetSizeOfCompactSize(vtx.size());

    map<uint256, std::tuple<CTxIndex, CTransaction>> mapQueuedChanges;
    map<uint256, CCrossChainTxIndex> mapQueuedChangesCC;
    int64 nFees = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(nTxPos, nHeight, pindex->GetBlockHash());
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, mapQueuedChanges, mapQueuedChangesCC, posThisTx, pindex, nFees, true, false))
            return false;
    }
    // Write queued txindex changes
    //HCE: save transaction index to db
    for (auto mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi) {
        CTxIndex txindex;
        std::tie(txindex, std::ignore) = (*mi).second;
        if (!txdb.UpdateTxIndex((*mi).first, txindex))
            return ERROR_FL("UpdateTxIndex failed");
    }

    //HC: 跨链交易之eth交易的hash保存到数据库
    for (auto mi = mapQueuedChangesCC.begin(); mi != mapQueuedChangesCC.end(); ++mi) {
        if (!CheckCrossChainEthTx((*mi).second)) {
            return ERROR_FL("CheckCrossChainEthTx failed");
        }

        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return ERROR_FL("UpdateCrossChainTxIndex failed");
    }

    if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
        return false;

    //HCE: Update block index on disk without changing it in memory.
    //HCE: The memory index structure will be changed after the db commits.
    auto spprev = pindex->pprev();
    if (spprev) {
        CDiskBlockIndex blockindexPrev(spprev.get());
        blockindexPrev.GetBlockIndex()->hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    } else if(pindex->nHeight > 0){
        cerr << StringFormat("%s: cannot found the previous block index: %d %s \n",
            __FUNCTION__, pindex->nHeight, pindex->hashBlock.ToString());
        return false;
    }

    //HCE: Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}


bool ForwardFindBlockInMain(int blkheight, const uint256 &blkhash, int h1, int h2, CBlock &block, BLOCKTRIPLEADDRESS &blktriaddr, vector<int> &vecHyperBlkIdLacking)
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    int genesisHID = g_cryptoCurrency.GetHID(); // 203238;
    T_APPTYPE app(APPTYPE::paracoin, genesisHID, g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    if (isInformalNetwork() && h1 <= genesisHID) {
        h1 = genesisHID + 1;
    }

    //(i >= 203239 && i <= 203247) || //HCE: first 172 blocks they are in hyperblock : 203239 ~ 203247
    for (int i = h1; i <= h2; ++i) {
        vector<T_PAYLOADADDR> vecPA;
        T_SHA256 thhash;
        if (hyperchainspace->GetLocalBlocksByHID(i, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    WARNING_FL("Fail to call ResolveBlock, Hyperblock Id: %d\n", i);
                    continue;
                }

                //HCE: skip some hyper block for bugs
                bool heightIncreCond = true;
                if (isInformalNetwork() && i < 430000)
                    //( i == 213084  //HCE: para 146027 triple address is [213084,3,34], but 146026 is [213084,3,35]
                    //|| i == 203343 //HCE:  [203343, 1, 8] height is 644, but [213343, 1, 7]'s height is 644 too, [203343, 1, 7] is in main chain
                    //|| i == 211538 //HCE:  [211538, 1, 33] height is 136026, but [213343, 1, 23]'s height is 136028
                    //|| i == 211549 //HCE:  [211549, 1, 28] height is 136252, but [213343, 1, 29]'s height is 136251
                    //)
                    heightIncreCond = false;

                if (heightIncreCond && block.nHeight < blkheight) {
                    break;
                }
                block.hashMyself = 0;
                if (blkheight == block.nHeight && block.GetHash() == blkhash) {
                    blktriaddr = pa->addr;
                    blktriaddr.hhash = to_uint256(thhash);
                    return true;
                }
            }
        } else {
            vecHyperBlkIdLacking.push_back(i);
        }
    }
    return false;
}


typedef struct _HeightRange
{
    int h1;
    int h2;
public:
    friend bool operator<(const _HeightRange& left, const _HeightRange& right)
    {
        if (left.h1 == right.h1) {
            return left.h2 < right.h2;
        }
        return (left.h1 + left.h2 < right.h1 + right.h2);
    }
} HeightRange;

static bool ValidateBlockbyHyperchainRange(CBlockIndexSP pindexNew, const HeightRange &hrange, string& reason)
{
    bool isValidBlk = false;

    //HCE: Notice: The following condition will be removed in the future
    if (isInformalNetwork()) {
        if (pindexNew->nHeight == 100000 && pindexNew->GetBlockHash() != uint256S("0072f164da3d5b21fd28b288bd12bbe07afecc24a5c0120db2ceaf2a9371cf73")) {
            return false;
        }
        if (pindexNew->nHeight == 200000 && pindexNew->GetBlockHash() != uint256S("00dd8805b92feafe76d41930fc193d3b98e8e9a218775f592bad7c8ab7ce70c5")) {
            return false;
        }
        if (pindexNew->nHeight == 300000 && pindexNew->GetBlockHash() != uint256S("0066a9f15584ab4651a1a5b4247d9e0d3fd08a8ee8cc50a27e0ad72a0ad270d4")) {
            return false;
        }
        if (pindexNew->nHeight == 400000 && pindexNew->GetBlockHash() != uint256S("014002567fe65529b2bc003e3dd436bfc50bf413a8f2175045853e7156ef8a5d")) {
            return false;
        }
        if (pindexNew->nHeight == 500000 && pindexNew->GetBlockHash() != uint256S("0282ff7668d479e17dba64e7d1e64ba57b710048d96f8a2f2c008cb6aaad95c8")) {
            return false;
        }
        if (pindexNew->nHeight == 550000 && pindexNew->GetBlockHash() != uint256S("0012e0183cafe575e321f937303592010dbb99d9eadc435da7ac56f0697efb14")) {
            return false;
        }

        //HC: 520000以后的Para块必须严格检查是否在主链
        //HCE: Para blocks after 520000 must be strictly checked whether they are in the main chain
        if(pindexNew->nHeight < 520000)
            return true;

        //HC: 测试网因为存在bug, 目前发现下面高度的Para块，不在超块主链上，因此不检查是否落地，认为是合法的
        //HCE: Do not check whether it has landed, it is considered legitimate
        //(pindexNew->nHeight >= 275 && pindexNew->nHeight <= 279) ||
        //    (pindexNew->nHeight >= 142258 && pindexNew->nHeight <= 142269) ||
        //    (pindexNew->nHeight >= 142458 && pindexNew->nHeight <= 142470) ||
        //    (pindexNew->nHeight >= 143679 && pindexNew->nHeight <= 143699) ||
        //    (pindexNew->nHeight >= 143806 && pindexNew->nHeight <= 143839) ||
        //    (pindexNew->nHeight >= 360688 && pindexNew->nHeight <= 360944) || //previous hyper block(228097) error
        //    (pindexNew->nHeight >= 137313 && pindexNew->nHeight <= 137321) ||
        //    pindexNew->nHeight == 136968 ||
        //    pindexNew->nHeight == 137394 ||
        //    pindexNew->nHeight == 140900 ||
        //    pindexNew->nHeight == 142035
        //    ))
    }

    if (pindexNew == pindexGenesisBlock)
        return true;

    //HC: 在超块链[h1,h2]区间内寻找Para块, 如果找到，那么说明Para块有效，否则无效
    //HCE: Look for the Para block in the Hyperchain [h1,h2] interval, if found, then the Para block is valid, otherwise it is invalid
    int h1 = hrange.h1;
    int h2 = hrange.h2;

    //HCE: Para block must in hyper block[h1 ~ h2], else the block is invalid
    BLOCKTRIPLEADDRESS triaddr;
    vector<int> vecHyperBlkIdLacking;
    CBlock blk;
    if (ForwardFindBlockInMain(pindexNew->nHeight, pindexNew->GetBlockHash(), h1, h2, blk, triaddr, vecHyperBlkIdLacking)) {
        blk.UpdateToBlockIndex(pindexNew, triaddr);
        isValidBlk = true;
    } else {
        //HC: 也许是没有超块，那么要去拉取超块, 拉取缺少的块
        //HCE: Maybe there is no Hyperblock, so go and pull the Hyperblock, pull the first missing block
        if (vecHyperBlkIdLacking.size() > 0) {
            int endHID = vecHyperBlkIdLacking.back() + 1;
            RSyncRemotePullHyperBlock(vecHyperBlkIdLacking[0], endHID);
            reason = StringFormat("pindexNew's previous HyperBlock info error(4), downloading hyperblock %d", vecHyperBlkIdLacking[0]);
        } else {
            reason = StringFormat("Invalid block due to cannot find it in main hyperblock chain: [%d, %d]", h1, h2);
        }
    }
    return isValidBlk;
}

//HC: 沿超块链前向检查新的Para链中Para块是否在主链上
//HC: 原理：前后2个块的前向超块nPrevHID(假设分别为:h1, h2)发生变化就认为需要检查，检查前一个块是否落在超块链的[h1+1,h2]范围内
//HC: 如果发现fork块不在主链上，那么forkblkerr返回true，Para链相应应该回退

//HCE: Check whether the Para block in the new Para chain is on the Hyperchain
//HCE: Principle: The forward hyperblock nPrevHID (assuming h1, h2) of the two blocks before and after changes is considered to be checked to check whether the previous block falls within the range of [h1+1, h2] of the Hyperchain
//HCE: If the fork block is found not on the main chain, then forkblkerr returns true and the Para chain should roll back accordingly
bool checkInMainChain(CBlockIndexSP pfork, vector<CBlockIndexSP>& vConnect, bool &forkblkerr)
{
    std::stack<int> stackTmp;
    std::map<HeightRange, CBlockIndexSP> mapNeedCheckBlocks;

    //HC: 提取需要检查的Para块，包括fork块
    //HCE: Extract the Para blocks that need to be checked, including fork blocks
    int nCount = vConnect.size();
    for (int i = nCount - 1; i >= 0; i--) {
        if (stackTmp.empty()) {
            stackTmp.push(vConnect[i]->nPrevHID);
        } else {
            if (stackTmp.top() == vConnect[i]->nPrevHID) {
                continue;
            } else {
                HeightRange hrange;
                hrange.h1 = vConnect[i]->nPrevHID + 1;
                hrange.h2 = stackTmp.top();
                stackTmp.pop();

                mapNeedCheckBlocks[hrange] = vConnect[i];

                stackTmp.push(vConnect[i]->nPrevHID);
            }
        }
    }

    if (!stackTmp.empty()) {
        if (stackTmp.top() != pfork->nPrevHID) {
            HeightRange hrange;
            hrange.h1 = pfork->nPrevHID + 1;
            hrange.h2 = stackTmp.top();
            mapNeedCheckBlocks[hrange] = pfork;
        }
    }

    //HC: 检查块是否落在超块链
    //HCE: Check if the block falls on the Hyperchain
    string reason;
    bool isOK = true;
    CBlockIndexSP pindexNew;

#ifdef COST_PARSE
    CSpentTime t;
    stringstream ossblocks;
    ossblocks << "(";
#endif

    for (auto & elm : mapNeedCheckBlocks) {
#ifdef COST_PARSE
        ossblocks << elm.second->Height() << ",";
#endif
        if (!ValidateBlockbyHyperchainRange(elm.second, elm.first, reason)) {
            pindexNew = elm.second;
            isOK = false;
            break;
        }
    }

#ifdef COST_PARSE
    ossblocks << ")";
    if (t.Elapse() > 100)
        LogCostParse("checkInMainChain: num:%s %d\n", ossblocks.str().c_str(), t.Elapse());
#endif

    forkblkerr = false;
    if (!isOK) {
        if (pindexNew == pfork) {
            forkblkerr = true;
        }
        INFO_FL("Block not in main chain: PreHID: %d(%s) %d(%s triaddr:%s) reason: %s",
            pindexNew->nPrevHID, pindexNew->hashPrevHyperBlock.ToPreViewString().c_str(),
            pindexNew->nHeight, pindexNew->hashBlock.ToPreViewString().c_str(), pindexNew->triaddr.ToString().c_str(),
            reason.c_str());

    }
    return isOK;
}

//HCE: Validate whether it is able to switch
bool CBlock::TryReorganize(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew,
    vector<CBlockIndexSP> &vDisconnect,
    vector<CBlockIndexSP> &vConnect,
    bool &forkblkerr, CBlockIndexSP &pfork)
{
    TRACE_FL("TryReorganize\n");

    // Find the fork
    pfork = pindexBest;
    CBlockIndexSP plonger = pindexNew;
    while (pfork != plonger) {
        while (plonger->nHeight > pfork->nHeight) {
            if (fShutdown) {
                return ERROR_FL("for shutdown");
            }
            if (!(plonger = plonger->pprev()))
                return ERROR_FL("plonger->pprev is null");
        }
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev()))
            return ERROR_FL("pfork->pprev is null");
    }

    // List of what to disconnect
    for (CBlockIndexSP pindex = pindexBest; pindex != pfork; pindex = pindex->pprev()) {
        if (fShutdown) {
            return ERROR_FL("for shutdown");
        }
        vDisconnect.push_back(pindex);
    }

    // List of what to connect
    for (CBlockIndexSP pindex = pindexNew; pindex != pfork; pindex = pindex->pprev()) {
        if (fShutdown) {
            return ERROR_FL("for shutdown");
        }
        vConnect.push_back(pindex);
    }
    reverse(vConnect.begin(), vConnect.end());

    if (!checkInMainChain(pfork, vConnect, forkblkerr)) {
        return false;
    }

    //HCE: check preHID of every block in vConnect if it is valid
    //CBlockIndexSP pPrev = pfork;
    //for (size_t i = 0; i < vConnect.size(); i++) {
    //    if (!ValidateNewParaBlock(pPrev, vConnect[i])) {
    //        return false;
    //    }
    //    pPrev = vConnect[i];
    //}
    return true;
}

bool static Reorganize(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew, vector<CBlockIndexSP> &vDisconnect, vector<CBlockIndexSP> &vConnect)
{
    TRACE_FL("REORGANIZE\n");

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndexSP pindex, vDisconnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("Height:%d ReadFromDisk for disconnect failed", pindex->nHeight);
        if (!block.DisconnectBlock(txdb, pindex))
            return ERROR_FL("DisconnectBlock failed");

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (size_t i = 0; i < vConnect.size(); i++) {
        CBlockIndexSP pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("ReadFromDisk(%d %s) for connect failed", pindex->nHeight, pindex->hashBlock.ToString().c_str());
        if (!block.ConnectBlock(txdb, pindex)) {
            // Invalid block
            return ERROR_FL("ConnectBlock(%d %s) failed", pindex->nHeight, pindex->hashBlock.ToString().c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    auto hash = pindexNew->GetBlockHash();
    if (!txdb.WriteHashBestChain(hash))
        return ERROR_FL("WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return ERROR_FL("TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndexSP pindex, vDisconnect)
    {
        auto spprev = pindex->pprev();
        if (spprev) {
            spprev->hashNext = 0;
            //HCE: The following operator has already done in above: block.DisconnectBlock
            //if (!txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get())))
            //    return ERROR_FL("WriteBlockIndex failed");
        }
    }

    // Connect longer branch
    BOOST_FOREACH(CBlockIndexSP pindex, vConnect)
    {
        auto spprev = pindex->pprev();
        if (spprev) {
            spprev->hashNext = pindex->GetBlockHash();
            //HCE: The following operator has already done in above: block.ConnectBlock
            //if(!txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get())))
            //    return ERROR_FL("WriteBlockIndex failed");
        }
    }

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
        tx.RemoveFromMemoryPool();

    return true;
}

bool CBlock::SetBestChain(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew)
{
#ifdef COST_PARSE
    CSpentTime t;
#endif

    if (pindexNew == pindexBest) {
        return true;
    }
    //HCE: make sure the reference count > 1, avoid db flush frequencely
    CBlockDB_Wrapper blockdb;

    uint256 hash = GetHash();

    //HCE: allow read for other thread
    //HCE: what difference for DB_READ_COMMITTED TXN_READ_COMMITTED?
    if(!txdb.TxnBegin(DB_READ_COMMITTED))
        return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);

    if (pindexGenesisBlock == nullptr && hash == hashGenesisBlock) {
        //HCE: Connect genesis block's transactions
        ConnectBlock(txdb, pindexNew);
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain) {

        bool forkblkerr;
        vector<CBlockIndexSP> vConnect;
        vConnect.push_back(pindexNew);
        if (!checkInMainChain(pindexBest, vConnect, forkblkerr)) {
            txdb.TxnAbort();
            if (forkblkerr) {
                //HC: fork 块 不在主链上, 回退
                //HCE: Fork blocks are not on the main chain, rollback
                auto& hashfork = pindexBest->hashPrevHyperBlock;
                CBlockIndexSP pforknew = pindexBest->pprev();
                if (!pforknew)
                    pforknew = pindexGenesisBlock;
                CBlock blk;
                if(blk.ReadFromDisk(pforknew))
                    blk.SetBestChain(txdb, pforknew);
                return false;
            }
            return false;
        }

        //if (!ValidateNewParaBlock(pindexBest, pindexNew)) {
        //   txdb.TxnAbort();
        //   return false;
        //}

        // Adding to current best branch
        if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("ConnectBlock failed");
        }

        // Add to current best branch
        auto spprev = pindexNew->pprev();
        if (spprev) {
            spprev->hashNext = pindexNew->GetBlockHash();
            if (!txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get()))) {
                txdb.TxnAbort();
                return ERROR_FL("WriteBlockIndex failed");
            }
        }

        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");

        // Delete redundant memory transactions
        BOOST_FOREACH(CTransaction& tx, vtx)
            tx.RemoveFromMemoryPool();
    }
    else {
        // New best branch
        vector<CBlockIndexSP> vDisconnect;
        vector<CBlockIndexSP> vConnect;
        bool forkblkerr;
        CBlockIndexSP pfork;

        if (!TryReorganize(txdb, pindexNew, vDisconnect, vConnect, forkblkerr, pfork)) {

            txdb.TxnAbort();
            if (forkblkerr && !fShutdown) {
                //HC: fork 块 不在主链上, 回退
                //HCE: Fork blocks are not on the main chain, rollback
                auto& hashfork = pfork->hashPrevHyperBlock;
                CBlockIndexSP pforknew = pfork->pprev();
                if (!pforknew)
                    pforknew = pindexGenesisBlock;
                CBlock blk;
                if (blk.ReadFromDisk(pforknew))
                    blk.SetBestChain(txdb, pforknew);
                return false;
            }

            INFO_FL("TryReorganize: Chain is invalid");
            return false;
        }

        if (!Reorganize(txdb, pindexNew, vDisconnect, vConnect)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("Reorganize failed");
        }
    }

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("SetBestChain::NewBestIndex: %d %d\n", pindexBest->nHeight, t.Elapse());
    t.Reset();
#endif


    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    nBestHeight = pindexBest->nHeight;
    bnBestChainWork = pindexBest->bnChainWork;


    uint256 hashchk;
    paramqcenter.MTC_Set(hashchk);

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("SetBestChain::MTC_Set: %d %d\n", pindexBest->nHeight, t.Elapse());
    t.Reset();
#endif

    // Update best block in wallet (so we can detect restored wallets)
    //if (!IsInitialBlockDownload()) {
        //HCE: CBlockLocator's construct need a large time cost, so take a simple way.
        CBlockLocator locator;
        locator.SetBrief(pindexNew, hashchk);
        ::SetBestChain(locator);
    //}

    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;

    //HCE: To solve a bug, add the following log
    //CBlockIndexSP pprevindex = pindexBest->pprev();
    //LogToFile("SetBestChain: new best=%s  height=%d work=%s, Pre's hashNext=%s\n",
    //    hashBestChain.ToString().c_str(), nBestHeight, pindexBest->bnChainWork.ToString().c_str(),
    //    (pprevindex ? pprevindex->hashNext.ToPreViewString().c_str() : "0"));

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("SetBestChain::SetBrief: %d %d\n", pindexBest->nHeight, t.Elapse());
    t.Reset();
#endif

    TRACE_FL("SetBestChain: new best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str());
    return true;
}


bool CBlock::UpdateToBlockIndex(CBlockIndexSP pIndex, const BLOCKTRIPLEADDRESS& blktriaddr)
{
    pIndex->triaddr = blktriaddr;

    CTxDB_Wrapper txdb;
    //HCE: maybe here is a nested transaction
    if (!txdb.TxnBegin())
        return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);

    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pIndex.get()))) {
        txdb.TxnAbort();
        return false;
    }

    if (!txdb.TxnCommit())
        return false;

    return true;
}

bool CBlock::AddToBlockIndex()
{
#ifdef COST_PARSE
    CSpentTime t;
#endif

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return ERROR_FL("%s already exists", hash.ToString().substr(0, 20).c_str());

    CBlockIndexSP pindexNew;

    // Construct new block index object
    pindexNew = make_shared_proxy<CBlockIndex>(tripleaddr, *this);

    if (!pindexNew)
        return ERROR_FL("new CBlockIndex failed");

    pindexNew->hashBlock = hash;
    auto miPrev = mapBlockIndex[hashPrevBlock];
    if (miPrev) {
        pindexNew->hashPrev = hashPrevBlock;// (*miPrev).second;
        pindexNew->nHeight = miPrev->nHeight + 1;
        //HCE: here cannot set miPrev->hashNext, because the action must be done in 'SetBestChain'
        //miPrev->hashNext = hash;
    } else if(pindexNew->nHeight >= 1){
        cerr << StringFormat("Para: Not found Block(%d %s)'s previous block index\n", pindexNew->nHeight, pindexNew->ToString());
        return false;
    }

    pindexNew->bnChainWork = (miPrev ? miPrev->bnChainWork : 0) + pindexNew->GetBlockWork();

    auto isSuccess = mapBlockIndex.insert(make_pair(hash, pindexNew));
    if (!isSuccess) {
        //HCE: Maybe another thread is handling.

        LogToFile("Para: AddToBlockIndex cannot insert new CBlockIndex(%d %s)\n", pindexNew->nHeight, pindexNew->hashBlock.ToString().c_str());
        cerr << StringFormat("Para: AddToBlockIndex cannot insert new CBlockIndex(%d %s)\n", pindexNew->nHeight, pindexNew->hashBlock.ToString());
        return false;
    }

    //HCE: Cannot use pindexNew directly, must get index from pool
    pindexNew = mapBlockIndex[hash];

    //LogToFile("Para: AddToBlockIndex new CBlockIndex(%d %s) work:%s %s best:%s\n", pindexNew->nHeight, pindexNew->hashBlock.ToString().c_str(),
    //    pindexNew->GetBlockWork().ToString().c_str(),
    //    pindexNew->bnChainWork.ToString().c_str(), bnBestChainWork.ToString().c_str());

#ifdef COST_PARSE
    if (t.Elapse() > 100) {
        LogCostParse("AddToBlockIndex: %d %d\n", nHeight, t.Elapse());
    }
    t.Reset();
#endif

    CTxDB_Wrapper txdb;
    //new block
    if (pindexNew->bnChainWork > bnBestChainWork) {
        //HC: Paracoin挖矿形成子链阶段，按难度来取舍最优链
        //HCE: Paracoin mining forms a solo chain stage, and the optimal chain is selected according to the difficulty
        if (!SetBestChain(txdb, pindexNew)) {
            return WARNING_FL("SetBestChain(%d) CBlockIndex failed: %d(%s) best: %d", __LINE__, pindexNew->nHeight,
                pindexNew->GetBlockHash().ToString().c_str(), nBestHeight);
        }

#ifdef COST_PARSE
        if (t.Elapse() > 100) {
            LogCostParse("AddToBlockIndex::SetBestChain: %d %d\n", pindexNew->nHeight, t.Elapse());
        }
        t.Reset();
#endif

        INFO_FL("Switch to: %d(%s) %s, PrevHID:%d(%s), LastHID: %u", pindexNew->nHeight,
            pindexNew->GetBlockHash().ToPreViewString().c_str(),
            pindexNew->triaddr.ToString().c_str(),
            pindexNew->nPrevHID, pindexNew->hashPrevHyperBlock.ToPreViewString().c_str(),
            LatestHyperBlock::GetHID());
    } else {
        INFO_FL("Para: AddToBlockIndex CBlockIndex(%d %s) new index:%s %s < best:(%d)%s\n",
            pindexNew->nHeight, pindexNew->hashBlock.ToString().c_str(),
            pindexNew->GetBlockWork().ToString().c_str(),
            pindexNew->bnChainWork.ToString().c_str(),
            nBestHeight, bnBestChainWork.ToString().c_str());
    }

    //else if(addr.isValid()){
    //    //HC: 以底层选择的最优超块为基准来取舍最优链，难度大者为最优链
    //    CBlockIndexSP pLatest = LatestBlockIndexOnChained();
    //    if (!pLatest || pindexNew->bnChainWork > pLatest->bnChainWork) {
    //        pLatest = pindexNew;
    //    }

    //    if (!SetBestChain(txdb, pLatest)) {
    //        return ERROR_FL("SetBestChain CBlockIndex failed");
    //    }
    //    pindexNew = pLatest;
    //    INFO_FL("Switch to: %d,PrevHID:%d,%s, %s, BestIndex: %d PrevHID:%d,%s, %s LastHID: %u", pLatest->nHeight,
    //        pLatest->nPrevHID,
    //        pLatest->addr.tostring().c_str(),
    //        pLatest->GetBlockHash().ToPreViewString().c_str(),
    //        pindexBest->nHeight, pindexBest->nPrevHID,
    //        pindexBest->addr.tostring().c_str(),
    //        pindexBest->GetBlockHash().ToPreViewString().c_str(),
    //        LatestHyperBlock::GetHID());
    //}

#ifdef COST_PARSE
    t.Reset();
#endif

    if (pindexNew == pindexBest) {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

#ifdef COST_PARSE
    if (t.Elapse() > 100) {
        LogCostParse("AddToBlockIndex::UpdatedTransaction: %d %d\n", nHeight, t.Elapse());
    }
#endif

    MainFrameRepaint();
    return true;
}

bool CBlock::CheckBlock() const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    //HCE: Fix me(how to do for the received block)
    //if (!CheckExternalData()) {
    //    return ERROR_FL("CheckExternalData invalid at height %d\n", nHeight);
    //}

#ifdef COST_PARSE
    //HCE: calling CheckProgPow take a lot of time, in 39.103.171.221: somtimes 5~9 seconds
    CSpentTime t;
#endif
    if (!CheckProgPow()) {
        return ERROR_FL("ProgPow invalid at height %d\n", nHeight);
    }

#ifdef COST_PARSE
    if(t.Elapse() > 300)
        LogCostParse("CheckBlock CheckProgPow: %d(%s) %d\n", 
            nHeight, GetHash().ToPreViewString().c_str(), t.Elapse());
#endif

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
        return ERROR_FL("size limits failed");

    // Check proof of work matches claimed amount
    if (!CheckProofOfWork(GetHash(), nBits))
        return ERROR_FL("proof of work failed");

    // Check timestamp
    //HCE: Skip the time check
    //if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    //    return ERROR_FL("block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return ERROR_FL("first tx is not coinbase");

    if (nHeight > g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        for (int i = 1; i < vtx.size(); i++)
            if (vtx[i].IsCoinBase())
                return ERROR_FL("more than one coinbase");
    }

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return ERROR_FL("CheckTransaction failed");

    // Check that it's not full of nonstandard transactions
    if (GetSigOpCount() > MAX_BLOCK_SIGOPS)
        return ERROR_FL("too many nonstandard transactions");

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return ERROR_FL("hashMerkleRoot mismatch");

    return true;
}

//HCE:check transaction
bool CBlock::CheckTrans()
{
    uint256 hash = GetHash();

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (!txin.IsFinal())
                return ERROR_FL("contains a non-final transaction");
    }
    return true;
}

bool CBlock::CheckProgPow() const
{
    if (nSolution.empty()) {
        return false;
    }

    //HCE: progpow nonce is 8 bytes, located the (24-32) of 32 bytes nonce
    //HCE: little endian
    uint64_t nonce = nNonce;

    uint32_t epoch = ethash::get_epoch_number(nHeight);
    ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

    ethash::hash256 header_hash = GetHeaderHash();

    ethash::hash256 mix;

    //HCE: nSolution is 32 bytes mix hash.
    const unsigned char *p = &*(nSolution.begin());
    memcpy(mix.bytes, &p[0], 32);

    ethash::hash256 target;
    CBigNum bnNew;
    bnNew.SetCompact(nBits);
    uint256 hashTarget = bnNew.getuint256();

    //HCE: endian conversion. ethash hash is considered as big endian.
    std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

    if (progpow::verify(epoch_ctx, nHeight,header_hash, mix, nonce, target)) {
        return true;
    } else {
        return ERROR_FL("verify_progpow failed");
    }
}


bool CBlock::AcceptBlock()
{
#ifdef COST_PARSE
    CSpentTime t;
#endif
    uint256 hash = GetHash();

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("AcceptBlock:ReadBlockTripleAddress: %d %d\n", nHeight, t.Elapse());
    t.Reset();
#endif

    while(mapBlockIndex.count(hash)) {
        //HCE: Update the logic address and block index for the block
        CBlockIndexSP pIndex = mapBlockIndex[hash];
        if (pIndex->triaddr.isValid()) {
            if (tripleaddr == pIndex->triaddr) {
                TRACE_FL("block already in mapBlockIndex %s", hash.ToString().substr(0, 20).c_str());
                break;
            }
            TRACE_FL("block already in mapBlockIndex %s,but need to update logic address", hash.ToString().substr(0, 20).c_str());
        }

        if (tripleaddr.isValid()) {
            if (!UpdateToBlockIndex(pIndex, tripleaddr)) {
                ERROR_FL("UpdateToBlockIndex failed");
            }
        }
        break;
    }

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("AcceptBlock:UpdateToBlockIndex: %d %d\n", nHeight, t.Elapse());
    t.Reset();
#endif

    //HCE: Get prev block index
    auto mi = mapBlockIndex[hashPrevBlock];
    if (!mi) {
        //HCE: Request the block I have not
        CRITICAL_BLOCK(cs_vNodes)
        {
            BOOST_FOREACH(CNode* pnode, vNodes)
                pnode->PushInventory(CInv(MSG_BLOCK, hashPrevBlock));
        }
        return WARNING_FL("prev block not found, pulling from neighbor");
    }

    CBlockIndexSP pindexPrev = mi;
    int nHeight = pindexPrev->nHeight + 1;

    //HCE: Check proof of work
    if (nBits != GetNextWorkRequired(pindexPrev))
        return ERROR_FL("incorrect proof of work");

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return ERROR_FL("block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return ERROR_FL("contains a non-final transaction");

    // Check that the block chain matches the known block chain up to a checkpoint
    //HCE: don't check
    //if (!fTestNet)
    //    if ((nHeight ==  11111 && hash != uint256("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")) ||
    //        (nHeight ==  33333 && hash != uint256("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")) ||
    //        (nHeight ==  68555 && hash != uint256("0x00000000001e1b4903550a0b96e9a9405c8a95f387162e4944e8d9fbe501cd6a")) ||
    //        (nHeight ==  70567 && hash != uint256("0x00000000006a49b14bcf27462068f1264c961f11fa2e0eddd2be0791e1d4124a")) ||
    //        (nHeight ==  74000 && hash != uint256("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")) ||
    //        (nHeight == 105000 && hash != uint256("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")) ||
    //        (nHeight == 118000 && hash != uint256("0x000000000000774a7f8a7a12dc906ddb9e17e75d684f15e00f8767f9e8f36553")) ||
    //        (nHeight == 134444 && hash != uint256("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")) ||
    //        (nHeight == 140700 && hash != uint256("0x000000000000033b512028abb90e1626d8b346fd0ed598ac0a3c371138dce2bd")))
    //        return error("AcceptBlock() : rejected by checkpoint lockin at %d", nHeight);

    //if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
    //    return error("AcceptBlock() : out of disk space");
    //unsigned int nFile = -1;
    //unsigned int nBlockPos = 0;
    //if (!WriteToDisk(nFile, nBlockPos))
    //    return error("AcceptBlock() : WriteToDisk failed");
    //if (!AddToBlockIndex(nFile, nBlockPos))
    //    return error("AcceptBlock() : AddToBlockIndex failed");

    //HCE: Write block to memory pool and disk index file
    if(!AddToMemoryPool(hash))
        return ERROR_FL("Block AddToMemoryPool failed");

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("AcceptBlock:AddToMemoryPool: %d %d\n", nHeight, t.Elapse());
    t.Reset();
#endif

    if (!AddToBlockIndex())
        return WARNING_FL("AddToBlockIndex failed");

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("AcceptBlock::AddToBlockIndex: %d %d\n", nHeight, t.Elapse());
#endif


    //HCE: Relay inventory, but don't relay old inventory during initial block download
    if (hashBestChain == hash)
        CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
        //HCE:
        //if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 140700))
        if(nBestHeight > pnode->chkpoint.nChkPointHeight)
            pnode->PushInventory(CInv(MSG_BLOCK, hash));

    return true;
}

void ProcessOrphanBlocks(const uint256& hash)
{
    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++)
    {
        if (fShutdown)
            return;

        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlockSP>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
            mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
            ++mi)
        {
            auto pblockOrphan = (*mi).second;

            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    //HCE: Check for duplicate
    uint256 hash = pblock->GetHash();
    INFO_FL("%s %d ", hash.ToPreViewString().c_str(), pblock->nHeight);

    if (mapBlockIndex.count(hash))
        return INFO_FL("already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToPreViewString().c_str());
    if (mapOrphanBlocks.count(hash))
         return INFO_FL("already have block %d %s (orphan)", mapOrphanBlocks[hash]->nHeight, hash.ToPreViewString().c_str());


    //HCE: Preliminary checks
    if (!pblock->CheckBlock())
        return WARNING_FL("CheckBlock %s FAILED", hash.ToPreViewString().c_str());

#ifdef COST_PARSE
    CSpentTime t;
#endif

    bool hyperblock_ok = true;
    if (pfrom) {
        //HCE: Received block

        bool cachehit;
        int ret = pblock->CheckHyperBlockConsistence(cachehit);
        if (ret != 0) {
            hyperblock_ok = false;
            //return WARNING_FL("Block: %s CheckHyperBlockConsistence invalid at height %d, cause: %d\n",
            //    hash.ToPreViewString().c_str(), pblock->nHeight, ret);
        }
#ifdef COST_PARSE
        if (t.Elapse() > 100) {
            LogCostParse("ProcessBlock: CheckHyperBlockConsistence %d hit: %d %s\n",
                pblock->nHeight, cachehit, t.ToString().c_str());
        }
        t.Reset();
#endif
    }

    //HCE: If don't already have its previous block, shunt it off to holding area until we get it
    if (!hyperblock_ok || !mapBlockIndex.count(pblock->hashPrevBlock) ) {
        TRACE_FL("%d(%s) ORPHAN BLOCK, hyperblock_ok:%d prev=%s\n", pblock->nHeight, hash.ToPreViewString().c_str(),
            hyperblock_ok,
            pblock->hashPrevBlock.ToPreViewString().c_str());

        CBlockSP spblock2 = make_shared<CBlock>(*pblock);
        mapOrphanBlocks.insert(make_pair(hash, spblock2));
        mapOrphanBlocksByPrev.insert(make_pair(spblock2->hashPrevBlock, spblock2));

        //HCE: Ask this guy to fill in what we're missing
        bool ismining = g_miningCond.IsMining();
        if (pfrom && ismining)
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(spblock2.get()));
#ifdef COST_PARSE
        if (t.Elapse() > 100)
            LogCostParse("ProcessBlock: %d %d\n", pblock->nHeight, t.Elapse());
#endif
        return true;
    }

    if (g_miningCond.IsSwitching()) {
        //HCE: Switching, avoid to switch again
        return false;
    }

    //HCE: Store to disk
    if (!pblock->AcceptBlock()) {

#ifdef COST_PARSE
        if (t.Elapse() > 100)
            LogCostParse("ProcessBlock: not AcceptBlock %d %d\n", pblock->nHeight, t.Elapse());
#endif

        return WARNING_FL("AcceptBlock %s FAILED", hash.ToPreViewString().c_str());
    }

#ifdef COST_PARSE
    if(t.Elapse() > 100)
        LogCostParse("ProcessBlock: AcceptBlock %d %d\n", pblock->nHeight, t.Elapse());
    t.Reset();
#endif

    ProcessOrphanBlocks(hash);

#ifdef COST_PARSE
    if(t.Elapse() > 100)
        LogCostParse("ProcessBlock: ProcessOrphanBlocks %d %d\n", pblock->nHeight, t.Elapse());
#endif

    TRACE_FL("ProcessBlock: %s ACCEPTED\n", hash.ToPreViewString().c_str());
    return true;
}


bool ProcessBlockWithTriaddr(CNode* pfrom, CBlock* pblock, BLOCKTRIPLEADDRESS* pblockaddr)
{
#ifdef COST_PARSE
    CSpentTime t;
    CSpentTime tt;

    defer{
        if (tt.Elapse() > 100)
            LogCostParse("ProcessBlockWithTriaddr: height: %d total cost: %d ****************************\n",
                pblock->nHeight, tt.Elapse());
    };
#endif

    //HC: Check, push into cache and download hyper blocks in background
    bool cachehit;
    bool isValidTriAddr = pblockaddr->isValid() ?
        CheckHyperBlockByCache(pblockaddr->hid, pblockaddr->hhash, cachehit) : false;

#ifdef COST_PARSE
    if (t.Elapse() > 100)
        LogCostParse("ProcessBlockWithTriaddr::CheckHyperBlockByCache: height: %d hit: %d cost: %d\n",
            pblock->nHeight, cachehit, t.Elapse());
    t.Reset();
#endif


    uint256 hash = pblock->GetHash();
    if (isValidTriAddr) {
        //HC: 保存本区块的三元组地址到内存
        pblock->tripleaddr = *pblockaddr;

        if (mapBlockIndex.count(hash)) {
            //HCE: compare and update block address
            CBlockIndexSP pIndex = mapBlockIndex[hash];
            if (pIndex->triaddr != *pblockaddr) {
                pblock->UpdateToBlockIndex(pIndex, *pblockaddr);

#ifdef COST_PARSE
            if (t.Elapse() > 100)
                LogCostParse("ProcessBlockWithTriaddr::UpdateToBlockIndex: height: %d cost: %d\n", pblock->nHeight, t.Elapse());
            t.Reset();
#endif
            }
        }
    }

    ProcessBlock(pfrom, pblock);

#ifdef COST_PARSE
    if(t.Elapse() > 100)
        LogCostParse("ProcessBlockWithTriaddr::ProcessBlock: height: %d cost: %d\n", pblock->nHeight, t.Elapse());
#endif

    if (!mapBlockIndex.count(hash)) {
        return false;
    }

    //HCE: compare and update block address
    CBlockIndexSP pIndex = mapBlockIndex[hash];
    if (isValidTriAddr && pIndex->triaddr != *pblockaddr) {
        if (!pblock->UpdateToBlockIndex(pIndex, *pblockaddr)) {
            ERROR_FL("UpdateToBlockIndex failed");
        }
    }

    //HCE: try to switch to new chain
    if (pindexBest != pIndex && bnBestChainWork < pIndex->bnChainWork) {
        SwitchChainToBlock(*pblock, pIndex);
        INFO_FL("SwitchChainToBlock: %d(%s)\n", pIndex->Height(), pIndex->hashBlock.ToPreViewString().c_str());
    }
    return true;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = boost::filesystem::space(GetDataDir()).available;

    // Check for 15MB because database could create another 10MB log file at any time
    if (nFreeBytesAvailable < (uint64)15000000 + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low  ");
        strMiscWarning = strMessage;
        //WARNING_FL("*** %s\n", strMessage.c_str());
        //ThreadSafeMessageBox(strMessage, "Hyperchain", wxOK | wxICON_EXCLAMATION);
        cerr << StringFormat("Para: %s, unload module...", strMessage);

        CreateThread(Shutdown, NULL);
        return false;
    }
    return true;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("%s/blk%04d.dat", GetDataDir().c_str(), nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

extern "C" BOOST_SYMBOL_EXPORT
string GetGenesisBlock(string& payload)
{
    CBlock genesis;
    genesis = g_cryptoCurrency.GetPanGuGenesisBlock();

    CDataStream datastream(SER_BUDDYCONSENSUS);
    datastream << genesis;
    payload = datastream.str();

    datastream.clear();
    datastream << genesis.hashMerkleRoot;
    return datastream.str();
}

void AddGenesisBlockToIndex()
{
    CBlock genesis;
    genesis = g_cryptoCurrency.GetGenesisBlock();
    //genesis = g_cryptoCurrency.MineGenesisBlock();

    uint256 hashGenesis = genesis.GetHash();
    assert(hashGenesis == g_cryptoCurrency.GetHashGenesisBlock());

    //HCE: genesis block exists in HC genesis block
    BLOCKTRIPLEADDRESS addr;
    addr.hid = g_cryptoCurrency.GetHID();
    addr.chainnum = g_cryptoCurrency.GetChainNum();
    addr.id = g_cryptoCurrency.GetLocalID();

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    T_HYPERBLOCK h;
    if (hyperchainspace->getHyperBlock(addr.hid, h)) {
        addr.hhash = to_uint256(h.GetHashSelf());
    }
    genesis.tripleaddr = addr;
    genesis.AddToBlockIndex();
}

//HC: 读取本地底层链子块缺失的para块
//HCE: Read the missing para block of the local underlying chain
bool LoadBlockUnChained()
{
    cout << "Paracoin: read block cache asynchronously in the background...\n";

    CBlockDB_Wrapper blockdb("cr");
    mapBlocks.blk_bf_future = std::async(std::launch::async, []()->CBlockBloomFilter {

        CBlockDB_Wrapper blkdbwp("r");
        CBlockBloomFilter filterBlk;
        blkdbwp.LoadBlockUnChained(filterBlk);
        mapBlocks.setFilterReadCompleted();
        return filterBlk;
    });

    return true;
}

void UpgradeBlockIndex(CTxDB_Wrapper &txdb, int height_util)
{
    cout << strprintf("Paracoin: upgrade the block indexes, until height: %d ...\n", height_util);

    CommadLineProgress progress;
    progress.Start();

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    if (!txdb.TxnBegin()) {
        ERROR_FL("%s : TxnBegin failed", __FUNCTION__);
        return;
    }

    int nTotalScanned = 0;
    int nOk = 0;
    int nUpgraded = 0;
    int nNull = 0;
    int nError = 0;

    string file = StringFormat("%s/upgradeblockidx.log", GetDataDir());
    ofstream ff(file);
    //ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);

    CBlockIndexSP pIndex = pindexBest;
    while (pIndex && pIndex->nHeight >= height_util) {
        T_LOCALBLOCKADDRESS tripleaddr;
        if (pIndex->triaddr.ToAddr().isValid()) {
            T_LOCALBLOCK localblock;
            if (hyperchainspace->GetLocalBlock(pIndex->triaddr.ToAddr(), localblock)) {

                string& payload = localblock.GetPayLoad();
                CBlock block;
                if (ResolveBlock(block, payload.c_str(), payload.size())) {
                    uint256 blkhash = block.GetHash();
                    if (blkhash == pIndex->hashBlock) {
                        T_HYPERBLOCK hyperblock;
                        if (hyperchainspace->getHyperBlock(pIndex->triaddr.hid, hyperblock)) {
                            auto hhashstorage = uint256S(hyperblock.GetHashSelf().toHexString());
                            if (pIndex->triaddr.hhash != hhashstorage) {

                                pIndex->triaddr.hhash = hhashstorage;
                                if (!txdb.WriteBlockIndex(CDiskBlockIndex(pIndex.get()))) {
                                    txdb.TxnAbort();
                                    cerr << ("WriteBlockIndex failed when upgrading block indexes\n");
                                    return;
                                }
                                nUpgraded++;
                            } else {
                                nOk++;
                            }
                        }
                    } else {
                        //HCE: This is a critical error, which means the block is not in main hyperblock chain.
                        nError++;
                        ff << strprintf("block %d[%s] index error, block index hash %s, %s in storage\n",
                            pIndex->nHeight,
                            pIndex->triaddr.ToString().c_str(), pIndex->hashBlock.ToPreViewString().c_str(),
                            blkhash.ToPreViewString().c_str());
                    }
                }
            }
        } else {
            nNull++;
            ff << strprintf("found Null triple address for block index: %d(%s) [PrevHID:%d(%s)\n",
                pIndex->nHeight, pIndex->hashBlock.ToPreViewString().c_str(),
                pIndex->nPrevHID, pIndex->hashPrevHyperBlock.ToPreViewString().c_str());
        }

        if (++nTotalScanned % 1000 == 0) {
            progress.PrintStatus(1000, strprintf("scanned: %d, ok: %d, upgraded: %d, null: %d, error: %d", nTotalScanned,
                nOk, nUpgraded, nNull, nError));
        }

        pIndex = pIndex->pprev();
    }
    if (!txdb.TxnCommit()) {
        cerr << ("TxnCommit failed when upgrading the block indexes\n");
        return;
    }
    string result = strprintf("scanned: %d, ok: %d, upgraded: %d, null: %d, error: %d", nTotalScanned,
        nOk, nUpgraded, nNull, nError);
    progress.PrintStatus(1, result);
    cout << "\n";
    ff << result;
}

void FixBlockIndexByHyperBlock(CTxDB_Wrapper& txdb, int begin_height, int end_height)
{
    cout << StringFormat("Paracoin: scan Hyperblock %d ~ %d, and fix block indexes...\n", begin_height, end_height);
    if (begin_height > end_height) {
        cerr << "Hyperblock height range error\n";
        return;
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    int i = g_cryptoCurrency.GetHID(); // 203238;
    T_APPTYPE app(APPTYPE::paracoin, i, g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    if (begin_height > i) {
        i = begin_height;
    }

    CommadLineProgress progress;
    progress.Start();

    if (!txdb.TxnBegin()) {
        ERROR_FL("%s : TxnBegin failed", __FUNCTION__);
        return;
    }

    int nTotalScanned = 0;
    int nUpgraded = 0;
    int nAdded = 0;

    int nMaxHeight = end_height; //pindexBest->nPrevHID;
    for (; i <= nMaxHeight; ++i) {

        vector<T_PAYLOADADDR> vecPA;
        T_SHA256 thhash;
        if (hyperchainspace->GetLocalBlocksByHID(i, app, thhash, vecPA)) {
            uint256 hhash = to_uint256(thhash);
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {

                CBlock block;
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    cerr << strprintf("Fail to call ResolveBlock, Hyperblock Id: %d\n", i);
                    break;
                }

                uint256 blkhash = block.GetHash();
                if (!mapBlockIndex.count(blkhash)) {
                    BLOCKTRIPLEADDRESS blockaddr(pa->addr);
                    blockaddr.hhash = to_uint256(thhash);
                    ProcessBlockWithTriaddr(nullptr, &block, &blockaddr);

                    if (!mapBlockIndex.count(blkhash)) {
                        //HCE: maybe in orphan pool
                        block.AddToBlockIndex();
                    }
                    nAdded++;
                    continue;
                }

                BLOCKTRIPLEADDRESS blktriaddr(pa->addr);
                blktriaddr.hhash = hhash;

                auto pIndex = mapBlockIndex[blkhash];
                if (pIndex->triaddr == blktriaddr) {
                    continue;
                }

                pIndex->triaddr = blktriaddr;
                if (!txdb.WriteBlockIndex(CDiskBlockIndex(pIndex.get()))) {
                    txdb.TxnAbort();
                    cerr << ("WriteBlockIndex failed when fixed block indexes\n");
                    return;
                }
                nUpgraded++;
            }
        }

        if (++nTotalScanned % 20 == 0) {
            progress.PrintStatus(20, strprintf("Hyperblock scanned: %d, indexes: (added: %d fixed: %d)", nTotalScanned, nAdded, nUpgraded));
        }
    }

    if (!txdb.TxnCommit()) {
        cerr << ("TxnCommit failed\n");
        return;
    }

    progress.PrintStatus(1, strprintf("Hyperblock scanned: %d, indexes: (added: %d fixed: %d)", nTotalScanned, nAdded, nUpgraded));
    cout << "\n";
}

bool LoadBlockIndex(bool fAllowNew)
{
    if (fTestNet)
    {
        hashGenesisBlock = uint256("0x00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008");
        //bnProofOfWorkLimit = CBigNum(~uint256(0) >> 28);
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 8);
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
    }

    //
    // Load block index
    //
    CTxDB_Wrapper txdb("cr+");
    if (!txdb.LoadBlockIndex())
        return false;

    //don't call Close directly because CTxDB_Wrapper
    //txdb.Close();

    //
    // Init with genesis block
    //

    if (mapBlockIndex.empty()) {
        if (!fAllowNew)
            return false;

        AddGenesisBlockToIndex();
    }

    if (GetBoolArg("-upgradeblockindex")) {
        UpgradeBlockIndex(txdb, 0);
    }

    if (GetBoolArg("-rebuildmaintrunk")) {
        cout << strprintf("Paracoin: rebuilding main trunk of chain...\n");
        CMainTrunkDB mtrunkdb("cr+");
        mtrunkdb.Close();
        if(!DeleteDBFile(mtrunkdb.GetDBFile()))
            cout << strprintf("Paracoin: cannot rebuilding main trunk of chain for DeleteDBFile failure\n");

    }

    CMainTrunkDB mtrunkdb("cr+");
    mtrunkdb.LoadData();

    cout << strprintf("Paracoin: building main trunk of chain from height: %d...\n", pindexBest->nHeight);
    CommadLineProgress progress;
    progress.Start();

    CBlockLocatorEx &mtc = paramqcenter.GetMTC();

    auto fn = [&progress, &mtc](int idx) {
        progress.PrintStatus(mtc.nHeightSpan,
            strprintf("%d %s", idx,
                mtc.vHave[idx].ToPreViewString().c_str()));
    };

    mtc.Set(&fn);
    cout << "\n";

    mtc.Save();

    return true;
}



void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndexSP, vector<CBlockIndexSP> > mapNext;
    for (auto mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndexSP pindex = (*mi).second;
        mapNext[pindex->pprev()].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndexSP> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndexSP pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol - 1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d  %s  %s  tx %d",
            pindex->nHeight,
            block.GetHash().ToString().substr(0, 20).c_str(),
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main timechain first
        vector<CBlockIndexSP>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext())
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol + i, vNext[i]));
    }
}



//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

map<uint256, CAlert> mapAlerts;
CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;
    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Longer invalid proof-of-work chain
    //HCE: Bitcoin is 6, to hc, should be 6 * 24 = 144
    //if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 144)
    //{
    //    nPriority = 2000;
    //    strStatusBar = strRPC = "WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.";
    //}

    // Alerts
    CRITICAL_BLOCK(cs_mapAlerts)
    {
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}

bool CAlert::ProcessAlert()
{
    if (!CheckSignature())
        return false;
    if (!IsInEffect())
        return false;

    CRITICAL_BLOCK(cs_mapAlerts)
    {
        // Cancel previous alerts
        for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
        {
            const CAlert& alert = (*mi).second;
            if (Cancels(alert))
            {
                printf("cancelling alert %d\n", alert.nID);
                mapAlerts.erase(mi++);
            }
            else if (!alert.IsInEffect())
            {
                printf("expiring alert %d\n", alert.nID);
                mapAlerts.erase(mi++);
            }
            else
                mi++;
        }

        // Check if this alert has been cancelled
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.Cancels(*this))
            {
                printf("alert already cancelled by %d\n", alert.nID);
                return false;
            }
        }

        // Add to mapAlerts
        mapAlerts.insert(make_pair(GetHash(), *this));
    }

    printf("accepted alert %d, AppliesToMe()=%d\n", nID, AppliesToMe());
    MainFrameRepaint();
    return true;
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB_Wrapper& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:    return mapTransactions.count(inv.hash) || mapOrphanTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:
    case MSG_BLOCKEX:
    case MSG_BLOCKEX_R:
        if (mapBlockIndex.count(inv.hash)) {
            auto pIndex = mapBlockIndex[inv.hash];
            if (pIndex->triaddr.isValid()) {
                return true;
            }

            //HCE: search in local block cache db
            if (mapBlocks.contain(inv.hash)) {
                return true;
            }
        }
        if (mapOrphanBlocks.count(inv.hash)) {
            return true;
        }
        return false;
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };

map<CNode*, time_t> mapPullingBlocksSpaceNodes;
CCriticalSection cs_PullingBlocksSpaceNodes;
void RequestBlockSpace(CNode* pfrom)
{
    time_t now = time(nullptr);
    CRITICAL_BLOCK(cs_PullingBlocksSpaceNodes)
    {
        if (mapPullingBlocksSpaceNodes.count(pfrom) == 0) {
            mapPullingBlocksSpaceNodes.insert({ pfrom, now });
        }
        else {
            if (now - mapPullingBlocksSpaceNodes[pfrom] < 120) {
                //HCE: pulling
                return;
            }
            else {
                mapPullingBlocksSpaceNodes[pfrom] = now;
            }
        }
    }
    CBlockIndexSP pindexOnChained = LatestBlockIndexOnChained();

    pfrom->PushGetBlocks(pindexOnChained, uint256(0));

}

const int SentBlock_TimeOut = 30;

void InsertSentBlock(CNode* pfrom, const uint256 &hashBlock, const uint256 &hashPrevBlock)
{
    if (!pfrom->mapBlockSent.count(hashBlock)) {
        //HCE: clear expired element
        auto now = time(nullptr);
        if (pfrom->mapBlockSent.size() > 1000) {
            //HCE: LRU policy
            auto it = pfrom->listBlockSent.begin();
            for (; it != pfrom->listBlockSent.end(); ) {
                if (std::get<0>((*it)->second) + SentBlock_TimeOut < now) {
                    pfrom->mapBlockSent.erase(*it);
                    pfrom->listBlockSent.erase(it++);
                } else {
                    break;
                }
            }
        }
        auto [it_blksent, success] = pfrom->mapBlockSent.insert(std::make_pair(hashBlock, std::make_tuple(now, hashPrevBlock)));
        if (success) {
            pfrom->listBlockSent.push_back(it_blksent);
        }
    }
}

bool FixBlockIndexofChain(CBlockIndexSP pindexInMain, CBlockIndexSP pindexEnd, CBlockIndexSP &pindexNew)
{
    CBlockIndexSP pindex = pindexBest;
    CBlockIndexSP ppindex = pindex->pprev();
    while (ppindex && (ppindex->nHeight > pindexEnd->nHeight)) {
        pindex = ppindex;
        ppindex = ppindex->pprev();
    }

    if (ppindex) {
        auto pblockindex = mapBlockIndex[ppindex->GetBlockHash()];

        CBlockIndexSP pindexFork = pindexEnd;
        while (pindexFork) {
            if (ppindex == pindexFork ||
                ppindex->GetBlockHash() == pindexFork->GetBlockHash()) {
                //HCE: find fork block
                break;
            }
            if (pindexInMain == pindexFork)
                return false;
            pindexFork = pindexFork->pprev();
            pindex = ppindex;
            ppindex = ppindex->pprev();
        }

        WARNING_FL("Blocks from %d to %d is not in best chain "
            "Fix hashNext of Block index's : %d", ppindex->nHeight+1, pindexEnd->nHeight, ppindex->nHeight);

        CTxDB_Wrapper txdb("r+");
        if(!txdb.TxnBegin())
            return ERROR_FL("%s : TxnBegin failed", __FUNCTION__);

        ppindex->hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(CDiskBlockIndex(ppindex.get()))) {
            txdb.TxnAbort();
            ERROR_FL("WriteBlockIndex failed");
        }

        if (!txdb.TxnCommit())
            ERROR_FL("TxnCommit failed");

        pindexNew = ppindex;
        return true;
    }
    return false;
}

//HCE: reply blocks from low height to high
void ReplyGetBlocks(CNode* pfrom, const uint256 &hashInMain, 
    const uint256 &hashInvContinue,
    const uint256 &hashChkP)
{
    int nLimit = 500;
    int nTotalSendBlock = 0;

    uint256 hashBlock;

    // Find the last block the caller has in the main chain
    CBlockIndexSP pindex;
    do {
        CBlockIndexSP pindexlast;
        if (mapBlockIndex.count(hashChkP)) {
            pindexlast = mapBlockIndex[hashChkP];
            if (pindexlast->IsInMainChain()) {
                pindex = pindexlast;
            }
        }

        if (mapBlockIndex.count(hashInvContinue)) {
            pindexlast = mapBlockIndex[hashInvContinue];
            if (pindexlast->IsInMainChain()) {
                if (!pindex) {
                    pindex = pindexlast;
                }
                else if (pindexlast->nHeight > pindex->nHeight) {
                    //HCE: choose maximum height block index
                    pindex = pindexlast;
                }
            }
        }

        CBlockIndexSP pindexIn;
        if (mapBlockIndex.count(hashInMain)) {
            pindexIn = mapBlockIndex[hashInMain];
            if (pindexIn->IsInMainChain()) {
                if (!pindex) {
                    pindex = pindexIn;
                } else if ( pindexIn->nHeight > pindex->nHeight) {
                    //HCE: choose maximum height block index
                    pindex = pindexIn;
                }
                break;
            }
        }

        //HCE: not found
        if (!pindex) {
            LogRequestFromNode(pfrom->nodeid,
                "\n\nRespond fgetblocks: requesting data(%s %s) not in main chain from: %s ***********************\n",
                hashInMain.ToString().c_str(),
                hashChkP.ToString().c_str(),
                pfrom->nodeid.c_str());
            return;
        }
    } while (false);


    LogRequestFromNode(pfrom->nodeid, "\n\nRespond fgetblocks(%s %s): %d(%s) from: %s ***********************\n",
        hashInMain.ToString().c_str(),
        hashChkP.ToString().c_str(),
        pindex->nHeight,
        pindex->GetBlockHash().ToPreViewString().c_str(), pfrom->nodeid.c_str());

    CBlockIndexSP pindexInMain = pindex;

    // Send the rest of the chain
    CBlockIndexSP pprevindex = pindex;
    if (pindex) {
        pindex = pindex->pnext();
    }
    unsigned int nBytes = 0;
    for (; pindex; pprevindex = pindex, pindex = pindex->pnext()) {

        if (!pindex->pnext() && pindex->nHeight < pindexBest->nHeight) {
            //HCE: index data of block's pnext has problem
            CBlockIndexSP pNew;

            WARNING_FL("Try to fix block index...%d", pindex->nHeight);
            if (FixBlockIndexofChain(pindexInMain, pindex, pNew)) {
                pindex = pNew;
                continue;
            }
            break;
        }

        if (pprevindex->GetBlockHash() != pindex->hashPrev) {
            //HCE: index data of block's has problem
            ERROR_FL("Find issue in block index: %d, please restart to fix with '-scanbestindex'", pprevindex->nHeight);
            break;
        }

        if (nTotalSendBlock >= nLimit) {
            LogRequestFromNode(pfrom->nodeid, "  fgetblocks limit(%d) stoppped at: %s\n",
                nTotalSendBlock,
                pindex->GetBlockHash().ToPreViewString().c_str());
            break;
        }

        hashBlock = pindex->GetBlockHash();

        if (mapBlockIndex.count(hashBlock)) {

            CInv inv(MSG_BLOCKEX, hashBlock);
            inv.height = pindex->nHeight;
            pfrom->PushInventory(inv);

            nTotalSendBlock++;
            continue;
        } else {
            string hashpreview = hashBlock.ToPreViewString().c_str();
            LogRequestFromNode(pfrom->nodeid, "  fgetblocks (%d) stoppped at: %s due to no found\n",
                nTotalSendBlock,
                hashpreview);
        }
        break;
    }
    LogRequestFromNode(pfrom->nodeid, "  fgetblocks (%d) \n", nTotalSendBlock);
}

bool GetBlockData(const uint256& hashBlock, CBlock& block, BLOCKTRIPLEADDRESS& addrblock, char **pWhere)
{
    addrblock = BLOCKTRIPLEADDRESS();

    auto mi = mapBlockIndex[hashBlock];
    if (mi) {
        if (block.ReadFromDisk(mi)) {
            addrblock = mi->triaddr;
            *pWhere = "mapBlockIndex";
            return true;
        }
    } else if (mapOrphanBlocks.count(hashBlock)) {
        block = *(mapOrphanBlocks[hashBlock]);
        addrblock = block.tripleaddr;
        *pWhere = "mapOrphanBlocks";
        return true;
    } else if (block.ReadFromMemoryPool(hashBlock)) {
        *pWhere = "blockcache\n";
        return true;
    }

    TRACE_FL("I have not Block: %s\n", hashBlock.ToPreViewString().c_str());
    return false;
}

bool ProcessReceivedTx(CNode * pfrom, CTransaction &tx)
{
    vector<uint256> vWorkQueue;
    CDataStream vMsg;
    vMsg << tx;

    CInv inv(MSG_TX, tx.GetHash());
    if(pfrom)
        pfrom->AddInventoryKnown(inv);

    bool fMissingInputs = false;
    tx.m_strRunTimeErr = "";
    if (tx.AcceptToMemoryPool(true, &fMissingInputs)) {
        SyncWithWallets(tx, NULL, true);
        RelayMessage(inv, vMsg);
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            mapAlreadyAskedFor.erase(inv);
        vWorkQueue.push_back(inv.hash);

        // Recursively process any orphan transactions that depended on this one
        for (int i = 0; i < vWorkQueue.size(); i++) {
            uint256 hashPrev = vWorkQueue[i];
            for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                ++mi) {
                const CDataStream& vMsg = *((*mi).second);
                CTransaction tx;
                CDataStream(vMsg) >> tx;
                CInv inv(MSG_TX, tx.GetHash());

                if (tx.AcceptToMemoryPool(true)) {
                    TRACE_FL("   accepted orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
                    SyncWithWallets(tx, NULL, true);
                    RelayMessage(inv, vMsg);
                    CRITICAL_BLOCK(cs_mapAlreadyAskFor)
                        mapAlreadyAskedFor.erase(inv);
                    vWorkQueue.push_back(inv.hash);
                }
            }
        }

        BOOST_FOREACH(uint256 hash, vWorkQueue)
            EraseOrphanTx(hash);
    } else {
        if (fMissingInputs) {
            TRACE_FL("storing orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
            AddOrphanTx(vMsg);
            return false;
        }
        return false;
    }

    return true;
}

std::set<string> setNonLockCommands = {
    "verack", "addr", "getdata", "fgetblocks", "rgetblocks", "getblocks", "getheaders", "rblock",
    "getaddr", "ping", "pong",
    "checkorder", "reply",
    //
    "checkblock", "getchkblock"
};

std::unordered_map<string, std::function<bool(CNode*, CDataStream&)>> mapRecvMessages = {
    {"version",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        static int nAskedForBlocks = 0;
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            // tell version,under udp environment, maybe node hasn't still received the verack message.
            TRACE_FL("I had its version information,Maybe it has restarted, so update version. (%s)", pfrom->addr.ToString().c_str());
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        recvMsg >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (pfrom->nVersion >= 106 && !recvMsg.empty())
            recvMsg >> addrFrom >> nNonce;
        if (pfrom->nVersion >= 106 && !recvMsg.empty())
            recvMsg >> pfrom->strSubVer;
        if (pfrom->nVersion >= 209 && !recvMsg.empty())
            recvMsg >> pfrom->nStartingHeight;

        if (pfrom->nVersion == 0)
            return false;

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1) {
            WARNING_FL("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        // Be shy and don't send version until we hear
        //if (pfrom->fInbound)
        //    pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr.ip, nTime);

        // Change version
        if (pfrom->nVersion >= 209)
            pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        if (pfrom->nVersion < 209)
            pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        if (!pfrom->fInbound) {
            // Advertise our address
            if (addrLocalHost.IsRoutable() && !fUseProxy) {
                CAddress addr(addrLocalHost);
                addr.nTime = GetAdjustedTime();
                pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->nVersion >= 31402 || mapAddresses.size() < 1000) {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
        }

        // Ask the first connected node for block updates
        if (!pfrom->fClient &&
            (pfrom->nVersion < 32000 || pfrom->nVersion >= 32400) &&
            //(nAskedForBlocks < 1 || vNodes.size() <= 1))
            (nAskedForBlocks < 1 || vNodes.size() <= 1)) {
            nAskedForBlocks++;
            RequestBlockSpace(pfrom);
        }

        // Relay alerts
        CRITICAL_BLOCK(cs_mapAlerts)
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert) & item, mapAlerts)
            item.second.RelayTo(pfrom);

        pfrom->fSuccessfullyConnected = true;

        pfrom->Ping();
        pfrom->PushChkBlock();
        TRACE_FL("version message: version %d, blocks=%d\n", pfrom->nVersion, pfrom->nStartingHeight);
        return true;
        } },

    {"veragain",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        pfrom->PushVersion();
        return true;
        } },

    {"verack",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));
        return true;
        } },

    {"addr",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        vector<CAddress> vAddr;
        recvMsg >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < 209)
            return true;
        if (pfrom->nVersion < 31402 && mapAddresses.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
            return ERROR_FL("message addr size() = %d", vAddr.size());

        // Store the new addresses
        CAddrDB addrDB;
        addrDB.TxnBegin();
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress & addr, vAddr)
        {
            if (fShutdown) {
                addrDB.TxnAbort();
                return true;
            }
            // ignore IPv6 for now, since it isn't implemented anyway
            if (!addr.IsIPv4())
                continue;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            AddAddress(addr, 2 * 60 * 60, &addrDB);
            pfrom->AddAddressKnown(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                CRITICAL_BLOCK(cs_vNodes)
                {
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        RAND_bytes((unsigned char*)&hashSalt, sizeof(hashSalt));
                    uint256 hashRand = hashSalt ^ (((int64)addr.ip) << 32) ^ ((GetTime() + addr.ip) / (24 * 60 * 60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode * pnode, vNodes)
                    {
                        if (pnode->nVersion < 31402)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = 2;
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
        }
        addrDB.TxnCommit();  // Save addresses (it's ok if this fails)
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        return true;
        } },

    {"inv",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        vector<CInv> vInv;
        recvMsg >> vInv;
        if (vInv.size() > 50000)
            return ERROR_FL("message inv size() = %d", vInv.size());

        CTxDB_Wrapper txdb;
        int nSize = vInv.size();
        int nHaving = 0;

        BOOST_FOREACH(const CInv & inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            if (inv.type == MSG_BLOCKEX) {
                pfrom->FPullBlockReached(inv);
                continue;
            }

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (fAlreadyHave) {
                nHaving++;
            }

            bool fAskFor = false;
            bool fPushGetBlocks = false;
            if (!fAlreadyHave) {
                pfrom->AskFor(inv);
                fAskFor = true;
            } else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                if (g_miningCond.IsMining()) {
                    pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash].get()));
                    fPushGetBlocks = true;
                }
            }

            DEBUG_FL("  got inventory: %s  %s, askfor: %s PGetBlocks: %s, from: %s\n", inv.ToString().c_str(),
                fAlreadyHave ? "have" : "new",
                fAskFor ? "y" : "n",
                fPushGetBlocks ? "y" : "n",
                pfrom->nodeid.c_str());

            // Track requests for our stuff
            Inventory(inv.hash);
        }

        return true;
        } },

    {"getdata",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        vector<CInv> vInv;
        int64 timerequest;
        recvMsg >> vInv >> timerequest;
        if (vInv.size() > 50000)
            return ERROR_FL("message getdata size() = %d", vInv.size());

        //outputlog(strprintf("Received getdata %d \n", vInv.size()));

        std::set<uint256> setBlockSended; //HCE: avoid to send the same block repeatedly
        BOOST_FOREACH(const CInv & inv, vInv)
        {
            if (fShutdown)
                return true;
            //outputlog(strprintf("received getdata for: %s\n", inv.ToString().c_str()));

            TRACE_FL("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK || inv.type == MSG_BLOCKEX || inv.type == MSG_BLOCKEX_R) {
                // Send block from disk
                CBlock block;
                BLOCKTRIPLEADDRESS addrblock;
                char* pWhere = nullptr;
                if (!setBlockSended.count(inv.hash) && GetBlockData(inv.hash, block, addrblock, &pWhere)) {
                    //HCE: send block address at the same time
                    //outputlog(strprintf("reply block: %d, %s\n", block.nHeight, addrblock.tostring().c_str()));
                    if (pfrom->nVersion > VERSION_V72) {
                        //HCE: v73 added
                        pfrom->PushMessage("blockz", block, addrblock, timerequest, GetTime());
                    }
                    else {
                        T_LOCALBLOCKADDRESS laddr = addrblock.ToAddr();
                        pfrom->PushMessage("block", block, laddr.hid, laddr.chainnum, laddr.id);
                    }
                    setBlockSended.insert(inv.hash);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue) {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType()) {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
        return true;
        } },


    //HC: 拉取区块hash清单
    {"fgetblocks",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        uint256 hashfork;
        uint256 hashInvContinue;
        uint256 hashChkP;
        recvMsg >> hashfork;
        recvMsg >> hashInvContinue;
        recvMsg >> hashChkP;
        ReplyGetBlocks(pfrom, hashfork, hashInvContinue, hashChkP);

        return true;
        } },

    {"getblocks",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        CBlockLocator locator;
        uint256 hashStop;
        recvMsg >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndexSP pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext();
        int nLimit = 25; //500 +locator.GetDistanceBack();
        TRACE_FL("\n\nRespond**************************************\n");
        TRACE_FL("getblocks %d to %s limit %d from node: %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0, 20).c_str(),
            nLimit,
            pfrom->nodeid.c_str());
        for (; pindex; pindex = pindex->pnext()) {
            if (pindex->GetBlockHash() == hashStop) {
                TRACE_FL("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str());
                break;
            }

            TRACE_FL("getblocks send %s(%s) to node: %s\n", pindex->GetBlockHash().ToPreViewString().c_str(),
                pindex->triaddr.ToString().c_str(),
                pfrom->nodeid.c_str());
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0 ) {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                TRACE_FL("  getblocks stopping at limit %d %s \n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
        return true;
        } },

    //HC: deprecated
    {"getheaders",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        CBlockLocator locator;
        uint256 hashStop;
        recvMsg >> locator >> hashStop;

        CBlockIndexSP pindex;
        if (locator.IsNull()) {
            // If locator is null, return the hashStop block
            auto mi = mapBlockIndex[hashStop];
            if (!mi)
                return true;
            pindex = mi;
        }
        else {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext();
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000 + locator.GetDistanceBack();
        TRACE_FL("getheaders %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0, 20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext()) {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
        return true;
        } },

    {"tx",[](CNode* pfrom, CDataStream& recvMsg) ->bool {

        CTransaction tx;
        recvMsg >> tx;
        pfrom->UpdateNodeRating(1);
        return ProcessReceivedTx(pfrom, tx);

        } },

    {"block",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        CBlock block;
        recvMsg >> block;

        T_LOCALBLOCKADDRESS addrblock;

        recvMsg >> addrblock.hid;  //HCE: here hid type is uint64
        recvMsg >> addrblock.chainnum;
        recvMsg >> addrblock.id;

        uint256 hash = block.GetHash();
        DEBUG_FL("Received block %s from %s, triple address: %s\n", hash.ToString().substr(0, 20).c_str(),
            pfrom->nodeid.c_str(), addrblock.tostring().c_str());

        pfrom->UpdateNodeRating(2);

        ProcessBlock(pfrom, &block);

        CInv inv(MSG_BLOCK, hash);
        pfrom->AddInventoryKnown(inv);
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            mapAlreadyAskedFor.erase(inv);

        return true;
        } },

    {"blockz",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        CBlock block;
        recvMsg >> block;

        BLOCKTRIPLEADDRESS addrblock;
        recvMsg >> addrblock;

        int64 timerequest, timereply;
        recvMsg >> timerequest >> timereply;

        int64 elapsedsec = GetTime() - timerequest;
        uint256 hash = block.GetHash();

        pfrom->UpdateNodeRating(30 - elapsedsec); //HC: 30秒内完成得到正反馈，否则为负
    #ifdef COST_PARSE
        CSpentTime t;
    #endif

        ProcessBlockWithTriaddr(pfrom, &block, &addrblock);

    #ifdef COST_PARSE
        string info = StringFormat("%s blockz %s(%d) from %s, tripleaddr: %s request: %s reply: %s %d %d(s) Process: %d(ms)\n",
            currentTime(),
            hash.ToString().substr(0, 20),
            block.nHeight,
            pfrom->nodeid.c_str(), addrblock.ToString(),
            DateTimeStrFormat("%H:%M:%S", timerequest),
            DateTimeStrFormat("%H:%M:%S", timereply),
            (GetTime() - timereply),
            elapsedsec,
            t.Elapse()
        );
        LogCostParse("%s", info.c_str());
    #endif
        CInv inv(MSG_BLOCK, hash);
        pfrom->AddInventoryKnown(inv);
        CRITICAL_BLOCK(cs_mapAlreadyAskFor)
            mapAlreadyAskedFor.erase(inv);
        return true;
        } },

    {"getaddr",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
            // Nodes rebroadcast an addr every 24 hours
        pfrom->vAddrToSend.clear();
        int64 nSince = GetAdjustedTime() - 3 * 60 * 60; // in the last 3 hours
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            unsigned int nCount = 0;
            BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, CAddress) & item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (addr.nTime > nSince)
                    nCount++;
            }
            BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, CAddress) & item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (addr.nTime > nSince && GetRand(nCount) < 2500)
                    pfrom->PushAddress(addr);
            }
        }
        return true;
        } },

    {"checkorder",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        static map<unsigned int, vector<unsigned char> > mapReuseKey;

        uint256 hashReply;
        recvMsg >> hashReply;

        if (!GetBoolArg("-allowreceivebyip")) {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        recvMsg >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr.ip], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);

        return true;
        } },

    {"reply",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        uint256 hashReply;
        recvMsg >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end()) {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, recvMsg);

        return true;
        } },

    {"ping",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        if (pfrom->nVersion >= VERSION_V72) {
            int64 timeReq;
            recvMsg >> timeReq;
            pfrom->PushMessage("pong", timeReq);
        }
        return true;
        } },

    { "pong",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        int64 timeReq;
        recvMsg >> timeReq;
        pfrom->Pong(timeReq);

        return true;
        } },


    {"alert",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        CAlert alert;
        recvMsg >> alert;

        if (alert.ProcessAlert()) {
            // Relay
            pfrom->setKnown.insert(alert.GetHash());
            CRITICAL_BLOCK(cs_vNodes)
                BOOST_FOREACH(CNode * pnode, vNodes)
                alert.RelayTo(pnode);
        }

        return true;
        } },

    {"checkblock",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        if (pfrom->nVersion > 0) {
            if (pfrom->nVersion >= VERSION_V72) {
                CBlockLocatorExIncr chainincr;
                ChkPointInc diff(pfrom->chkpoint, &chainincr);
                recvMsg >> diff;
                pfrom->chkpoint.Merge(diff);
            }
            else {
                recvMsg >> pfrom->chkpoint.nBstH;
                recvMsg >> pfrom->chkpoint.bestHash;
            }
            pfrom->tmlastgotchkp = time(nullptr);
        }

        pfrom->UpdateNodeRating(11);
        DEBUG_FL("received check point block: %s from %s\n",
            pfrom->chkpoint.ToString().c_str(), pfrom->nodeid.c_str());
        return true;
        } },

    {"getchkblock",[](CNode* pfrom, CDataStream& recvMsg) ->bool {
        DEBUG_FL("getchkblock from %s\n", pfrom->nodeid.c_str());
        if (ChkPoint::GetCurrent(mychkp)) {
            if (pfrom->nVersion > 0) {
                if (pfrom->nVersion >= VERSION_V72) {
                    uint256 hash_end_vhave;
                    uint256 hash_end_vhavetail;
                    recvMsg >> hash_end_vhave;
                    recvMsg >> hash_end_vhavetail;

                    CBlockLocatorExIncr chainincr;
                    paramqcenter.MTC_ComputeDiff(hash_end_vhave, hash_end_vhavetail, chainincr);
                    ChkPointInc diff(mychkp, &chainincr);
                    pfrom->PushMessage("checkblock", diff);
                }
                else {
                    pfrom->PushMessage("checkblock", mychkp.nBstH, mychkp.bestHash);
                }
            }
            DEBUG_FL("getchkblock reply: %s from %s\n", mychkp.ToString().c_str(), pfrom->nodeid.c_str());
            pfrom->UpdateNodeRating(-10);
        }
        return true;
        } },
};


typedef struct
{
    int nTimes = 0;
    int64 tmUsed = 0;
    int64 tmTotalUsed = 0;
    int tmMax = 0;
} COMMCOST;

map<string, COMMCOST> g_commcost;

string GetCommandsCost()
{
    stringstream ss;
    ss << strprintf("%16s %8s %12s %12s %12s %12s\n",
        "command", "Times", "Total(ms)", "Average(ms)", "Used(ms)", "Max(ms)");
    for (auto& elm : g_commcost) {
        ss << strprintf("%16s %8d %12" PRI64d " %12.1f %12" PRI64d " %12d\n",
            elm.first.c_str(),
            elm.second.nTimes,
            elm.second.tmTotalUsed,
            (float)elm.second.tmTotalUsed / elm.second.nTimes,
            elm.second.tmUsed,
            elm.second.tmMax
        );
    }
    return ss.str();

}


bool static ProcessMessage(CNode* pfrom, const string &strCommand, CDataStream& recvMsg)
{
    RandAddSeedPerfmon();
    TRACE_FL("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    TRACE_FL("received: %s (%d bytes)\n", strCommand.c_str(), recvMsg.size());

    pfrom->tmlastProcessRecv = time(nullptr);
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)     {
        TRACE_FL("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    defer{
        // Update the last seen time for this node's address
        if (pfrom->fNetworkNode) {
            if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
                AddressCurrentlyConnected(pfrom->addr);
        }
    };

    pfrom->UpdateNodeRating(1);
    if (strCommand == "version" || strCommand == "veragain") {
        return mapRecvMessages[strCommand](pfrom, recvMsg);
    }

    //HC: 不同版本有不同的数据通讯格式，所以必须有版本号才能开始交互
    //HCE: Different versions have different data communication formats, so you must have a version number to start the interaction
    if (pfrom->nVersion == 0)     {
        // Must have a version message before anything else
        TRACE_FL("I have not yet node version info, Maybe myself restarted, please tell me again. (%s)", pfrom->addr.ToString().c_str());
        //HCE: I think his version is VERSION_1 which is first version
        //pfrom->nVersion = VERSION_1;
        pfrom->PushMessage("veragain");
    } else if (mapRecvMessages.count(strCommand)) {

        int64 nCost = 0;
        if (setNonLockCommands.count(strCommand)) {
            nCost = GetTimeMillis();
            mapRecvMessages[strCommand](pfrom, recvMsg);
        }
        else {
            CRITICAL_BLOCK_T_MAIN(cs_main)
            {
                nCost = GetTimeMillis();
                mapRecvMessages[strCommand](pfrom, recvMsg);
            }
        }

        g_commcost[strCommand].tmUsed += GetTimeMillis() - nCost;
        if (g_commcost[strCommand].tmMax < GetTimeMillis() - nCost) {
            g_commcost[strCommand].tmMax = GetTimeMillis() - nCost;
        }
    }

    return true;
}


bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    int nRecvDataLen = vRecv.size();

    const int nBaseHandleTime = 300; //ms
    int allowedtime = 0;

    //HCE: To improve performance, reduce the divide operation
    if (nRecvDataLen < 1024) {
        allowedtime = nBaseHandleTime;
    } else if(nRecvDataLen < 2048) {
        allowedtime = 2 * nBaseHandleTime;
    } else {
        allowedtime = vRecv.size() / 1024 * nBaseHandleTime;
    }

    int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());

    CSpentTime spent;
    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vRecv.end() - pstart < nHeaderSize)         {
            if (vRecv.size() > nHeaderSize)             {
                WARNING_FL("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            WARNING_FL("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())         {
            ERROR_FL("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE)         {
            ERROR_FL("ProcessMessage(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size())         {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        if (vRecv.GetVersion() >= 209)         {
            uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            if (nChecksum != hdr.nChecksum)             {
                ERROR_FL("ProcessMessage(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
                       strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
                continue;
            }
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try {
            if (hyperblockMsgs.size() > 0) {
                //HCE: Process hyper block reached message
                CRITICAL_BLOCK_T_MAIN(cs_main)
                    hyperblockMsgs.process();
            }

            int64 nCost = GetTimeMillis();
            fRet = ProcessMessage(pfrom, strCommand, vMsg);
            g_commcost[strCommand].nTimes++;
            g_commcost[strCommand].tmTotalUsed += GetTimeMillis() - nCost;


            if (spent.Elapse() > allowedtime)
                break;
            if (fShutdown) {
                break;
            }
        }
        catch (std::ios_base::failure& e)         {
            if (strstr(e.what(), "end of data"))             {
                // Allow exceptions from underlength message on vRecv
                ERROR_FL("ProcessMessage(%s, %u bytes) from %s : Exception '%s' caught, normally caused by a message being shorter than its stated length\n",
                    strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
            }
            else if (strstr(e.what(), "size too large"))             {
                // Allow exceptions from overlong size
                ERROR_FL("ProcessMessage(%s, %u bytes) from %s : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
            }
            else             {
                PrintExceptionContinue(&e, "ProcessMessage()");
            }
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessage()");
        }
        catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessage()");
        }

        if (!fRet)
            ERROR_FL("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    //HCE: We can remove cs_main
    //CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty()) {
            pto->Ping();
        }

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (GetTime() - nLastRebroadcast > 24 * 60 * 60)         {
            nLastRebroadcast = GetTime();
            CRITICAL_BLOCK(cs_vNodes)
            {
                BOOST_FOREACH(CNode * pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (addrLocalHost.IsRoutable() && !fUseProxy)                     {
                        CAddress addr(addrLocalHost);
                        addr.nTime = GetAdjustedTime();
                        pnode->PushAddress(addr);
                    }
                }
            }
        }

        // Clear out old addresses periodically so it's not too much work at once
        static int64 nLastClear;
        if (nLastClear == 0)
            nLastClear = GetTime();
        if (GetTime() - nLastClear > 10 * 60 && vNodes.size() >= 3)         {
            nLastClear = GetTime();
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                CAddrDB addrdb;
                int64 nSince = GetAdjustedTime() - 14 * 24 * 60 * 60;
                for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.begin();
                    mi != mapAddresses.end();)                 {
                    const CAddress& addr = (*mi).second;
                    if (addr.nTime < nSince)                     {
                        if (mapAddresses.size() < 1000 || GetTime() > nLastClear + 20)
                            break;
                        addrdb.EraseAddress(addr);
                        mapAddresses.erase(mi++);
                    }
                    else
                        mi++;
                }
            }
        }


        //
        // Message: addr
        //
        if (fSendTrickle)         {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress & addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)                 {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)                     {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        if (pto->vInventoryToSend.size() > 0) {
            vector<CInv> vInv;
            vector<CInv> vInvWait;
            CRITICAL_BLOCK(pto->cs_inventory)
            {
                vInv.reserve(pto->vInventoryToSend.size());
                vInvWait.reserve(pto->vInventoryToSend.size());
                BOOST_FOREACH(const CInv & inv, pto->vInventoryToSend)
                {
                    //HCE:
                    //if (pto->setInventoryKnown.count(inv))
                    //    continue;

                    // trickle out tx inv to protect privacy
                    if (inv.type == MSG_TX && !fSendTrickle)                 {
                        // 1/4 of tx invs blast to all immediately
                        static uint256 hashSalt;
                        if (hashSalt == 0)
                            RAND_bytes((unsigned char*)&hashSalt, sizeof(hashSalt));
                        uint256 hashRand = inv.hash ^ hashSalt;
                        hashRand = Hash(BEGIN(hashRand), END(hashRand));
                        bool fTrickleWait = ((hashRand & 3) != 0);

                        // always trickle our own transactions
                        if (!fTrickleWait)                     {
                            CWalletTx wtx;
                            if (GetTransaction(inv.hash, wtx))
                                if (wtx.fFromMe)
                                    fTrickleWait = true;
                        }

                        if (fTrickleWait)                     {
                            vInvWait.push_back(inv);
                            continue;
                        }
                    }

                    // returns true if wasn't already contained in the set
                    //printf("  setInventoryKnown size: %u  pto: %s\n", pto->setInventoryKnown.size(), pto->nodeid.c_str());
                    //HCE: remove send cache
                    //if (pto->setInventoryKnown.insert(inv).second)
                    {
                        TRACE_FL("  send inventory: %s to: %s\n", inv.ToString().c_str(), pto->nodeid.c_str());

                        vInv.push_back(inv);
                        if (vInv.size() >= 1000)                     {
                            pto->PushMessage("inv", vInv);
                            vInv.clear();
                        }
                    }
                }
                pto->vInventoryToSend = vInvWait;
            }
            if (!vInv.empty())
                pto->PushMessage("inv", vInv);
        }

        //
        // Message: getdata
        //
        if (!pto->mapAskFor.empty()) {
            vector<CInv> vGetData;
            int64 nNow = GetTime() * 1000000;
            CTxDB_Wrapper txdb;
            CRITICAL_BLOCK(pto->cs_askfor)
                while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).tmaskfor <= nNow) {
                    const CInv& inv = (*pto->mapAskFor.begin()).inv;
                    if (!AlreadyHave(txdb, inv)) {
                        TRACE_FL("sending getdata: %s to %s\n",
                            inv.ToString().c_str(), pto->addr.ToString().c_str());
                        vGetData.push_back(inv);
                        if (vGetData.size() >= 20) {
                            pto->PushMessage("getdata", vGetData, GetTime()); //HC: with current time
                            vGetData.clear();
                        }
                    }

                    CRITICAL_BLOCK(cs_mapAlreadyAskFor)
                        mapAlreadyAskedFor[inv] = nNow;
                    pto->mapAskFor.erase(pto->mapAskFor.begin());
                }
            if (!vGetData.empty())
                pto->PushMessage("getdata", vGetData, GetTime());
        }
    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;

static const unsigned int pSHA256InitState[8] =
{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

inline void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    memcpy(pstate, pinit, 32);
    CryptoPP::SHA256::Transform((CryptoPP::word32*)pstate, (CryptoPP::word32*)pinput);
}

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
unsigned int static ScanHash_CryptoPP(char* pmidstate, char* pdata, char* phash1, char* phash, unsigned int& nHashesDone)
{
    unsigned int& nNonce = *(unsigned int*)(pdata + 12);
    for (;;)     {
        // Crypto++ SHA-256
        // Hash pdata using pmidstate as the starting state into
        // preformatted buffer phash1, then hash phash1 into phash
        nNonce++;
        SHA256Transform(phash1, pdata, pmidstate);
        SHA256Transform(phash, phash1, pSHA256InitState);

        //HCE: Return the nonce if the hash has at least some zero bits,
        //HCE: caller will check if it has enough to reach the target
        if (((unsigned short*)phash)[14] == 0)
            return nNonce;

        //HCE: If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)         {
            nHashesDone = 0xffff + 1;
            return -1;
        }
    }
}

//HCE: Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f)\n", ptx->GetHash().ToString().substr(0, 10).c_str(), dPriority);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0, 10).c_str());
    }
};


void ReadTrans(map<uint256, CTransaction>& mapTrans)
{
    string txfilename = mapArgs["-importtx"];

    uint32_t genesisHID;
    uint32_t genesisChainNum;
    uint32_t genesisID;

    using PUBKEY = std::vector<unsigned char>;
    map<PUBKEY, int64> mapPubKeyWallet;

    FILE* fp = std::fopen(txfilename.c_str(), "r");
    if (!fp) {
        throw runtime_error(strprintf("cannot open file: %s\n", txfilename.c_str()));
    }

    int rs = std::fscanf(fp, "Triple address: %u %u %u", &genesisHID, &genesisChainNum, &genesisID);
    cout << strprintf("Got old chain genesis block triple address: %u %u %u\n", genesisHID, genesisChainNum, genesisID);

    CommadLineProgress progress;
    progress.Start();

    int64 nCount = 0;
    int64 nLast = 0;
    for (;; nCount++) {

        int64 nValue = 0;
        char pubkey[512] = { 0 };

        rs = std::fscanf(fp, "%s : %llu", pubkey, &nValue);
        if (rs == EOF) {
            break;
        }

        PUBKEY vchPubKey = ParseHex(pubkey);
        if (mapPubKeyWallet.count(vchPubKey)) {
            mapPubKeyWallet[vchPubKey] += nValue;
        }
        else {
            mapPubKeyWallet.insert(make_pair(vchPubKey, nValue));
        }

        if (nCount - nLast > 10000) {
            pubkey[16] = '\0';
            progress.PrintStatus(nCount - nLast, strprintf("%s...: %llu", pubkey, nValue).c_str());
            nLast = nCount;
        }
    }

    if (std::ferror(fp)) {
        throw runtime_error(strprintf("I/O error when reading transaction file: %s\n", txfilename.c_str()));
    }
    std::fclose(fp);

    cout << strprintf("\nGot %u transactions\n", mapPubKeyWallet.size());

    //HCE: Create Transactions
    for (auto& elm : mapPubKeyWallet) {
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        txNew.vout.resize(1);
        txNew.vout[0].scriptPubKey << elm.first << OP_CHECKSIG;

        txNew.vout[0].nValue = elm.second;

        mapTrans[txNew.GetHash()] = txNew;
    }
}

CBlock* CreateBlockBuiltIn(CReserveKey& reservekey, int& nTxCountInblock)
{
    //HCE: Create new block
    CBlock* pblock = new CBlock();
    if (!pblock)
        return NULL;

    //HCE: Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = reservekey.GetDefaultKeyScript();

    //HCE: Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    //HCE: Collect memory pool transactions into the block
    int64 nFees = 0;
    CRITICAL_BLOCK_T_MAIN(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
    {
        //HCE: Priority order to process transactions
        uint64 nBlockSize = 1000;
        int nBlockSigOps = 100;

        //HCE: Collect transactions into block
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end();) {
            CTransaction& tx = (*mi).second;

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
            if (nBlockSize + nTxSize >= (MAX_BLOCK_SIZE - 2048))
                break;
            int nTxSigOps = tx.GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                break;

            // Added
            nTxCountInblock++;
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            nBlockSigOps += nTxSigOps;

            mapTransactions.erase(mi++);
        }
    }
    return pblock;
}

void UpdateBlockBuiltIn(CBlock* pblock)
{
    CRITICAL_BLOCK_T_MAIN(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
    {
        pblock->SetHyperBlockInfo();
        CBlockIndex* pindexPrev = pindexBest.get();
        pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight + 1, 0);

        //HCE: Randomise nonce for new block format.
        uint256 nonce;
        nonce = GetRandHash();

        //HCE: Clear the top and bottom 16 bits (for local use as thread flags and counters)
        nonce <<= 32;
        nonce >>= 16;

        //HCE: Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        pblock->nHeight = pindexPrev->nHeight + 1;
        memset(pblock->nReserved, 0, sizeof(pblock->nReserved));

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
        pblock->nBits = 0x2100ffff;// GetNextWorkRequired(pindexPrev);
        pblock->nNonce = nonce.GetUint64(3);
        pblock->nSolution.clear();
    }
}

CBlock* CreateNewBlock(CReserveKey& reservekey, const char* pszAddress)
{
    //HCE: Create new block
    CBlock* pblock(new CBlock());
    if (!pblock)
        return nullptr;

    //HCE: Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();

    int ntx = 1;
    ntx = pszAddress ? 2 : 1;

    txNew.vout.resize(ntx);

    //HCE: use default key script
    txNew.vout[0].scriptPubKey = reservekey.GetDefaultKeyScript();

    if (pszAddress) {
        //HCE: The second output of coinbase tx will use as a reward to light node
        CTxDestination address = DecodeDestination(pszAddress);
        if (!IsValidDestination(address))
            return nullptr;
        txNew.vout[1].scriptPubKey = GetScriptForDestination(address);
    }

    //HCE: Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    //HCE: Collect memory pool transactions into the block
    int64 nFees = 0;
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            pblock->SetHyperBlockInfo();
            CBlockIndexSP pindexPrev = pindexBest;
            CTxDB_Wrapper txdb;

            //HCE: Priority order to process transactions
            list<COrphan> vOrphan;          // list memory doesn't move
            map<uint256, vector<COrphan*> > mapDependers;
            multimap<double, CTransaction*> mapPriority;
            for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi)             {
                CTransaction& tx = (*mi).second;
                if (tx.IsCoinBase() || !tx.IsFinal())
                    continue;

                COrphan* porphan = NULL;
                double dPriority = 0;
                BOOST_FOREACH(const CTxIn & txin, tx.vin)
                {
                    //HCE: Read prev transaction
                    CTransaction txPrev;
                    CTxIndex txindex;
                    CBlockIndex idxBlock;

                    bool istxok = txPrev.ReadFromDisk(txdb, txin.prevout, txindex);
                    if (!istxok) {
                        //HCE: Has to wait for dependencies
                        if (!porphan)                         {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);
                        continue;
                    }
                    int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;

                    // Read block header
                    //HC: 深度越大越好，深度指交易所在块距离最优链最后块的块数
                    //HCE: The greater the depth, the better, and depth refers to the number of blocks on the exchange at the end of the optimal chain
                    int nConf = txindex.GetDepthInMainChain();

                    dPriority += (double)nValueIn * nConf;

                    if (GetBoolArg("-printpriority"))
                        DEBUG_FL("priority     nValueIn=%-12I64d nConf=%-5d dPriority=%-20.1f\n", nValueIn, nConf, dPriority);
                }

                // Priority is sum(valuein * age) / txsize
                //HC: 计算单位size的优先级
                //HCE: Calculate the priority of the unit size
                dPriority /= ::GetSerializeSize(tx, SER_NETWORK);

                if (porphan)
                    porphan->dPriority = dPriority;
                else
                    //HC: dPriority取负数确保高优先级排在map的前面
                    //HCE: dPriority takes a negative number to ensure that high priority is ranked first in the map
                    mapPriority.insert(make_pair(-dPriority, &(*mi).second));

                if (GetBoolArg("-printpriority")) {
                    DEBUG_FL("priority %-20.1f %s\n%s", dPriority, tx.GetHash().ToString().substr(0, 10).c_str(), tx.ToString().c_str());
                    if (porphan)
                        porphan->print();
                    DEBUG_FL("\n");
                }
            }

            //HCE: Collect transactions into block
            map<uint256, std::tuple<CTxIndex, CTransaction>> mapTestPool;
            uint64 nBlockSize = 1000;
            int nBlockSigOps = 100;
            while (!mapPriority.empty())             {
                //HCE: Take highest priority transaction off priority queue
                double dPriority = -(*mapPriority.begin()).first;
                CTransaction& tx = *(*mapPriority.begin()).second;
                mapPriority.erase(mapPriority.begin());

                // Size limits
                unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
                if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN)
                    continue;
                int nTxSigOps = tx.GetSigOpCount();
                if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                    continue;

                //HCE: Transaction fee required depends on block size
                bool fAllowFree = (nBlockSize + nTxSize < 4000 || CTransaction::AllowFree(dPriority));
                int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, true);

                //HCE: Connecting shouldn't fail due to dependency on other memory pool transactions
                //HCE: because we're already processing them in order of dependency
                map<uint256, std::tuple<CTxIndex, CTransaction>> mapTestPoolTmp(mapTestPool);
                map<uint256, CCrossChainTxIndex> mapCCUnused;
                if (!tx.ConnectInputs(txdb, mapTestPoolTmp, mapCCUnused, CDiskTxPos(1), pindexPrev, nFees, false, true, nMinFee))
                    continue;
                swap(mapTestPool, mapTestPoolTmp);

                // Added
                pblock->vtx.push_back(tx);
                nBlockSize += nTxSize;
                nBlockSigOps += nTxSigOps;

                //HCE: Add transactions that depend on this one to the priority queue
                uint256 hash = tx.GetHash();
                if (mapDependers.count(hash))                 {
                    BOOST_FOREACH(COrphan * porphan, mapDependers[hash])
                    {
                        if (!porphan->setDependsOn.empty())                         {
                            porphan->setDependsOn.erase(hash);
                            if (porphan->setDependsOn.empty())
                                mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
                        }
                    }
                }
            }

            int64 nValue = GetBlockValue(pindexPrev->nHeight + 1, nFees);
            pblock->vtx[0].vout[0].nValue = nValue;

            if (pszAddress) {
                pblock->vtx[0].vout[0].nValue = nValue * 3 / 4;
                pblock->vtx[0].vout[1].nValue = nValue / 4; //offer 1/4 reward to light node
            }

            uint256 nonce;
            //HCE: Randomise nonce for new block foramt.
            nonce = GetRandHash();
            //HCE: Clear the top and bottom 16 bits (for local use as thread flags and counters)
            nonce <<= 32;
            nonce >>= 16;

            //HCE: Fill in header
            pblock->hashPrevBlock = pindexPrev->GetBlockHash();
            pblock->nHeight = pindexPrev->nHeight + 1;
            memset(pblock->nReserved, 0, sizeof(pblock->nReserved));

            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
            pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

            //HCE: make sure any two coinbases are different, the bug was found by spv wallet
            if (pblock->nTime == pindexPrev->nTime) {
                Sleep(1000);
                pblock->nTime += 1;
                //cout << "Increase time for Para new block\n";
            }

            pblock->nBits = GetNextWorkRequired(pindexPrev);
            pblock->nNonce = nonce.GetUint64(3);
            pblock->nSolution.clear();
        }
    }
    /*
    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    */

    return pblock;
}


bool CommitChainToConsensus(deque<CBlock>& deqblock, string& requestid, string& errmsg)
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();

    vector<string> vecMTRootHash;
    vector<CUInt128> vecNodeId;

    uint32_t hid = g_cryptoCurrency.GetHID();
    uint16 chainnum = g_cryptoCurrency.GetChainNum();
    uint16 localid = g_cryptoCurrency.GetLocalID();

    if (consensuseng) {
        vector<PostingBlock> postingchain;
        //HCE: To SER_BUDDYCONSENSUS, avoid commit the ownerNodeID member of CBlock
        CDataStream datastream(SER_BUDDYCONSENSUS);
        size_t num = deqblock.size();
        for (size_t i = 0; i < num; ++i) {

            PostingBlock blk;

            datastream.clear();
            datastream << deqblock[i];

            blk.payload = datastream.str();

            datastream.clear();
            datastream << deqblock[i].hashMerkleRoot;
            blk.hashMTRoot = datastream.str();

            for (auto& tx : deqblock[i].vtx) {
                datastream.clear();
                blk.vecMT.push_back(tx.GetHash().ToString());
            }

            blk.nodeid = deqblock[i].ownerNodeID;
            postingchain.push_back(std::move(blk));
        }

        auto number = consensuseng->AddChainEx(T_APPTYPE(APPTYPE::paracoin, hid, chainnum, localid), postingchain);
        DEBUG_FL("Add a paracoin chain to consensus layer: %u\n", number);
        return true;
    }
    else {
        errmsg = "Cannot commit chain to consensus, Consensus engine is stopped\n";
    }
    return false;
}


bool CommitGenesisToConsensus(CBlock* pblock, string& requestid, string& errmsg)
{
    //HCE: Just submit transaction data to buddy consensus layer.
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        CDataStream datastream(SER_BUDDYCONSENSUS);
        datastream << *pblock;

        string payload = datastream.str();

        datastream.clear();
        datastream << pblock->hashMerkleRoot;

        SubmitData data;
        data.app = T_APPTYPE(APPTYPE::paracoin, 0, 0, 0);
        data.MTRootHash = datastream.str();
        data.payload = payload;

        uint32 nOrder;
        if (consensuseng->AddNewBlockEx(data, requestid, nOrder, errmsg)) {
            DEBUG_FL("Add a paracoin block to consensus layer, requestid: %s\n", requestid.c_str());
            return true;
        }
        return false;
    }
    else {
        errmsg = "Cannot commit consensus, Consensus engine is stopped\n";
    }
    return false;
}

void IncrementExtraNonce(CBlock* pblock, unsigned int& nExtraNonce)
{
    //HCE: Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)     {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    pblock->vtx[0].vin[0].scriptSig = CScript() << pblock->nTime << CBigNum(nExtraNonce);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Prebuild hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            uint256 nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion = pblock->nVersion;
    tmp.block.hashPrevBlock = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime = pblock->nTime;
    tmp.block.nBits = pblock->nBits;
    tmp.block.nNonce = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    //HCE: Byte swap all the input buffer
    for (int i = 0; i < sizeof(tmp) / 4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    //HCE: Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget)
        return false;


    //// debug print
    TRACE_FL("\nproof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    TRACE_FL("%s ", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()).c_str());
    TRACE_FL("generated %s\n\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    //HCE: Found a solution
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        if (pblock->hashPrevBlock != hashBestChain)
            return WARNING_FL("generated block is stale");

        //HCE: Remove key from key pool
        reservekey.KeepKey();

        //HCE: Track how many getdata requests this block gets
        CRITICAL_BLOCK(wallet.cs_wallet)
            wallet.mapRequestCount[pblock->GetHash()] = 0;

        //HCE: Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return WARNING_FL("ProcessBlock, block not accepted");
    }

    Sleep(2000);
    return true;
}

extern std::function<void(int)> SleepFn;

void PutTxIntoTxPool(map<uint256, CTransaction>& mapTrans)
{
    CTxDB_Wrapper txdb;
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        mapTransactions.clear();
        auto iter = mapTrans.begin();
        for (; iter != mapTrans.end(); ) {

            iter->second.AddToMemoryPoolUnchecked();
            ++iter;
            continue;

            //uint256 hash = iter->first;
            //if (!txdb.ContainsTx(hash)) {
            //    iter->second.AddToMemoryPoolUnchecked();
            //    ++iter;
            //}
            //else {
            //    cout << strprintf("The Transaction has already chained: %s\n", iter->second.vout[0].ToString().c_str());
            //    iter = mapTrans.erase(iter);
            //}
        }
    }
}

//HCE: Handle built-in transactions
void static BuiltInMiner(CWallet* pwallet)
{
    CReserveKey reservekey(pwallet);

    map<uint256, CTransaction> mapTrans;

    //HCE: Read out old chain's transactions
    try {
        ReadTrans(mapTrans);
    }
    catch (runtime_error* e) {
        ERROR_FL("%s", e->what());
        return;
    }

    //A block contains 7850 transactions;
    PutTxIntoTxPool(mapTrans);
    mapTrans.clear();

    unsigned int nExtraNonce = 0;

    uint32_t nPrevHIDUsing = LatestHyperBlock::GetHID(nullptr);

    for (; !fShutdown;) {

        if (!mapTransactions.size()) {
            break;
        }

        int nTxCountInblock = 0;

        using SPBLOCK = std::shared_ptr<CBlock>;
        std::map<int, SPBLOCK> mapBlockBuiltIn;

        int i = 0;
        int nMaxParaBlkCount = 20; //number of a hyper block containing max para blocks

        cout << strprintf("Create a built-in block which contains %d Para blocks at mostly and PreHID is %d...\n",
            nMaxParaBlkCount, nPrevHIDUsing);

        CRITICAL_BLOCK(cs_mapTransactions)
        {
            for (; mapTransactions.size() > 0 && i < nMaxParaBlkCount;) {
                SPBLOCK blk(CreateBlockBuiltIn(reservekey, nTxCountInblock));
                cout << strprintf("%u transactions in the block created, left %u in transaction pool\n",
                    nTxCountInblock, mapTransactions.size());

                mapBlockBuiltIn.insert(std::make_pair(i++, blk));
            }
        }

        size_t nCount = mapBlockBuiltIn.size();
        cout << strprintf("Mining for %u built-in blocks...\n", nCount);
        cout << "Very Important: Please make sure new hyper block created haven't replaced by one from other nodes\n";

        while (!g_miningCond.EvaluateIsAllowed(false)) {
            SleepFn(2);
            if (fShutdown)
                return;
        }

        cout << strprintf("Wait for Latest Hyperblock %d is ready...\n", nPrevHIDUsing);
        while (nPrevHIDUsing != LatestHyperBlock::GetHID(nullptr)) {
            SleepFn(2);
        }

        g_isBuiltInBlocksReady = false;

        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            cout << strprintf("Chain best block: height:%u, hash:%s  PrevHid:%u PreHHash: %s\n",
                pindexBest->nHeight,
                pindexBest->GetBlockHash().ToPreViewString().c_str(),
                pindexBest->nPrevHID,
                pindexBest->hashPrevHyperBlock.ToPreViewString().c_str());
        }

        for (i = 0; i < nCount && !fShutdown; i++) {

            auto spBlk = mapBlockBuiltIn[i];
            UpdateBlockBuiltIn(spBlk.get());
            IncrementExtraNonce(spBlk.get(), nExtraNonce);

            if (nPrevHIDUsing != spBlk->nPrevHID) {
                //HCE: cancel this turn all para block
                cout << strprintf("Action failed, because PrevHID changed, spBlk->nPrevHID:%u nPrevHIDUsing: %u\n", spBlk->nPrevHID, nPrevHIDUsing);
                return;
            }

            cout << strprintf("Mining for new block: height:%u, PrevHid:%u PreHHash: %s\n",
                spBlk->nHeight,
                spBlk->nPrevHID,
                spBlk->hashPrevHyperBlock.ToPreViewString().c_str());

            progpow::search_result r;
            while (DoMining(*spBlk.get(), r)) {

                //HCE: Found a solution
                CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__);
                if (spBlk.get()->hashPrevBlock != hashBestChain || !spBlk.get()->IsLastestHyperBlockMatched()) {

                    if (spBlk.get()->hashPrevBlock != hashBestChain) {
                        cout << "\tgenerated block is stale,try again...\n";
                    }
                    else {
                        cout << "\tgenerated block's hyper block is stale,try again...\n";
                    }

                    CBlockIndexSP pIndex = LatestBlockIndexOnChained();
                    cout << strprintf("Switch best chain to height %u\n", pIndex->nHeight);
                    if (!SwitchChainTo(pIndex)) {
                        cout << strprintf("Failed to Switch best chain to height %u, program will exit\n", pIndex->nHeight);
                        exit(-1);
                    }

                    i = pIndex->nHeight - 1;
                    break;
                }

                //HCE: Process this block the same as if we had received it from another node
                //HCE: 270000 is Para current height of informal network, 2021/5/13, 207360 = (12 * 6) * 24 * 30 * 2 is generating number during two months
                //if (spBlk.get()->nHeight > 207360 + 270000)
                //{
                //    cerr << "Para: PocessBlock, block not accepted, you need to update software version ...\n";
                //    break;
                //}

                if (!ProcessBlock(NULL, spBlk.get())) {
                    cout << "\tProcessBlock, block not accepted,try again...\n";
                    i--;
                    break;
                }

                //list<string> cmdlist;
                //cmdlist.push_back("coin");
                //cmdlist.push_back("acc");

                //string info;
                //ConsoleCmd(cmdlist, info);
                //cout << "Query account: \n" << info << endl;

                //HCE: Remove key from key pool
                reservekey.KeepKey();

                break;
            }
        }
        mapBlockBuiltIn.clear();
        nPrevHIDUsing++;
        g_isBuiltInBlocksReady = true;
    }

    cout << "BuiltInMiner thread exited, submitting built-in blocks \n";
}

void static ThreadBitcoinMiner(void* parg);


void ChangeCoinbaseIfExist(CBlock *pblock, unsigned int nExtraNonce)
{
    CTxDB_Wrapper txdb;
    while (true) {
        IncrementExtraNonce(pblock, nExtraNonce);
        uint256 txhash = pblock->vtx[0].GetHash();
        CTxIndex idx;
        if (!txdb.ReadTxIndex(txhash, idx))
            break;
    }
}

void static BitcoinMiner(CWallet* pwallet)
{
    TRACE_FL("ParacoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);


    //HCE: Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (true)     {
        if (AffinityBugWorkaround(ThreadBitcoinMiner))
            return;
        if (fShutdown)
            return;

        //HCE: If too many blocks waiting to do global consensus, stop creating new block
        //HCE: while (vNodes.empty() || IsInitialBlockDownload() || WaitingBlockFn() >= 6) {
        string reason;
        while (!g_miningCond.EvaluateIsAllowed()) {
            if (g_miningCond.IsSwitching())
                Sleep(100);
            else
                SleepFn(5);

            if (fShutdown)
                return;
        }


        //HCE: Create new block
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;

        std::unique_ptr<CBlock> pblock(CreateNewBlock(reservekey));
        if (!pblock.get())
            return;

        //HCE: avoid coinbase conflict
        ChangeCoinbaseIfExist(pblock.get(), nExtraNonce);

        DEBUG_FL("Running ParacoinMiner with %d transactions in block\n", pblock->vtx.size());

        //
        //HCE: Search
        //

        CBigNum bnNew;
        bnNew.SetCompact(pblock->nBits);
        uint256 hashTarget = bnNew.getuint256();

        ethash::hash256 target;
        //HCE: ethash hash is always consider as big endian. uint256 is little endian.
        std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

        ethash::hash256 header_hash = pblock->GetHeaderHash();

        uint64_t start_nonce = pblock->nNonce;
        uint32_t epoch = ethash::get_epoch_number(pblock->nHeight);
        ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

        for (;;) {
            uint64_t nMaxTries = 1000000;

            int64 nStart = GetTime();
            auto r = progpow::search_light(epoch_ctx, pblock->nHeight, header_hash, target, start_nonce, nMaxTries,
                [&nStart, &nTransactionsUpdatedLast]() {
                //HCE: Return true means stop mining.
                if (fShutdown || !fGenerateBitcoins) {
                    return true;
                }

                if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 20) {
                    return true;
                }
                return false;
            });
            if (r.solution_found) {
                //HCE: found, set nonce & mix hash
                pblock->nNonce = r.nonce;

                pblock->nSolution.resize(sizeof(r.mix_hash.bytes));
                memcpy(pblock->nSolution.data(), r.mix_hash.bytes, sizeof(r.mix_hash.bytes));

                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                if (!pblock->IsLastestHyperBlockMatched()) {
                    CBlockIndexSP pIndex = LatestBlockIndexOnChained();
                    SwitchChainTo(pIndex);
                    WARNING_FL("generated block's hyper block is stale");
                    break;
                }

                CheckWork(pblock.get(), *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
                break;
            }
            else {
                //HCE: Check for stop or if block needs to be rebuilt
                if (fShutdown)
                    return;
                if (fLimitProcessors && vnThreadsRunning[3] > nLimitProcessors)
                    return;
                break;
            }
        }
    }
}

void static ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try     {
        vnThreadsRunning[3]++;
        if (mapArgs.count("-importtx"))
            //HCE: Mining for built-in transactions
            BuiltInMiner(pwallet);
        else
            BitcoinMiner(pwallet);
        vnThreadsRunning[3]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[3]--;
        PrintException(&e, "ThreadParacoinMiner()");
    }
    catch (...) {
        vnThreadsRunning[3]--;
        PrintException(NULL, "ThreadParacoinMiner()");
    }
    UIThreadCall(boost::bind(CalledSetStatusBar, "", 0));
    nHPSTimerStart = 0;
    if (vnThreadsRunning[3] == 0)
        dHashesPerSec = 0;
    DEBUG_FL("ThreadParacoinMiner exiting, %d threads remaining\n", vnThreadsRunning[3]);
}

//HCE: Use GenerateBitcoins to create trading block
void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    if (fGenerateBitcoins != fGenerate)     {
        fGenerateBitcoins = fGenerate;
        WriteSetting("fGenerateBitcoins", fGenerateBitcoins);
        MainFrameRepaint();
    }

    //HCE: anyway miner thread should start in order to prepare for a integrated Paracoin chain
    //if (fGenerateBitcoins)
    {
        int nProcessors = boost::thread::hardware_concurrency();
        TRACE_FL("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;

        //HCE: already started, only allow one miner thread
        if (vnThreadsRunning[3] >= 1)
            return;

        //int nAddThreads = nProcessors - vnThreadsRunning[3];

        //TRACE_FL("Starting %d ParacoinMiner threads\n", nAddThreads);
        TRACE_FL("Starting ParacoinMiner thread\n");
        //HCE: start a miner thread.
        //for (int i = 0; i < nAddThreads; i++)
        {
            if (!CreateThread(ThreadBitcoinMiner, pwallet))
                ERROR_FL("Error: CreateThread(ThreadParacoinMiner) failed\n");
            Sleep(10);
        }
    }
}

void FreeGlobalMemeory()
{
    mapBlockIndex.clear();

    mapTransactions.clear();

    mapOrphanBlocksByPrev.clear();
    mapOrphanBlocks.clear();

    mapOrphanTransactionsByPrev.clear();
    for (auto mi = mapOrphanTransactions.begin(); mi != mapOrphanTransactions.end(); ++mi) {
        delete mi->second;
    }
    mapOrphanTransactions.clear();

    mapBlocks.clear();
}

void ReInitSystemRunningEnv()
{
    fExit = false;
    fShutdown = false;

    hashBestChain = 0;
    hashGenesisBlock = 0;
    pindexGenesisBlock = nullptr;
    pindexBest = nullptr;

    FreeGlobalMemeory();

    dbenv.reset(new DbEnv(0));
}

SyncingChainProgress progress;
void LatestParaBlock::PullingNextBlocks(std::function<void(const SyncingChainProgress&)> notiprogress)
{
    std::vector<CNode*> vNodesCopy;
    NodesCopy nc(vNodesCopy);

    CBlockLocatorEx* pBestlocInSeeds = nullptr;
    if (!g_seedserver.bestChain(&pBestlocInSeeds)) {
        //HC: 在邻居里寻找链最优的
        if(!VisibleFriends::bestChain(&pBestlocInSeeds, vNodesCopy))
            return;
    }

    uint256 hashMyFork;
    CBlockLocatorEx::ForkIndex myforkIdx = paramqcenter.MTC_FindForkIndex(*pBestlocInSeeds, hashMyFork);

    LogRequest("PullingNextBlocks: fork index: (%d %d) with best chain of seeds ****************\n", myforkIdx.nIdxInVHave, myforkIdx.nIdxInVHaveTail);

    int nRequestingNodes = 0;

    g_seedserver.RefreshOnlineState();


    //HC: 可拉取块数据节点
    //HCE: Vector of nodes whose block data can be pulled
    vector<CNode*> vPullingDataNodes;

    //HC: 可拉取块清单信息节点
    //HCE: List of nodes whose block inventory can be pulled
    list<CNode*> listPullingInvNodes;
    bool InvNodeisValid = false;
    for (auto& node : vNodesCopy) {
        if (g_seedserver.isBestServer(node->addr)) {
            listPullingInvNodes.push_back(node);
            vPullingDataNodes.insert(std::upper_bound(vPullingDataNodes.begin(), vPullingDataNodes.end(), node, [](const CNode* a, const CNode* b) {
                return a->GetRating() < b->GetRating();
            }), node);

            continue;
        }

        int nMatchIdx = 0;
        int nContainIdx = g_seedserver.containChain(node->chkpoint);
        if (nContainIdx > 0) {
            //HC: 种子节点包含node节点的链
            //HCE: A seed node which contains a chain of 'node'
            nMatchIdx = nContainIdx;
        } else {
            //HC: 分叉
            //HCE: fork
            uint256 hashFork;
            nMatchIdx = pBestlocInSeeds->FindForkIndex(node->chkpoint.chainloc, hashFork).nIdxInVHave;
        }

        if (myforkIdx.nIdxInVHave <= nMatchIdx && node->fgetInvContinue.height < node->chkpoint.nBstH) {
            //HC: 可作为拉取清单节点
            //HCE: treat as a inventory node
            listPullingInvNodes.push_back(node);
        }

        if (myforkIdx.nIdxInVHave <= nMatchIdx && node->fgetInvContinue.height < node->chkpoint.nBstH) {
            //HC: 本地最优链与node节点的分叉点高度小，可去同步数据
            //HCE: The fork point between the local optimal chain and the 'node' is small, and the data can be synchronized
            vPullingDataNodes.insert(std::upper_bound(vPullingDataNodes.begin(), vPullingDataNodes.end(), node, [](const CNode* a, const CNode* b) {
                return a->GetRating() < b->GetRating();
            }), node);
        }
    }

    listPullingInvNodes.sort([](const CNode* a, const CNode* b) {
        //return a->nAvgPingCost < b->nAvgPingCost;
        return a->GetRating() < b->GetRating();
    });

    if (vPullingDataNodes.size() > 10) {
        vPullingDataNodes.erase(vPullingDataNodes.begin() + 9, vPullingDataNodes.end());
    }

    if (listPullingInvNodes.empty()) {
        progress.pPullingInvNode = nullptr;
        progress.vecPullingDataNode.clear();
        notiprogress(progress);
        return;
    }


    //HC: 清单拉取节点会话是否存在
    bool invNodeisValid = false;
    if (progress.pPullingInvNode != nullptr) {
        for (auto& node : vNodesCopy) {
            if (node == progress.pPullingInvNode) {
                invNodeisValid = true;
                break;
            }
        }
    }

    if (invNodeisValid) {
        if (progress.pPullingInvNode->IsNotHavingInvReply()) {
            //HC: 上一个节点长时间无应答，更换清单拉取节点
            //HCE: If the previous node does not respond for a long time, change the list pull node
            auto iterpulling = ++(listPullingInvNodes.begin());
            for (; iterpulling != listPullingInvNodes.end(); ++iterpulling) {
                if ((*iterpulling) != progress.pPullingInvNode && !(*iterpulling)->IsNotHavingInvReply()) {
                    LogRequest("PullingNextBlocks: change inventory node from %s to %s ****************\n",
                        progress.pPullingInvNode->addr.ToString().c_str(),
                        (*iterpulling)->addr.ToString().c_str());
                    progress.pPullingInvNode = *iterpulling;
                    break;
                }
            }
        }
    }
    else {
        progress.pPullingInvNode = *listPullingInvNodes.begin();
    }

    //LogRequest("Choose highest net speed node: %s to pull block, ping: %d(ms)", pulling->nodeid.c_str(), pulling->nAvgPingCost);

    CNode* pRequestInvNode = progress.pPullingInvNode;

    progress.vecPullingDataNode.clear();
    for (auto& n : vPullingDataNodes) {
        progress.vecPullingDataNode.push_back(strprintf("%s: %d(times)", n->addr.ToString().c_str(), n->nfAskFor));
    }

    //HC: 获取上次块清单拉取请求完成情况，返回未拉取到的块hash
    //HCE: Gets the completion status of the last block list pull request and returns the block hash that was not pulled
    vector<CInv> vecHaveNot;
    int nGotNum = 0;
    auto stt = pRequestInvNode->OnGetFBlocksCompleted(nGotNum, vecHaveNot);
    progress.nGotNum = nGotNum;

    if(stt == CNode::GetFBlocksState::PullingInventory || stt == CNode::GetFBlocksState::Completed) {
        //HCE: trigger to pull next batch blocks or retry to pull last time.
        progress.startPullingTm = pRequestInvNode->FPullBlocks(hashMyFork);
        progress.pullingInvStart = pRequestInvNode->fgetInvContinue;
        progress.pullingInvEnd.SetNull();
        progress.nPullingRetry = pRequestInvNode->nfgetRetry;
    } else {
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(vPullingDataNodes.begin(), vPullingDataNodes.end(), g);

        LogRequest("PullingNextBlocks: will pulling blocks: %d ****************\n", vecHaveNot.size());

        //HC: 扫描未在拉取的缺少的块
        //HCE: Scan for missing blocks that are not being pulled
        vector<int> unRequestPulling;
        int n = vecHaveNot.size();
        for (int i = 0; i < n && !fShutdown; i++) {
            if (CNode::AlreadyAskFor(vecHaveNot[i])) {
                //近期几分钟内已经请求过了
                continue;
            }

            bool askingfor = false;
            for (auto& node : vPullingDataNodes) {
                if (node->AskingFor(vecHaveNot[i])) {
                    askingfor = true;
                    break;
                }
            }

            if (askingfor) {
                continue;
            }
            unRequestPulling.push_back(i);
        }

        //HC: 分别向不同节点拉取缺少的块
        //HCE: Pull missing blocks to different nodes separately
        n = unRequestPulling.size();
        if (vPullingDataNodes.size() > 0) {
            for (int i = 0; i < n && !fShutdown;) {
                for (auto& node : vPullingDataNodes) {
                    auto& inv = vecHaveNot[unRequestPulling[i]];
                    if(node->AskForF(inv))
                        LogRequest("Ask node: %s for block: %d (%d %s)\n", node->nodeid.c_str(),
                            unRequestPulling[i],
                            inv.height, inv.hash.ToString().c_str());
                    i++;
                    if (i >= n || i > 60) {
                        break;
                    }
                }
            }
        }

        if (pRequestInvNode->vfgetblocksInv.size() > 0) {
            progress.pullingInvStart = pRequestInvNode->vfgetblocksInv.front();
            progress.pullingInvEnd = pRequestInvNode->vfgetblocksInv.back();
        }
        else {
            progress.pullingInvStart.SetNull();
            progress.pullingInvEnd.SetNull();
        }
        progress.startPullingTm = pRequestInvNode->tmlastfget;
        progress.nPullingRetry = pRequestInvNode->nfgetRetry;
    }
    notiprogress(progress);
}

//////////////////////////////////////////////////////////////////////////
bool MiningCondition::IsTooFar()
{
    uint32_t ncount = 0;
    const int nMaxUnChained = 45;

    //CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        uint256 PrevHHash;
        int nPrevHID = LatestHyperBlock::GetHID(&PrevHHash);

        CBlockIndexSP p = pindexBest;
        while (p && !p->triaddr.isValid() && p->nPrevHID == nPrevHID) {
            ncount++;
#ifndef MinDiff
            if (ncount > nMaxUnChained) {
                _eStatusCode = miningstatuscode::ManyBlocksNonChained;
                return true;
            }
#endif
            p = p->pprev();
        }
        return false;
    }
    //HCE: The following code doesn't execute for ever
    return true;
}

bool MiningCondition::EvaluateIsAllowed(bool NeighborIsMust)
{
    if (_eStatusCode == miningstatuscode::VersionLow)
        return false;

    if (NeighborIsMust && vNodes.empty()) {
        _eStatusCode = miningstatuscode::NoAnyNeighbor;
        return false;
    }

    if (!fGenerateBitcoins) {
        _eStatusCode = miningstatuscode::GenDisabled;
        return false;
    }

    bool isLoadTxAndKey = !GetBoolArg("-noloadwallet"); //HCE: no loading wallet cannot do mining
    if (!isLoadTxAndKey) {
        _eStatusCode = miningstatuscode::UnloadWallet;
        return false;
    }

    if (IsTooFar()) {
        return false;
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    //CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        if (!hyperchainspace->IsLatestHyperBlockReady()) {
            _eStatusCode = miningstatuscode::HyperBlockNotReady;
            return false;
        }
        //else if (IsInitialBlockDownload()) {
        //    _reason += "Initial Block is downloading";
        //    return false;
        //}
        else if (!g_cryptoCurrency.CheckGenesisBlock()) {
            _eStatusCode = miningstatuscode::InvalidGenesisBlock;
            return false;
        }

        //HCE: if Latest hyper block has changed, process them.
        if (hyperblockMsgs.size() > 0)
        {
            CRITICAL_BLOCK_T_MAIN(cs_main)
                hyperblockMsgs.process();
        }

        auto f = std::bind(&MiningCondition::SyncingProgressChanged, this, std::placeholders::_1);

        bool chainIsAlignment = g_seedserver.checkChainData(_eSSStatusCode);
        if (!chainIsAlignment && _eSSStatusCode != MiningCondition::seedserverstatuscode::seed_server_null) {

            //HC: 与种子服务器同步数据，同时挖矿停止
            LatestParaBlock::PullingNextBlocks(f);
            _eStatusCode = miningstatuscode::SyncingChain;
            return false;
        }

        //
        //HC: 与种子服务器数据一致情况下，查看邻居是否比我更优，如果是，那么尝试拉取数据，同时本地挖矿继续
        //
        bool isNeedPullingData = !VisibleFriends::checkChainData();
        if (isNeedPullingData) {
            //HCE: 与邻居同步数据，同时挖矿继续
            LatestParaBlock::PullingNextBlocks(f);
            _eStatusCode = miningstatuscode::MiningAndSyncingChain;
        } else {
            _eStatusCode = miningstatuscode::Mining;
        }
    }

    return true;
}


//////////////////////////////////////////////////////////////////////////
void SeedServers::addServer(const string& ipaddr, int nPort)
{
    CAddress addr(ipaddr.c_str(), nPort);
    CRITICAL_BLOCK(_cs_seedserver)
    {
        if (_mapserver.count(addr))
            return;
        _mapserver.insert(make_pair(addr, SSState()));
    }
}

//update seed server check point
void SeedServers::updateSSCheckPoint(const CAddress& netaddr, const ChkPoint& cp)
{
    CRITICAL_BLOCK(_cs_seedserver)
        for (auto& elm : _mapserver) {
            if (elm.first == netaddr) {
                elm.second.chkp = cp;
                elm.second.online = true;
                return;
            }
        }
}

bool SeedServers::isSeedServer(const CAddress& netaddr)
{
    CRITICAL_BLOCK(_cs_seedserver)
    {
        for (auto& elm : _mapserver) {
            if (elm.first == netaddr) {
                return true;
            }
        }
    }
    return false;
}

size_t SeedServers::size()
{
    CRITICAL_BLOCK(_cs_seedserver)
        return _mapserver.size();
    return 0;
}



bool VisibleFriends::ChkPontLeftIsBest(const ChkPoint &left, const ChkPoint &right)
{
    if (left.nChkPointHeight < right.nChkPointHeight)
        return false;

    if (left.nChkPointHeight > right.nChkPointHeight) {
        return true;
    } else if (left.nBstH > right.nBstH) {
        return true;
    }
    return false;
}

bool VisibleFriends::bestChain(CBlockLocatorEx** bestloc, vector<CNode*>& vNodesCopy)
{
    auto best = vNodesCopy.end();
    auto it = vNodesCopy.begin();
    for (; it != vNodesCopy.end(); ++it) {
        if ((*it)->fDisconnect) {
            continue;
        }

        if (best == vNodesCopy.end()) {
            best = it;
            continue;
        }

        if(ChkPontLeftIsBest((*best)->chkpoint, (*it)->chkpoint))
            continue;
        best = it;
    }

    if (best == vNodesCopy.end()) {
        return false;
    }

    *bestloc = &((*best)->chkpoint.chainloc);
    return true;
}

bool VisibleFriends::checkChainData()
{
    //HC: 种子服务器无法访问
    std::vector<CNode*> vNodesCopy;
    NodesCopy nc(vNodesCopy);

    CBlockLocatorEx* pBestlocInSeeds = nullptr;
    //HC: 在邻居里寻找链最优的
    if (!bestChain(&pBestlocInSeeds, vNodesCopy))
        return false;

    ChkPoint ck;
    ck.nChkPointHeight = pBestlocInSeeds->GetChkPoint(ck.chkPointHash);

    //HC：比较链数据
    if (!paramqcenter.MTC_CompareChainWithLocal(ck)) {
        return false;
    }
    return true;
}

//HC: 必须在paramqcenter所在的MQ线程里执行
int VisibleFriends::containChain(const ChkPoint& leftcp, const ChkPoint& rightcp)
{
    int ret = leftcp.chainloc.contain(rightcp.chainloc);
    if (ret == 0) {
        ret = rightcp.chainloc.contain(leftcp.chainloc);
        //HC: 反包含
        //HCE: Anti-containment
        return -ret;
    }
    return 0;
}

//////////////////////////////////////////////////////////////////////////

map<CAddress, SSState>::iterator SeedServers::bestServer()
{
    CRITICAL_BLOCK(_cs_seedserver)
    {
        auto best = _mapserver.end();
        auto it = _mapserver.begin();
        for (; it != _mapserver.end(); ++it) {
            if (!it->second.online) {
                continue;
            }
            if (best == _mapserver.end()) {
                best = it;
                continue;
            }

            if (VisibleFriends::ChkPontLeftIsBest(it->second.chkp, best->second.chkp))
                continue;
            best = it;
        }
        return best;
    }
    return _mapserver.end();
}



bool SeedServers::checkChainData(MiningCondition::seedserverstatuscode& StatusCode)
{
    CRITICAL_BLOCK(_cs_seedserver)
    {
        //if (_mapserver.size() == 0) {
        //    StatusCode = MiningCondition::seedserverstatuscode::non_seed_server;
        //    //HCE: Non seed server is face to risk to error chain.
        //    return true;
        //}

        auto best = bestServer();
        if (best == _mapserver.end()) {
            //HC: 无可用种子服务器
            StatusCode = MiningCondition::seedserverstatuscode::seed_server_null;
            return false;
        }

        ChkPoint& cp = best->second.chkp;
        if (paramqcenter.MTC_CompareChainWithLocal(cp)) {
            StatusCode = MiningCondition::seedserverstatuscode::chain_data_same;
            return true;
        }
    }

    //HCE: Warning: chain different from Seed server's
    StatusCode = MiningCondition::seedserverstatuscode::local_chain_fork;
    return false;
}

bool ChkPoint::GetCurrent(ChkPoint &cp)
{
    CRITICAL_BLOCK(cs_cpRefresh)
        if (cp.nBstH != nBestHeight || cp.bestHash != hashBestChain) {
            cp.nBstH = nBestHeight;
            cp.bestHash = hashBestChain;
            cp.nChkPointHeight = paramqcenter.MTC_GetChkPoint(cp.chkPointHash);
        }

    return true;
}



//HC: 返回值为匹配度, 0：不匹配，>0：2条链为正包含关系, <0: 为反包含关系
//HCE: The return value is matching, 0: mismatch, >0:2 chains are positive containment relations, and <0: are anti-inclusion relationships
int SeedServers::containChain(const ChkPoint& cp)
{
    auto best = bestServer();
    if (best != _mapserver.end()) {
        ChkPoint& bestcp = best->second.chkp;
        int ret = bestcp.chainloc.contain(cp.chainloc);
        if (ret == 0) {
            ret = cp.chainloc.contain(bestcp.chainloc);
            //HC: 反包含
            //HCE: Anti-containment
            return -ret;
        }
        return ret;
    }
    return 0;
}

void CNode::MakeChainLonger(const CInv &inv)
{
    if (mapOrphanBlocks.count(inv.hash)) {
        uint256 rootblk = GetOrphanRoot(mapOrphanBlocks[inv.hash].get());
        CBlockSP spblk = mapOrphanBlocks.at(rootblk);
        if (mapBlockIndex.count(spblk->hashPrevBlock)) {
            auto pindex = mapBlockIndex[spblk->hashPrevBlock];
            LogRequest("OnGetFBlocksCompleted: Previous of OrphanRoot: %d(%s) in main chain ******###**********\n",
                pindex->nHeight, pindex->hashBlock.ToPreViewString().c_str());
            if (!pindex->IsInMainChain() || pindex->bnChainWork > pindexBest->bnChainWork) {
                SwitchChainTo(pindex);
            }
            else {
                ProcessOrphanBlocks(spblk->hashPrevBlock);
            }
        }
        //else {
        //    LogRequest("OnGetFBlocksCompleted: Root: %s, PushGetBlocks: %s ****************\n",
        //        rootblk.ToString().c_str(),
        //        spblk->hashPrevBlock.ToString().c_str());
        //    PushGetBlocks(pindexBest, spblk->hashPrevBlock);
        //}
    }
}


CNode::GetFBlocksState CNode::OnGetFBlocksCompleted(int &nHaving, vector<CInv> &vecHaveNot)
{
    CTxDB_Wrapper txdb;
    int nSize = vfgetblocksInv.size();

    nHaving = 0;

    if (nSize == 0) {
        return GetFBlocksState::PullingInventory;
    }

    for(const CInv & inv: vfgetblocksInv) {
        bool fAlreadyHave = AlreadyHave(txdb, inv);
        if (fAlreadyHave) {
            nHaving++;
        }

        if (!fAlreadyHave) {
            vecHaveNot.push_back(inv);
        }
    }


    fgetInvContinue = vfgetblocksInv.back();
    if (nHaving != nSize) {
        CRITICAL_BLOCK_T_MAIN(cs_main) {
            MakeChainLonger(vfgetblocksInv.front());
        }
    } else if (nHaving == nSize) {
        CRITICAL_BLOCK_T_MAIN(cs_main) {
            //HCE: try to switch
            for (auto& inv : vfgetblocksInv) {
                if (fShutdown) {
                    return GetFBlocksState::PullingBlocks;
                }

                if (!mapBlockIndex.count(inv.hash) && !mapOrphanBlocks.count(inv.hash)) {
                    CBlock block;
                    BLOCKTRIPLEADDRESS addrblock;
                    char* pWhere = nullptr;
                    if (GetBlockData(inv.hash, block, addrblock, &pWhere)) {
                        ProcessBlockWithTriaddr(this, &block, &addrblock);
                    } else {
                        vecHaveNot.push_back(inv);
                        nHaving--;
                        continue;
                    }
                }
            }

            if (vecHaveNot.size() > 0) {
                return GetFBlocksState::PullingBlocks;
            }
            MakeChainLonger(vfgetblocksInv.back());
        }

        ClearGot(vfgetblocksInv);
        vfgetblocksInv.clear();
        setfgetblocksInv.clear();
        tmlastfget = 0;
        nfgetRetry = 0;
        return GetFBlocksState::Completed;
    }

    return GetFBlocksState::PullingBlocks;
}

int64 CNode::FPullBlocks(const uint256& hashfork)
{
    uint256 hashchkp;
    auto chkheight = paramqcenter.MTC_GetChkPoint(hashchkp);

    if (lasthashfork == hashfork && lastInvContinue == fgetInvContinue.hash) {
        if (tmlastfget + 60 > GetTime())
            return tmlastfget;
    }

    lasthashfork = hashfork;
    lastInvContinue = fgetInvContinue.hash;
    lasthash = hashchkp;

    LogRequest("FPullBlocks: fgetblocks %s (%d:%s) (%d:%s) towards: %s ****************\n",
        hashfork.ToString().c_str(),
        fgetInvContinue.height,
        fgetInvContinue.hash.ToPreViewString().c_str(),
        chkheight, 
        hashchkp.ToPreViewString().c_str(),
        nodeid.c_str());

    PushMessage("fgetblocks", lasthashfork, lastInvContinue, lasthash);

    if (hashlastfget == lastInvContinue) {
        nfgetRetry++;
    } else {
        hashlastfget = lastInvContinue;
        nfgetRetry = 0;
    }

    tmlastfget = GetTime();
    return tmlastfget;
}

void CNode::FPullBlockReached(const CInv& inv)
{
    if (!setfgetblocksInv.count(inv.hash)) {
        vfgetblocksInv.push_back(inv);
        setfgetblocksInv.insert(inv.hash);
    }
    tmlastrecvfgetblock = GetTime();
}


void ParaMQCenter::startMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&ParaMQCenter::DispatchService, this, std::placeholders::_1, std::placeholders::_2);

    _msghandler.registerWorker(PARA_SERVICE, fwrk);

    _msghandler.registerTimer(100 * 1000 * 60, std::bind(&CBlockLocatorEx::Save, &_maintrunkchain));


    _msghandler.start("ParaMQCenter");
    cout << "ParaMQCenter MQID: " << MQID() << endl;
}

void ParaMQCenter::DispatchService(void* wrk, zmsg* msg)
{
    HCMQWrk* realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();
    string u = msg->pop_front();

    int service_t = 0;
    memcpy(&service_t, u.c_str(), sizeof(service_t));

    switch ((SERVICE)service_t) {
    case SERVICE::MTC_Save: {
        MTC_Save();
        break;
    }
    case SERVICE::MTC_Set: {
        uint256 *hashchk = nullptr;
        MQMsgPop(msg, hashchk);
        MTC_Set(*hashchk);
        break;
    }
    case SERVICE::MTC_Have: {
        CBlockIndexSP* pindex = nullptr;
        MQMsgPop(msg, pindex);
        bool r = MTC_Have(*pindex);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_GetRange: {
        int nBlkHeight;
        uint256 *hashbegin = nullptr;
        uint256 *hashEnd = nullptr;
        MQMsgPop(msg, nBlkHeight, hashbegin, hashEnd);

        bool r = MTC_GetRange(nBlkHeight, *hashbegin, *hashEnd);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_FindForkIndex: {
        CBlockLocatorEx* blkloc = nullptr;
        uint256 *hashfork = nullptr;
        CBlockLocatorEx::ForkIndex *fi = nullptr;
        MQMsgPop(msg, blkloc, hashfork, fi);
        *fi = MTC_FindForkIndex(*blkloc, *hashfork);
        break;
    }
    case SERVICE::MTC_ComputeDiff: {
        uint256* hash_end_vhave = nullptr;
        uint256* hash_end_vhavetail = nullptr;
        CBlockLocatorExIncr* incr = nullptr;
        MQMsgPop(msg, hash_end_vhave, hash_end_vhavetail, incr);

        MTC_ComputeDiff(*hash_end_vhave, *hash_end_vhavetail, *incr);
        break;
    }
    case SERVICE::MTC_IsInMain: {
        int nheight;
        uint256* hash= nullptr;
        MQMsgPop(msg, nheight, hash);

        bool r = MTC_IsInMain(nheight, *hash);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_GetChain: {
        vector<uint256>* chains = nullptr;
        MQMsgPop(msg, chains);

        int r = MTC_GetChain(*chains);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_CompareChainWithLocal: {
        ChkPoint * cp = nullptr;
        MQMsgPop(msg, cp);

        bool r = MTC_CompareChainWithLocal(*cp);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_GetChkPoint: {
        uint256* hashchkp = nullptr;
        MQMsgPop(msg, hashchkp);

        int r = MTC_GetChkPoint(*hashchkp);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_ToString: {
        int idx;
        MQMsgPop(msg, idx);

        string r = MTC_ToString(idx);
        MQMsgPush(msg, r);
        break;
    }
    case SERVICE::MTC_ToDetailString: {
        int idx;
        int idxTail;
        MQMsgPop(msg, idx, idxTail);

        string r = MTC_ToDetailString(idx, idxTail);
        MQMsgPush(msg, r);
        break;
    }
    default:
        //HCE: throw it
        return;
    }
    realwrk->reply(reply_who, msg);
}



void ParaMQCenter::MTC_Set(uint256 &hashchk)
{
    if (!_isStarted) {
        //HCE: single thread
        _maintrunkchain.Set();
        return;
    }

    if (_msghandler.getID() == std::this_thread::get_id()) {
        _maintrunkchain.Set();
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_Set, &hashchk);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void ParaMQCenter::MTC_Save()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        _maintrunkchain.Save();
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_Save);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool ParaMQCenter::MTC_Have(const CBlockIndexSP& pindex)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.Have(pindex);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_Have, &pindex);

        bool ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

CBlockLocatorEx::ForkIndex ParaMQCenter::MTC_FindForkIndex(const CBlockLocatorEx& blkloc, uint256& hashfork)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.FindForkIndex(blkloc, hashfork);
    }
    else {
        CBlockLocatorEx::ForkIndex fi;
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_FindForkIndex, &blkloc, &hashfork, &fi);

        if (rspmsg) {
            delete rspmsg;
        }
        return fi;
    }
}

bool ParaMQCenter::MTC_GetRange(int nBlkHeight, uint256& hashbegin, uint256& hashEnd)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.GetRange(nBlkHeight, hashbegin, hashEnd);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_GetRange, nBlkHeight, &hashbegin, &hashEnd);
        bool ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

void ParaMQCenter::MTC_ComputeDiff(const uint256& hash_end_vhave, const uint256& hash_end_vhavetail, CBlockLocatorExIncr& incr)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        incr = _maintrunkchain.computeDiff(hash_end_vhave, hash_end_vhavetail);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_ComputeDiff, &hash_end_vhave, &hash_end_vhavetail, &incr);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

int ParaMQCenter::MTC_GetChain(vector<uint256>& chains)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.GetChain(chains);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_GetChain, &chains);

        int ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

int ParaMQCenter::MTC_GetChkPoint(uint256& hashchkp)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.GetChkPoint(hashchkp);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_GetChkPoint, &hashchkp);

        int ret = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}


bool ParaMQCenter::MTC_CompareChainWithLocal(const ChkPoint& cp)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {

        //HC: 如果远端节点链的关键检查块在我的主链上，那么可以认为该节点链数据与我的链数据有如下二种关系：
        //1. 基本是一致的
        //2. 我的链包含了对方的链
        if (_maintrunkchain.IsInMain(cp.nChkPointHeight, cp.chkPointHash)) {
            return true;
        }

        uint256 hash;
        int nHeight = _maintrunkchain.GetChkPoint(hash);
        if (nHeight > cp.nChkPointHeight) {
            return true;
        }
        return false;

        /*
        uint256 hash;
        int nHeight = _maintrunkchain.GetChkPoint(hash);
        if (nHeight == cp.nChkPointHeight && cp.chkPointHash == hash) {
            //HCE: My Para chain data is basically same with the remote node
            return true;
        }

        if (cp.nChkPointHeight >= 0 && cp.chkPointHash > 0) {

            //HCE: compare block height and block hash with the remote node
            if (nHeight > cp.nChkPointHeight && nHeight - 200 <= cp.nChkPointHeight) {
                if (_maintrunkchain.IsInMain(cp.nChkPointHeight, cp.chkPointHash)) {
                    //HCE: My chain contains chain of the remote node
                    return true;
                }
            }
            else if (nHeight < cp.nChkPointHeight) {
                if (_maintrunkchain.IsInMain(cp.nChkPointHeight, cp.chkPointHash)) {
                    return true;
                }
            }
        }

        //paramqcenter.MTC_CompareChainWithLocal(const ChkPoint & cp);
        //containChain(, cp)
        //return _maintrunkchain.IsInMain(nheight, hash);
        */
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_CompareChainWithLocal, &cp);
        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

bool ParaMQCenter::MTC_IsInMain(int nheight, const uint256& hash)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.IsInMain(nheight, hash);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_IsInMain, nheight, &hash);
        bool ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}


std::string ParaMQCenter::MTC_ToString(int idx)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.ToString(idx);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_ToString, idx);
        string ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}


std::string ParaMQCenter::MTC_ToDetailString(int idx, int idxTail)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return _maintrunkchain.ToDetailString(idx, idxTail);
    }
    else {
        zmsg* rspmsg = MQRequest(PARA_SERVICE, (int)SERVICE::MTC_ToDetailString, idx, idxTail);
        string ret;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }
        return ret;
    }
}

#ifdef WIN32

BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#endif
