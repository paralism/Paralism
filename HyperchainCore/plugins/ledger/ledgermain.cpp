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

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "ledgermain.h"
#include "cryptotoken.h"
#include "latestledgerblock.h"

#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CBlockCacheLocator mapBlocks;

static map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;

//HC: 用于代替交易功能
//HCE: Used in place of trading functions
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;

//HCE: The following is target.
uint256 hashGenesisBlock;

//static CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 12);
const int nTotalBlocksEstimate = 0; // Conservative estimate of total nr of blocks on main chain
const int nInitialBlockThreshold = 30; // Regard blocks up until N-threshold as "initial download"
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashBestChain = 0;

//HC: 含账本的最大地址(T_LOCALBLOCKADDRESS)
//HCE: Maximum address with ledger (T_LOCALBLOCKADDRESS)

//HC: 当最优块索引所指向地址小于addrMaxChain时，往前扫描
//HCE: When the address pointed to by the optimal block index is less than addrMaxChain, scan forward

T_LOCALBLOCKADDRESS addrMaxChain;

CBlockIndex* pindexBest;
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

void RSyncGetBlock(const uint256& hashPrevBlock);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern std::function<void(int)> SleepFn;
extern ChainReadyCondition g_chainReadyCond;
extern HyperBlockMsgs hyperblockMsgs;

//HCE: convert uint256 to T_SHA256
T_SHA256 to_T_SHA256(const uint256& uhash)
{
    unsigned char tmp[DEF_SHA256_LEN];
    memcpy(tmp, uhash.begin(), DEF_SHA256_LEN);
    std::reverse(std::begin(tmp), std::end(tmp));

    return T_SHA256(tmp);
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
//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

CBlockIndex* LatestBlockIndexOnChained()
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    CBlockIndex* pIndex = pindexBest;
    while (pIndex) {
        if (pIndex->triaddr.isValid()) {
            if (hyperchainspace->CheckHyperBlockHash(pIndex->triaddr.hid, to_T_SHA256(pIndex->triaddr.hhash))) {
                return pIndex;
            }
            else {
                INFO_FL("CheckHyperBlockHash cannot pass: %d(%s) (Triaddr: %s)", pIndex->nHeight, pIndex->GetBlockHash().ToPreViewString().c_str(),
                    pIndex->triaddr.ToString().c_str());
            }
        }
        pIndex = pIndex->pprev;
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
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx, wtx))
            return true;
    return false;
}

void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

void static SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}

void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

void static ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet * pwallet, setpwalletRegistered)
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
    BOOST_FOREACH(const CTxIn & txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn & txin, tx.vin)
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

CBlockLocator::CBlockLocator(uint256 hashBlock)
{
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end())
        Set((*mi).second);
}

int CBlockLocator::GetDistanceBack()
{
    // Retrace how far back it was in the sender's branch
    int nDistance = 0;
    int nStep = 1;
    BOOST_FOREACH(const uint256 & hash, vHave)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain())
                return nDistance;
        }
        nDistance += nStep;
        if (nDistance > 10)
            nStep *= 2;
    }
    return nDistance;
}

CBlockIndex* CBlockLocator::GetBlockIndex()
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256 & hash, vHave)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain())
                return pindex;
        }
    }
    return pindexGenesisBlock;
}

uint256 CBlockLocator::GetBlockHash()
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256 & hash, vHave)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain())
                return hash;
        }
    }
    return hashGenesisBlock;
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB_Wrapper().ReadTxIndex(GetHash(), txindex))
                return 0;

            BLOCKTRIPLEADDRESS addrblock;
            char* pWhere = nullptr;
            if (!GetBlockData(txindex.pos.hashBlk, blockTmp, addrblock, &pWhere))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            WARNING_FL("couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->Height() - pindex->Height() + 1;
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
    BOOST_FOREACH(const CTxOut & txout, vout)
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
    BOOST_FOREACH(const CTxIn & txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    //HCE:
    //if (!IsCoinBase())
    //{
    //    BOOST_FOREACH(const CTxIn& txin, vin)
    //        if (txin.prevout.IsNull())
    //            return ERROR_FL("prevout is null");
    //}

    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction())
        return ERROR_FL("CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return ERROR_FL("coinbase as individual tx");

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)nLockTime > INT_MAX)
        return ERROR_FL("not accepting nLockTime beyond 2038 yet");

    // Safety limits
    unsigned int nSize = ::GetSerializeSize(*this, SER_NETWORK);
    // Checking ECDSA signatures is a CPU bottleneck, so to avoid denial-of-service
    // attacks disallow transactions with more than one SigOp per 34 bytes.
    // 34 bytes because a TxOut is:
    //   20-byte address + 8 byte bitcoin amount + 5 bytes of ops + 1 byte script length
    if (GetSigOpCount() > nSize / 34 || nSize < 100)
        return ERROR_FL("nonstandard transaction");

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !IsStandard())
        return ERROR_FL("nonstandard transaction type");

    // Do we already have it?
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash))
            return false;
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

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
        int64 nFees = 0;
        if (!ConnectInputs(txdb, mapUnused, CDiskTxPos(1), pindexBest, nFees, false, false))
        {
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return ERROR_FL("ConnectInputs failed %s", hash.ToString().substr(0, 10).c_str());
        }

        // Don't accept it if it can't get into a block
        if (nFees < GetMinFee(1000, true, true))
            return ERROR_FL("not enough fees");

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
                if (dFreeCount > GetArg("-limitfreerelay", 15) * 10 * 1000 && !IsFromMe(*this))
                    return ERROR_FL("free transaction rejected by rate limiter");
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
        BOOST_FOREACH(const CTxIn & txin, vin)
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
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
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
    if (pindex->triaddr.hid == g_cryptoToken.GetHID()) {
        //HCE: initialization supply
        return COINBASE_MATURITY + 1;
    }
    return pindexBest->Height() - pindex->Height() + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    //HCE:for test
    //return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
    //HCE: notice (COINBASE_MATURITY + 1), must be consistent with GetDepthInMainChain,
    //HCE: make sure the condition (pindex->addr.hid == g_cryptoToken.GetHID()) is true
    return max(0, (COINBASE_MATURITY + 1) - GetDepthInMainChain());
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
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx & tx, vtxPrev)
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
    //HCE: Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pos.hashBlk);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->Height();
}



//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::NewBlockFromString(const CBlockIndex* pindex, string&& payload)
{
    try {
        CAutoBuffer autobuff(std::move(payload));
        autobuff >> *this;
        if (GetHash() == pindex->GetBlockHash()) {
            return true;
        }
    }
    catch (std::ios_base::failure& e) {
        return ERROR_FL("%s", e.what());
    }
    return false;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
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
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
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
            //HCE: to be fixed
            RSyncRemotePullHyperBlock(pindex->triaddr.hid);
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

bool CBlock::ReadFromDisk(const CBlockIndexSimplified* pindex)
{
    //HCE: Read from cache at first
    bool isGot = false;
    if (ReadFromMemoryPool(pindex->GetBlockHash())) {
        isGot = true;
    }
    else {
        BLOCKTRIPLEADDRESS blkaddr = pindex->addr;
        if (!pindex->addr.isValid()) {
            BLOCKTRIPLEADDRESS addr;
            if (!COrphanBlockTripleAddressDB().ReadBlockTripleAddress(pindex->GetBlockHash(), addr))
                return WARNING_FL("Block TripleAddress unknown: %d", pindex->nHeight);
            blkaddr = addr.ToAddr();
        }

        //HCE: Read data from chain space
        if (ReadFromDisk(blkaddr)) {
            isGot = true;
        }
    }

    if (isGot && GetHash() == pindex->GetBlockHash())
        return true;
    return isGot ? WARNING_FL("GetHash() doesn't match index, Height: %d", pindex->nHeight) :
        WARNING_FL("Block unknown, Height: %d", pindex->nHeight);
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
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
    int64 nSubsidy = 50 * COIN;

    // Subsidy is cut in half every 4 years
    nSubsidy >>= (nHeight / 210000);

    return nSubsidy + nFees;
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
    if (pindexBest == NULL || nBestHeight < (GetTotalBlocksEstimate() - nInitialBlockThreshold))
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 10 &&
        pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    WARNING_FL("InvalidChainFound: invalid block=%s  height=%d \n", pindexNew->GetBlockHash().ToString().substr(0, 20).c_str(), pindexNew->Height());
    WARNING_FL("InvalidChainFound:  current best=%s  height=%d \n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight);
}

bool CTransaction::DisconnectInputs(CTxDB_Wrapper& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn & txin, vin)
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
        tx = mapTransactions[hashTx];
    }
    return true;
}

//HCE: find the transaction in the in-memory and unchained blocks
bool SeachTxInUnchainedBlocks(const uint256& hashTx, CTransaction& tx, CBlockIndex& idxBlock)
{
    bool isFound = false;
    CBlockIndex* pIndex = pindexBest;
    while (!isFound && pIndex && !pIndex->triaddr.isValid()) {
        auto hash = pIndex->GetBlockHash();
        if (!mapBlocks.contain(hash)) {
            pIndex = pIndex->pprev;
            continue;
        }

        for (auto& elmTx : mapBlocks[hash].vtx)
        {
            if (elmTx.GetHash() == hashTx) {
                isFound = true;
                tx = elmTx;
                idxBlock = *pIndex;
                break;
            }
        }
        pIndex = pIndex->pprev;
    }

    return isFound;
}

// HC: find the transaction in the in - memory and unchained blocks
bool SearchTxByBlockHeight(CBlockIndex* pindexBlock, const uint256& hashTx, int nBlockHeight, CTransaction& tx)
{
    CBlockIndex* pIndex = pindexBlock;
    while (pIndex) {
        if (pIndex->nHeight > nBlockHeight) {
            pIndex = pIndex->pprev;
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

bool CTransaction::ConnectInputs(CTxDB_Wrapper& txdb, map<uint256, std::tuple<CTxIndex, CTransaction>>& mapTestPool, CDiskTxPos posThisTx,
    CBlockIndex* pindexBlock, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee)
{
    // Take over previous transactions' spent pointers
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

            if (!fFound && (fBlock || fMiner))
                return fMiner ? false : ERROR_FL("%s prev tx %s index entry not found", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());

            if (!fFound || txindex.pos == CDiskTxPos(1)) {
                //HC: 连续交易，本交易的输入交易所在块就是当前块
                //HCE: For continuous trading, the input exchange of this transaction in the block is the current block
                // Get prev tx from single transactions in memory
                if (!SearchTxInTransactions(prevout.hash, txPrev))
                    return ERROR_FL("%s mapTransactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else {
                do {

                    if (fPreTxInThisBlk) {
                        break;
                    }

                    if (txPrev.ReadFromDisk(txindex.pos)) {
                        break;
                    }

                    //HCE: Search in transaction pool
                    if (!SearchTxInTransactions(prevout.hash, txPrev)) {
                        //if (!SearchTxByBlockHeight(pindexBlock, prevout.hash, txindex.pos.nHeight, txPrev)) {
                        //    return ERROR_FL("%s Transactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                        //}
                        return ERROR_FL("%s Transactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                    }
                } while (false);

                //HCE: no maturity for ledger
                //if (txPrev.IsCoinBase()) {
                //    if (pindexBlock->nHeight - txindex.pos.nHeight < COINBASE_MATURITY) {
                //        return ERROR_FL("tried to spend coinbase at depth %d", pindexBlock->nHeight - txindex.pos.nHeight);
                //    }
                //}
            }

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return ERROR_FL("%s prevout.n out of range %d %d %d prev tx %s\n%s", GetHash().ToString().substr(0, 10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0, 10).c_str(), txPrev.ToString().c_str());

            // If prev is coinbase, check that it's matured
            //HCE: no maturity for ledger
            //if (txPrev.IsCoinBase() && txindex.pos.addr.isValid()) {
            //    for (CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < COINBASE_MATURITY; pindex = pindex->pprev)
            //        if (pindex->addr == txindex.pos.addr)
            //            return ERROR_FL("tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);
            //}
            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return ERROR_FL("%s VerifySignature failed", GetHash().ToString().substr(0, 10).c_str());

            // Check for conflicts
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : ERROR_FL("%s prev tx already used at %s", GetHash().ToString().substr(0, 10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return ERROR_FL("txin values out of range");

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner) {
                mapTestPool[prevout.hash] = std::make_tuple(txindex, txPrev);
            }
        }

        if (nValueIn < GetValueOut())
            return ERROR_FL("%s value in < value out", GetHash().ToString().substr(0, 10).c_str());

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return ERROR_FL("%s nTxFee < 0", GetHash().ToString().substr(0, 10).c_str());
        if (nTxFee < nMinFee)
            return false;
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return ERROR_FL("nFees out of range");
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
            //     return ERROR_FL("prev tx already used");
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


bool CBlock::DisconnectBlock(CTxDB_Wrapper& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    auto spprev = pindex->pprev;
    if (spprev)
    {
        CDiskBlockIndex blockindexPrev(spprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    }

    //HCE: Remove transactions, maybe it is a bug for Bitcoin
    BOOST_FOREACH(CTransaction & tx, vtx)
        EraseFromWallets(tx.GetHash());

    return true;
}

bool CBlock::ConnectBlock(CTxDB_Wrapper& txdb, CBlockIndex* pindex)
{
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock())
        return false;

    //// issue here: it doesn't know the version
    unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 1 + GetSizeOfCompactSize(vtx.size());

    map<uint256, std::tuple<CTxIndex, CTransaction>> mapQueuedChanges;
    int64 nFees = 0;
    BOOST_FOREACH(CTransaction & tx, vtx)
    {
        CDiskTxPos posThisTx(nTxPos, nHeight, pindex->GetBlockHash());
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, mapQueuedChanges, posThisTx, pindex, nFees, true, false))
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

    //HCE: unnecessary check CoinBase tx value
    //if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
    //    return false;

    //HCE: Update block index on disk without changing it in memory.
    //HCE: The memory index structure will be changed after the db commits.
    auto spprev = pindex->pprev;
    if (spprev) {
        CDiskBlockIndex blockindexPrev(spprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction & tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}


bool static Reorganize(CTxDB_Wrapper& txdb, CBlockIndex* pindexNew)
{
    TRACE_FL("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger) {
        while (plonger->Height() > pfork->Height())
            if (!(plonger = plonger->pprev))
                return ERROR_FL("plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return ERROR_FL("pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex * pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return ERROR_FL("DisconnectBlock failed");

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction & tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (int i = 0; i < vConnect.size(); i++) {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex)) {
            // Invalid block
            return ERROR_FL("ConnectBlock failed");
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction & tx, block.vtx)
            vDelete.push_back(tx);
    }
    auto hash = pindexNew->GetBlockHash();
    if (!txdb.WriteHashBestChain(hash))
        return ERROR_FL("WriteHashBestChain failed");


    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex * pindex, vDisconnect)
    {
        auto spprev = pindex->pprev;
        if (spprev) {
            spprev->pnext = nullptr;
        }
    }

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex * pindex, vConnect)
    {
        auto spprev = pindex->pprev;
        if (spprev) {
            spprev->pnext = pindex;
        }
    }

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return ERROR_FL("TxnCommit failed");

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction & tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction & tx, vDelete)
        tx.RemoveFromMemoryPool();

    return true;
}


bool CBlock::SetBestChain(CTxDB_Wrapper& txdb, CBlockIndex* pindexNew)
{
    if (pindexNew == pindexBest) {
        return true;
    }

    //HCE: make sure the reference count > 1, avoid db flush frequencely
    CBlockDB_Wrapper blkdb;

    uint256 hash = GetHash();

    txdb.TxnBegin();
    if (pindexGenesisBlock == nullptr && hash == hashGenesisBlock) {
        //HCE: Connect genesis block's transactions
        ConnectBlock(txdb, pindexNew);
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain) {
        // Adding to current best branch
        if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("ConnectBlock failed");
        }
        //HCE: let pnext pointer of all previous blocks point to pindexNew
        CBlockIndex* p = pindexNew->pprev;
        if (p) {
            p->pnext = pindexNew;
            if (!txdb.WriteBlockIndex(CDiskBlockIndex(p))) {
                txdb.TxnAbort();
                return ERROR_FL("WriteBlockIndex failed");
            }
        }

        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");

        // Delete redundant memory transactions
        BOOST_FOREACH(CTransaction & tx, vtx)
            tx.RemoveFromMemoryPool();
    }
    else {
        // New best branch
        if (!Reorganize(txdb, pindexNew)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("Reorganize failed");
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    if (!IsInitialBlockDownload()) {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    nBestHeight = pindexBest->Height();
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    TRACE_FL("SetBestChain: new best=%s  height=%d \n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight);

    return true;
}

bool CBlock::UpdateToBlockIndex(const BLOCKTRIPLEADDRESS& blktriaddr)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (!mapBlockIndex.count(hash))
        return ERROR_FL("%s not exists", hash.ToString().substr(0, 20).c_str());

    CBlockIndex* pIndex = mapBlockIndex[hash];
    pIndex->triaddr = blktriaddr;

    CTxDB_Wrapper txdb;

    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pIndex));

    if (!txdb.TxnCommit())
        return false;

    return true;
}

bool CBlock::UpdateToBlockIndex(CBlockIndex* pIndex, const BLOCKTRIPLEADDRESS& blktriaddr)
{
    pIndex->triaddr = blktriaddr;

    CTxDB_Wrapper txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pIndex));
    auto spprev = pIndex->pprev;
    if (spprev) {
        spprev->pnext = pIndex;
        txdb.WriteBlockIndex(CDiskBlockIndex(spprev));
    }

    if (!txdb.TxnCommit())
        return false;

    return true;
}

bool CBlock::AddToBlockIndex(const BLOCKTRIPLEADDRESS& addr)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return ERROR_FL("%s already exists", hash.ToString().substr(0, 20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(addr, *this);
    if (!pindexNew)
        return ERROR_FL("new CBlockIndex failed");

    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end()) {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->Height() + 1;
        //HCE: here cannot set miPrev->second->pnext, because the action will be do in 'SetBestChain'
        //miPrev->second->pnext = pindexNew;
    }

    CTxDB_Wrapper txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    pindexNew->print();
    //new block
    //HCE: if (!pindexBest || pindexNew->addr >= pindexBest->addr)
    if (!SetBestChain(txdb, pindexNew))
        return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    MainFrameRepaint();
    return true;
}

/*
bool CBlock::AddToBlockIndex(const T_LOCALBLOCKADDRESS& addr)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return ERROR_FL("%s already exists", hash.ToString().substr(0, 20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(addr, *this);
    if (!pindexNew)
        return ERROR_FL("new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        //HCE:
        //pindexNew->Height() = pindexNew->pprev->Height() + 1;
    }
    pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

    CTxDB txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    //new block
    if (pindexNew > pindexBest)
        if (!SetBestChain(txdb, pindexNew))
            return false;

    if (!ConnectBlock(txdb,pindexNew))
        return false;

    txdb.Close();

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    MainFrameRepaint();
    return true;
}
*/

//HCE: don't call this
/*
bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return ERROR_FL("%s already exists", hash.ToString().substr(0, 20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return ERROR_FL("new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

    CTxDB txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    if (pindexNew->bnChainWork > bnBestChainWork)
        if (!SetBestChain(txdb, pindexNew))
            return false;

    txdb.Close();

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    MainFrameRepaint();
    return true;
}
*/

bool CBlock::CheckBlock() const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
        return ERROR_FL("size limits failed");


    // Check timestamp
    //HCE: Skip the time check
    //if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    //    return ERROR_FL("block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    //HCE: remove the following check condition
    //if (vtx.empty() || !vtx[0].IsCoinBase())
    //    return ERROR_FL("first tx is not coinbase");
    //for (int i = 1; i < vtx.size(); i++)
    //    if (vtx[i].IsCoinBase())
    //        return ERROR_FL("more than one coinbase");

    // Check transactions
    BOOST_FOREACH(const CTransaction & tx, vtx)
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
    BOOST_FOREACH(const CTransaction & tx, vtx)
    {
        BOOST_FOREACH(const CTxIn & txin, tx.vin)
            if (!txin.IsFinal())
                return ERROR_FL("contains a non-final transaction");
    }
    //HCE:
    //if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
    //    return ERROR_FL("out of disk space");
    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();

    BLOCKTRIPLEADDRESS tripleaddr;
    LatestLedgerBlock::GetBlockTripleAddr(hash, tripleaddr);

    while (mapBlockIndex.count(hash)) {
        //HCE: Update the logic address and block index for the block
        CBlockIndex* pIndex = mapBlockIndex[hash];
        if (pIndex->triaddr.isValid()) {
            if (tripleaddr == pIndex->triaddr) {
                TRACE_FL("block already in mapBlockIndex %s", hash.ToString().substr(0, 20).c_str());
                break;
            }
            TRACE_FL("block already in mapBlockIndex %s,but need to update logic address", hash.ToString().substr(0, 20).c_str());
        }

        if (tripleaddr.isValid()) {
            if (!UpdateToBlockIndex(tripleaddr)) {
                ERROR_FL("UpdateToBlockIndex failed");
            }
        }
        break;
    }

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end()) {
        return WARNING_FL("prev block not found, pulling from neighbor");
    }
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->Height() + 1;

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return ERROR_FL("block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction & tx, vtx)
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
    //        return ERROR_FL("AcceptBlock() : rejected by checkpoint lockin at %d", nHeight);

    // Write block to history file

    //HCE: don't save to disk
    //if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
    //    return ERROR_FL("AcceptBlock() : out of disk space");
    //unsigned int nFile = -1;
    //unsigned int nBlockPos = 0;
    //if (!WriteToDisk(nFile, nBlockPos))
    //    return ERROR_FL("AcceptBlock() : WriteToDisk failed");
    //if (!AddToBlockIndex(nFile, nBlockPos))
        //return ERROR_FL("AcceptBlock() : AddToBlockIndex failed");

    if (!AddToMemoryPool(hash))
        return ERROR_FL("Block AddToMemoryPool failed");

    if (!AddToBlockIndex(tripleaddr))
        return ERROR_FL("AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    //HCE: no need inventory
    //if (hashBestChain == hash)
    //    CRITICAL_BLOCK(cs_vNodes)
    //    BOOST_FOREACH(CNode* pnode, vNodes)
    //    if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 140700))
    //        pnode->PushInventory(CInv(MSG_BLOCK, hash));

    return true;
}

/*
bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return error("AcceptBlock() : prev block not found");
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    if (nBits != GetNextWorkRequired(pindexPrev))
        return error("AcceptBlock() : incorrect proof of work");

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return error("AcceptBlock() : contains a non-final transaction");

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

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    if (hashBestChain == hash)
        CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
        if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 140700))
            pnode->PushInventory(CInv(MSG_BLOCK, hash));

    return true;
}
*/

void ProcessOrphanBlocks(const uint256& hash)
{
    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++) {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlockSP>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
            mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
            ++mi) {
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
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    INFO_FL("%s %d ", hash.ToPreViewString().c_str(), pblock->nHeight);
    if (mapBlockIndex.count(hash))
        return INFO_FL("already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToPreViewString().c_str());
    if (mapOrphanBlocks.count(hash))
        return INFO_FL("already have block %d %s (orphan)", mapOrphanBlocks[hash]->nHeight, hash.ToPreViewString().c_str());

    // Preliminary checks
    if (!pblock->CheckBlock())
        return WARNING_FL("CheckBlock %s FAILED", hash.ToPreViewString().c_str());

    bool hyperblock_ok = true;
    if (pfrom) {
        //HCE: Received block
        int ret = pblock->CheckHyperBlockConsistence(pfrom);
        if (ret != 0) {
            /*if (ret == -2 && pblockaddr->isValid()) {
                mapSubsequentBlockAddr.insert(make_pair(pblock->nPrevHID, *pblockaddr));
            }*/
            /*if (pblock->nHeight > pindexBest->nHeight + BLOCK_MATURITY) {
                RequestBlockSpace(pfrom);
            }*/
            hyperblock_ok = false;
            //return WARNING_FL("Block: %s CheckHyperBlockConsistence invalid at height %d, cause: %d\n",
            //    hash.ToPreViewString().c_str(), pblock->nHeight, ret);
        }
    }

    //HCE: If don't already have its previous block, shunt it off to holding area until we get it
    if (!hyperblock_ok || !mapBlockIndex.count(pblock->hashPrevBlock)) {
        WARNING_FL("%s ORPHAN BLOCK, hyperblock_ok:%d prev=%s\n", hash.ToPreViewString().c_str(),
            hyperblock_ok,
            pblock->hashPrevBlock.ToPreViewString().c_str());

        CBlockSP spblock2 = make_shared<CBlock>(*pblock);
        mapOrphanBlocks.insert(make_pair(hash, spblock2));
        mapOrphanBlocksByPrev.insert(make_pair(spblock2->hashPrevBlock, spblock2));

        bool isReady = g_chainReadyCond.IsReady();

        //HCE: save the orphan block.
        if (!isReady) {
            COrphanBlockDB_Wrapper blockdb;
            blockdb.WriteBlock(*spblock2);
        }
        // Ask this guy to fill in what we're missing
        if (pfrom && isReady)
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(spblock2.get()));
        return true;
    }

    if (g_chainReadyCond.IsSwitching()) {
        //HCE: Switching, avoid to switch again
        return false;
    }
    // Store to disk
    if (!pblock->AcceptBlock())
        return ERROR_FL("AcceptBlock %s FAILED", hash.ToPreViewString().c_str());

    ProcessOrphanBlocks(hash);

    TRACE_FL("ProcessBlock: %s ACCEPTED\n", hash.ToPreViewString().c_str());
    return true;
}

bool ProcessBlockWithTriaddr(CNode* pfrom, CBlock* pblock, BLOCKTRIPLEADDRESS* pblockaddr)
{
    uint256 hash = pblock->GetHash();
    if (pblockaddr && pblockaddr->isValid()) {
        if (mapBlockIndex.count(hash)) {
            //HCE: compare and update block address
            CBlockIndex* pIndex = mapBlockIndex[hash];
            if (pIndex->triaddr != *pblockaddr) {
                if (!pblock->UpdateToBlockIndex(pIndex, *pblockaddr)) {
                    return ERROR_FL("UpdateToBlockIndex failed");
                }
            }
        }
        else {
            if (!COrphanBlockTripleAddressDB().WriteBlockTripleAddress(hash, *pblockaddr))
                return ERROR_FL("COrphanBlockTripleAddressDB::WriteBlockTripleAddress failed");
        }
    }

    ProcessBlock(pfrom, pblock);
    if (pblockaddr && pblockaddr->isValid()) {
        if (!mapBlockIndex.count(hash)) {
            return false;
        }

        //HCE: compare and update block address
        CBlockIndex* pIndex = mapBlockIndex[hash];
        if (pIndex->triaddr != *pblockaddr) {
            if (!pblock->UpdateToBlockIndex(pIndex, *pblockaddr)) {
                return ERROR_FL("UpdateToBlockIndex failed");
            }
        }

        return true;
    }

    return false;
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
        WARNING_FL("*** %s\n", strMessage.c_str());
        ThreadSafeMessageBox(strMessage, "Hyperchain", wxOK | wxICON_EXCLAMATION);
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
        FILE * file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
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
string GetGenesisBlock(string & payload)
{
    CBlock genesis;

    genesis = g_cryptoToken.GetGenesisBlock();

    CDataStream datastream(SER_BUDDYCONSENSUS);
    datastream << genesis;
    payload = datastream.str();

    datastream.clear();
    datastream << genesis.hashMerkleRoot;
    return datastream.str();
}

//HCE:
void AddGenesisBlockToIndex()
{
    //HCE: Mine genesis block
    //CKey genesiskey;
    //genesiskey.MakeNewKey();
    //g_cryptoToken.MineGenesisBlock(genesiskey);
    //WriteKeyToFile(genesiskey);

    CBlock genesis;
    genesis = g_cryptoToken.GetGenesisBlock();

    uint256 hashGenesis = genesis.GetHash();

    //string str = hashGenesis.ToString();
    assert(hashGenesis == g_cryptoToken.GetHashGenesisBlock());

    //HCE: Ledger genesis block exists in HC genesis block
    T_LOCALBLOCKADDRESS addr;
    addr.hid = g_cryptoToken.GetHID();
    addr.chainnum = g_cryptoToken.GetChainNum();
    addr.id = g_cryptoToken.GetLocalID();

    genesis.AddToBlockIndex(addr);
}

//HC: 读取还未进行底层Buddy共识的块
//HCE: Read blocks that have not yet had underlying Buddy consensus
bool LoadBlockUnChained()
{
    cout << "Ledger: read block cache asynchronously in the background...\n";

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
        AddGenesisBlockToIndex();
    }

    return true;
}



void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
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
            pindex->Height(),
            block.GetHash().ToString().substr(0, 20).c_str(),
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
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

    // Alerts
    CRITICAL_BLOCK(cs_mapAlerts)
    {
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert) & item, mapAlerts)
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
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert) & item, mapAlerts)
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
    switch (inv.type) {
    case MSG_TX:    return mapTransactions.count(inv.hash) || mapOrphanTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:
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

        if (LatestLedgerBlock::Count(inv.hash)) {
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
    CBlockIndex* pindexOnChained = LatestBlockIndexOnChained();

    pfrom->PushGetBlocks(pindexOnChained, uint256(0));

}

const int SentBlock_TimeOut = 30;

void InsertSentBlock(CNode* pfrom, const uint256& hashBlock, const uint256& hashPrevBlock)
{
    if (!pfrom->mapBlockSent.count(hashBlock)) {
        //HCE: clear expired element
        auto now = time(nullptr);
        if (pfrom->mapBlockSent.size() > 60) {
            auto it = pfrom->mapBlockSent.begin();
            for (; it != pfrom->mapBlockSent.end(); ) {
                if (std::get<0>(*it) + SentBlock_TimeOut < now) {
                    pfrom->mapBlockSent.erase(it++);
                }
                else {
                    ++it;
                }
            }
        }
        pfrom->mapBlockSent.insert(std::make_pair(hashBlock, std::make_tuple(now, hashPrevBlock)));
    }
    else {
        auto& blkelm = pfrom->mapBlockSent[hashBlock];
        std::get<0>(blkelm) = time(nullptr);
    }
}

extern bool SwitchChainTo(CBlockIndex* pindexBlock);

void ReplyPBFT(CNode* pfrom, std::vector<CBlock>& vblock, const vector<unsigned char>& vchSig)
{
    if (!g_cryptoToken.AmIConsensusNode()) {
        return;
    }

    if (!g_cryptoToken.VerifyBlocks(pfrom->nPKeyIdx, vchSig, vblock)) {
        WARNING_FL("Failed to VerifyBlocks from PKIdx: %d\n", pfrom->nPKeyIdx);
        return;
    }

    //HCE: call ProcessBlock to check blocks
    auto* p = pindexBest;
    for (auto& blk : vblock) {
        if (!ProcessBlock(pfrom, &blk)) {
            ERROR_FL("ProcessBlock error\n");
            SwitchChainTo(p);
            return;
        }
    }

    //HCE: switch to the origin best block
    SwitchChainTo(p);

    vector<unsigned char> vchSigReply;
    if (g_cryptoToken.SignBlocks(vblock, vchSigReply)) {
        DEBUG_FL("Reply my sign, PKIdx: %d\n", g_cryptoToken.GetPKIdx());
        pfrom->PushMessage("PBFTP", vchSigReply);
    }
}

void ReplyRGetBlocks(CNode* pfrom, uint256 hashBlock, int64 timeReq)
{
    int nLimit = 500;
    int nTotalSendBlock = 0;
    int nMaxSendSize = 256 * 1024;
    int nTotalSendSize = 0;

    uint256 hashPrevBlock;
    CBlock block;
    CBlockIndex* pindex = nullptr;
    LogRequestFromNode(pfrom->nodeid, "\n\nRespond rgetblocks(cache size: %d): %s from: %s ***********************\n", pfrom->mapBlockSent.size(),
        hashBlock.ToPreViewString().c_str(), pfrom->nodeid.c_str());

    while (1) {
        if (nTotalSendBlock >= nLimit || nTotalSendSize > nMaxSendSize) {
            LogRequestFromNode(pfrom->nodeid, "  rgetblocks limit(%d, %.2f KB) stoppped at: %s\n",
                nTotalSendBlock, (float)nTotalSendSize / 1024,
                hashBlock.ToPreViewString().c_str());
            break;
        }

        if (pfrom->mapBlockSent.count(hashBlock)) {
            auto& blkelm = pfrom->mapBlockSent[hashBlock];
            if (std::get<0>(blkelm) + SentBlock_TimeOut > time(nullptr)) {
                //HCE: Already sent before 30 seconds, don't send again
                hashBlock = std::get<1>(blkelm);
                LogRequestFromNode(pfrom->nodeid, "  rgetblocks %s, already sent, don't send again\n", hashBlock.ToPreViewString().c_str());
                continue;
            }
        }

        if (mapBlockIndex.count(hashBlock)) {

            pindex = mapBlockIndex[hashBlock];

            string hashpreview = hashBlock.ToPreViewString().c_str();

            if (!pindex) {
                mapBlockIndex.erase(hashBlock);
                LogRequestFromNode(pfrom->nodeid, "  rgetblocks stoppped at: %s due to null block index\n", hashpreview.c_str());
                break;
            }

            LogRequestFromNode(pfrom->nodeid, "  rgetblocks will send %s(%s) to node: %s\n", hashpreview.c_str(),
                pindex->triaddr.ToString().c_str(),
                pfrom->nodeid.c_str());

            CBlock block;
            BLOCKTRIPLEADDRESS addrblock;
            char* pWhere = nullptr;

            if (GetBlockData(pindex->GetBlockHash(), block, addrblock, &pWhere)) {
                BLOCKTRIPLEADDRESS tripleaddr(addrblock);

                nTotalSendBlock++;
                nTotalSendSize += block.GetSerializeSize(SER_NETWORK) + sizeof(BLOCKTRIPLEADDRESS);
                pfrom->PushMessage("rblock", block, tripleaddr, timeReq);

                InsertSentBlock(pfrom, hashBlock, block.hashPrevBlock);
                hashBlock = block.hashPrevBlock;
                continue;
            }
            else {
                LogRequestFromNode(pfrom->nodeid, "  rgetblocks no found %s(%s)\n", hashpreview.c_str(),
                    pindex->triaddr.ToString().c_str());
            }
        }
        else if (LatestLedgerBlock::Count(hashBlock)) {
            CBlock block;
            BLOCKTRIPLEADDRESS tripleaddr;
            if (!LatestLedgerBlock::GetBlock(hashBlock, block, tripleaddr)) {
                LogRequestFromNode(pfrom->nodeid, "\n\nRespond regetblocks(read %s failed) from node %s *************************************\n",
                    hashBlock.ToPreViewString().c_str(),
                    pfrom->nodeid.c_str());
            }
            else {

                LogRequestFromNode(pfrom->nodeid, "rgetblocks send %s(tripleaddr: %s) to node: %s\n",
                    hashBlock.ToPreViewString().c_str(),
                    tripleaddr.ToString().c_str(),
                    pfrom->nodeid.c_str());

                nTotalSendBlock++;
                nTotalSendSize += block.GetSerializeSize(SER_NETWORK) + sizeof(BLOCKTRIPLEADDRESS);
                pfrom->PushMessage("rblock", block, tripleaddr, timeReq);

                InsertSentBlock(pfrom, hashBlock, block.hashPrevBlock);
                hashBlock = block.hashPrevBlock;
                continue;
            }
        }
        LogRequestFromNode(pfrom->nodeid, "  rgetblocks (%d, %.2f KB) stoppped at: %s due to no found\n",
            nTotalSendBlock, (float)nTotalSendSize / 1024,
            hashBlock.ToPreViewString().c_str());
        break;
    }
}

bool GetBlockData(const uint256& hashBlock, CBlock& block, BLOCKTRIPLEADDRESS& addrblock, char** pWhere)
{
    addrblock = BLOCKTRIPLEADDRESS();

    auto mi = mapBlockIndex[hashBlock];
    if (mi) {
        if (block.ReadFromDisk(mi)) {
            addrblock = mi->triaddr;
            *pWhere = "mapBlockIndex";
            return true;
        }
    }
    else if (mapOrphanBlocks.count(hashBlock)) {
        block = *(mapOrphanBlocks[hashBlock]);
        BLOCKTRIPLEADDRESS tripleaddr;
        if (COrphanBlockTripleAddressDB().ReadBlockTripleAddress(hashBlock, tripleaddr)) {
            addrblock = tripleaddr;
        }
        *pWhere = "mapOrphanBlocks";
        return true;
    }
    else if (LatestLedgerBlock::Count(hashBlock)) {
        BLOCKTRIPLEADDRESS tripleaddr;
        if (LatestLedgerBlock::GetBlock(hashBlock, block, tripleaddr)) {
            addrblock = tripleaddr;
            *pWhere = "LatestParaBlock";
            return true;
        }
    }

    TRACE_FL("I have not Block: %s\n", hashBlock.ToPreViewString().c_str());
    return false;
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static int nAskedForBlocks = 0;
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    RandAddSeedPerfmon();
    TRACE_FL("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    TRACE_FL("received: %s (%d bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        TRACE_FL("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    //HC: 不同版本有不同的数据通讯格式，所以必须有版本号才能开始交互
    //HCE: Different versions have different data communication formats, so you must have a version number to start the interaction
    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            // tell version,under udp environment, maybe node hasn't still received the verack message.
            TRACE_FL("I had its version information,Maybe it has restarted, so update version. (%s)", pfrom->addr.ToString().c_str());
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (pfrom->nVersion >= 106 && !vRecv.empty())
            vRecv >> addrFrom >> nNonce;

        //HCE:
        vector<unsigned char> vchSig;

        int nPKIdx = -1;
        vRecv >> nPKIdx >> vchSig;

        if (g_cryptoToken.Verify(nPKIdx, vchSig, &nNonce, &nNonce)) {
            pfrom->nPKeyIdx = nPKIdx;
        }

        if (pfrom->nVersion >= 106 && !vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (pfrom->nVersion >= 209 && !vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->nVersion == 0)
            return false;

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
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

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (addrLocalHost.IsRoutable() && !fUseProxy)
            {
                CAddress addr(addrLocalHost);
                addr.nTime = GetAdjustedTime();
                pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->nVersion >= 31402 || mapAddresses.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
        }

        // Ask the first connected node for block updates
        if (!pfrom->fClient &&
            (pfrom->nVersion < 32000 || pfrom->nVersion >= 32400) &&
            (nAskedForBlocks < 1 || vNodes.size() <= 1))
        {
            nAskedForBlocks++;
            RequestBlockSpace(pfrom);
        }

        // Relay alerts
        CRITICAL_BLOCK(cs_mapAlerts)
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert) & item, mapAlerts)
            item.second.RelayTo(pfrom);

        pfrom->fSuccessfullyConnected = true;

        TRACE_FL("version message: version %d, blocks=%d\n", pfrom->nVersion, pfrom->nStartingHeight);
    }
    else if (strCommand == "veragain") {
        pfrom->PushVersion();
        //if (nAskedForBlocks > 0) {
            //HCE: UDP is different from TCP,how to control the command order: verack and getblocks?
            //HCE: if nVersion == 0, then throw getblocks command? (PushGetBlocks)
            //RequestBlockSpace(pfrom);
        //}
        //return true;
    }
    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        TRACE_FL("I have not yet node version info, Maybe myself restarted, please tell me again. (%s)", pfrom->addr.ToString().c_str());
        pfrom->PushMessage("veragain");
        pfrom->nVersion = VERSION;
    }

    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));
    }
    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

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
            if (fShutdown)
                return true;
            // ignore IPv6 for now, since it isn't implemented anyway
            if (!addr.IsIPv4())
                continue;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            AddAddress(addr, 2 * 60 * 60, &addrDB);
            pfrom->AddAddressKnown(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
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
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > 50000)
            return ERROR_FL("message inv size() = %d", vInv.size());

        CTxDB_Wrapper txdb;
        BOOST_FOREACH(const CInv & inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);

            bool fAskFor = false;
            bool fPushGetBlocks = false;
            if (!fAlreadyHave) {
                pfrom->AskFor(inv);
                fAskFor = true;
            }
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash].get()));
                fPushGetBlocks = true;
            }

            DEBUG_FL("  got inventory: %s  %s, askfor: %s pushPutBlocks: %s\n", inv.ToString().c_str(),
                fAlreadyHave ? "have" : "new",
                fAskFor ? "yes" : "no",
                fPushGetBlocks ? "yes" : "no");

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > 50000)
            return ERROR_FL("message getdata size() = %d", vInv.size());

        BOOST_FOREACH(const CInv & inv, vInv)
        {
            if (fShutdown)
                return true;
            TRACE_FL("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block, mi->second->triaddr);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
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
    }
    else if (strCommand == "rgetblocks") {
        uint256 hashBlock;
        vRecv >> hashBlock;

        int64 timeReq;
        vRecv >> timeReq;

        ReplyRGetBlocks(pfrom, hashBlock, timeReq);
    }

    else if (strCommand == "getblocks") {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 25; //500 +locator.GetDistanceBack();
        unsigned int nBytes = 0;
        TRACE_FL("\n\nRespond**************************************\n");
        TRACE_FL("getblocks %d to %s limit %d from node: %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0, 20).c_str(),
            nLimit,
            pfrom->nodeid.c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                TRACE_FL("  getblocks stopping at %d %s (%u bytes)\n", pindex->Height(), pindex->GetBlockHash().ToString().substr(0, 20).c_str(), nBytes);
                break;
            }

            CBlock block;
            if (!block.ReadFromDisk(pindex, true)) {
                continue;
            }

            TRACE_FL("getblocks send %s(%s) to node: %s\n", pindex->GetBlockHash().ToPreViewString().c_str(),
                pindex->triaddr.ToString().c_str(),
                pfrom->nodeid.c_str());
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            nBytes += block.GetSerializeSize(SER_NETWORK);
            if (--nLimit <= 0 || nBytes >= SendBufferSize())
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                TRACE_FL("  getblocks stopping at limit %d %s (%u bytes)\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str(), nBytes);
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000 + locator.GetDistanceBack();
        TRACE_FL("getheaders %d to %s limit %d\n", (pindex ? pindex->Height() : -1), hashStop.ToString().substr(0, 20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                    mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                    ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());

                    if (tx.AcceptToMemoryPool(true))
                    {
                        TRACE_FL("   accepted orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vWorkQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            TRACE_FL("storing orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
            AddOrphanTx(vMsg);
        }
    }

    else if (strCommand == "PBFTPP") {
        vector<CBlock> vblock;
        vector<unsigned char> vchSig;
        vRecv >> vblock >> vchSig;
        ReplyPBFT(pfrom, vblock, vchSig);
    }
    else if (strCommand == "PBFTP") {
        vector<unsigned char> vchSig;
        vRecv >> vchSig;
        g_PBFT.Prepare(pfrom->nPKeyIdx, vchSig);
    }

    else if (strCommand == "rblock") {

        CBlock block;
        vRecv >> block;

        BLOCKTRIPLEADDRESS tripleaddr;
        vRecv >> tripleaddr;

        int64 timeReqBlk;
        vRecv >> timeReqBlk;

        auto blkhash = block.GetHash();

        LogRequest("rblock: Received block %s from %s(Score will +1,current: %d), triple address: %s\n", blkhash.ToString().substr(0, 20).c_str(),
            pfrom->nodeid.c_str(), pfrom->nScore, tripleaddr.ToString().c_str());

        pfrom->DecreReqBlkInterval(timeReqBlk);

        //HCE: to do: how to store tripleaddr?
        ProcessBlockWithTriaddr(pfrom, &block, &tripleaddr);
    }
    else if (strCommand == "block") {
        CBlock block;
        vRecv >> block;

        BLOCKTRIPLEADDRESS addrblock;
        vRecv >> addrblock;

        uint256 hash = block.GetHash();
        DEBUG_FL("Received block %s from %s, triple address: %s\n", hash.ToString().substr(0, 20).c_str(),
            pfrom->nodeid.c_str(), addrblock.ToString().c_str());

        ProcessBlockWithTriaddr(pfrom, &block, &addrblock);

        CInv inv(MSG_BLOCK, hash);
        pfrom->AddInventoryKnown(inv);
        mapAlreadyAskedFor.erase(inv);

    }

    else if (strCommand == "getaddr") {
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
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr.ip], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping") {
        int64 timeReq;
        vRecv >> timeReq;
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        if (alert.ProcessAlert())
        {
            // Relay
            pfrom->setKnown.insert(alert.GetHash());
            CRITICAL_BLOCK(cs_vNodes)
                BOOST_FOREACH(CNode * pnode, vNodes)
                alert.RelayTo(pnode);
        }
    }
    //HCE: new command
    else if (strCommand == "checkblock")
    {
        vRecv >> pfrom->nHeightCheckPointBlock;
        vRecv >> pfrom->hashCheckPointBlock;

        BLOCKTRIPLEADDRESS tripleaddr;
        vRecv >> tripleaddr;

        CBlockIndexSimplified* pIndex = LatestLedgerBlock::Get();
        if (!pIndex) {
            return true;
        }
        //HCE: sync block
        if (pIndex->nHeight < pfrom->nHeightCheckPointBlock) {
            vector<T_PAYLOADADDR> vecPA;
            T_SHA256 hhash;
            T_APPTYPE app(APPTYPE::ledger, g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID());
            CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
            if (hyperchainspace->GetLocalBlocksByHID(tripleaddr.hid, app, hhash, vecPA)) {
                LatestLedgerBlock::CompareAndUpdate(vecPA, true);
            }
            else {
                RSyncRemotePullHyperBlock(tripleaddr.hid, pfrom->nodeid);
            }
        }

        DEBUG_FL("received check point block: %d, %s from %s\n",
            pfrom->nHeightCheckPointBlock, pfrom->hashCheckPointBlock.ToPreViewString().c_str(), pfrom->nodeid.c_str());
    }
    //HCE: new command
    else if (strCommand == "getchkblock")
    {
        DEBUG_FL("getchkblock from %s\n", pfrom->nodeid.c_str());
        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            CBlockIndexSimplified* pIndex = LatestLedgerBlock::Get();
            if (!pIndex) {
                return true;
            }

            uint256 hash = pIndex->GetBlockHash();
            BLOCKTRIPLEADDRESS blktripleaddr(pIndex->addr);
            pfrom->PushMessage("checkblock", pIndex->nHeight, hash, blktripleaddr);

            DEBUG_FL("getchkblock reply: %d %s from %s\n", pIndex->nHeight, hash.ToPreViewString().c_str(),
                pfrom->nodeid.c_str());
        }
    }
    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


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

    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize)
        {
            if (vRecv.size() > nHeaderSize)
            {
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
        if (!hdr.IsValid())
        {
            ERROR_FL("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE)
        {
            ERROR_FL("ProcessMessage(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        if (vRecv.GetVersion() >= 209)
        {
            uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            if (nChecksum != hdr.nChecksum)
            {
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
            CRITICAL_BLOCK_T_MAIN(cs_main)
            {
                //HCE: Process hyper block reached message
                hyperblockMsgs.process();
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }

            if (fShutdown)
                return true;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from underlength message on vRecv
                ERROR_FL("ProcessMessage(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from overlong size
                ERROR_FL("ProcessMessage(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
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
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty())
            pto->PushMessage("ping", currentMillisecond());

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (GetTime() - nLastRebroadcast > 24 * 60 * 60)
        {
            nLastRebroadcast = GetTime();
            CRITICAL_BLOCK(cs_vNodes)
            {
                BOOST_FOREACH(CNode * pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (addrLocalHost.IsRoutable() && !fUseProxy)
                    {
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
        if (GetTime() - nLastClear > 10 * 60 && vNodes.size() >= 3)
        {
            nLastClear = GetTime();
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                CAddrDB addrdb;
                int64 nSince = GetAdjustedTime() - 14 * 24 * 60 * 60;
                for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.begin();
                    mi != mapAddresses.end();)
                {
                    const CAddress& addr = (*mi).second;
                    if (addr.nTime < nSince)
                    {
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
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress & addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
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
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        RAND_bytes((unsigned char*)&hashSalt, sizeof(hashSalt));
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
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
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        CTxDB_Wrapper txdb;
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                TRACE_FL("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 20)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            mapAlreadyAskedFor[inv] = nNow;
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

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
    for (;;)
    {
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
        if ((nNonce & 0xffff) == 0)
        {
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


CBlock* CreateNewBlock(CReserveKey& reservekey)
{
    CBlockIndex* pindexPrev = pindexBest;

    // Create new block
    CBlock* pblock(new CBlock());
    if (!pblock)
        return NULL;

    //HCE: no need coinbase
    // Create coinbase tx
    //CTransaction txNew;
    //txNew.vin.resize(1);
    //txNew.vin[0].prevout.SetNull();
    //txNew.vout.resize(1);
    //txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    //pblock->vtx.push_back(txNew);

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
    {
        pblock->SetHyperBlockInfo();

        CTxDB_Wrapper txdb;

        //HCE: Priority order to process transactions
        list<COrphan> vOrphan;          // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        multimap<double, CTransaction*> mapPriority;
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi)
        {
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
                    if (!porphan)
                    {
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

            if (GetBoolArg("-printpriority"))
            {
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
        while (!mapPriority.empty())
        {
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
            if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1), pindexPrev, nFees, false, true, nMinFee))
                continue;
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            nBlockSigOps += nTxSigOps;

            //HCE: Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan * porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                            mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
                    }
                }
            }
        }
    }
    //HCE: no need coinbase
    //pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->Height() + 1, nFees);

    if (pblock->vtx.size() == 0) {
        //HCE: no any transactions
        delete pblock;
        return nullptr;
    }
    // Fill in header
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    return pblock;
}


void FillBlockHeader(CBlockSP spblk)
{
    CBlockIndex* pindexPrev = pindexBest;

    spblk->hashPrevBlock = pindexPrev->GetBlockHash();
    spblk->hashMerkleRoot = spblk->BuildMerkleTree();
    spblk->nHeight = pindexPrev->nHeight + 1;
    spblk->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
}

//HCE: at least create 2 blocks
void CreateNewChain()
{
    CBlockSP pblock;
    // Collect memory pool transactions into the block
    int64 nFees = 0;
    CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
    {
        CTxDB_Wrapper txdb;

        //HCE: Priority order to process transactions
        list<COrphan> vOrphan;          // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        multimap<double, CTransaction*> mapPriority;
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi) {
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
                    if (!porphan) {
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

        if (mapPriority.size() + mapDependers.size() <= 1) {
            //HCE: Transactions too less to create two blocks at least
            return;
        }

        //HCE: Collect transactions
        map<uint256, std::tuple<CTxIndex, CTransaction>> mapTestPool;
        uint64 nBlockSize = 1000;
        int nBlockSigOps = 100;

        vector<std::tuple<CTransaction*, double>> vecTxs;
        while (!mapPriority.empty()) {
            //HCE: Take highest priority transaction off priority queue
            double dPriority = -(*mapPriority.begin()).first;
            CTransaction& tx = *(*mapPriority.begin()).second;
            mapPriority.erase(mapPriority.begin());

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
            if (nTxSize >= MAX_BLOCK_SIZE_GEN) {
                //HCE: too large size transaction
                continue;
            }

            int nTxSigOps = tx.GetSigOpCount();
            if (nTxSigOps >= MAX_BLOCK_SIGOPS) {
                continue;
            }

            //HCE: Transaction fee required depends on block size
            bool fAllowFree = (nBlockSize + nTxSize < 4000 || CTransaction::AllowFree(dPriority));
            int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, true);

            //HCE: Connecting shouldn't fail due to dependency on other memory pool transactions
            //HCE: because we're already processing them in order of dependency
            map<uint256, std::tuple<CTxIndex, CTransaction>> mapTestPoolTmp(mapTestPool);
            if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1), pindexBest, nFees, false, true, nMinFee)) {
                continue;
            }
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            auto txd = std::tuple<CTransaction*, double>{ &tx, dPriority };
            vecTxs.push_back(txd);

            //HCE: Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash)) {
                BOOST_FOREACH(COrphan * porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty()) {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty()) {
                            mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
                        }
                    }
                }
            }
        }

        mapTestPool.clear();
        nBlockSize = 1000;
        nBlockSigOps = 100;

        auto nTotalCount = vecTxs.size();
        size_t nTxInblk = 0;
        size_t nTxMinCount = nTotalCount / 2;

        // Create new blocks
        pblock.reset(new CBlock());
        pblock->SetHyperBlockInfo();

        //HCE: put transactions into block
        for (auto txp : vecTxs) {
            // Size limits
            CTransaction& tx = *std::get<0>(txp);
            double dPriority = std::get<1>(txp);

            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
            int nTxSigOps = tx.GetSigOpCount();

            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS ||
                nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN ||
                (nTxInblk > 0 && nTxInblk >= nTxMinCount)) {

                FillBlockHeader(pblock);
                if (!ProcessBlock(nullptr, pblock.get())) {
                    return;
                }

                //HCE: create new block and put transactions
                pblock.reset(new CBlock());
                pblock->SetHyperBlockInfo();

                mapTestPool.clear();
                nTxInblk = 0;
                nBlockSize = 1000;
                nBlockSigOps = 100;
                nTxMinCount = nTotalCount / 2 + 1;
            }

            //HCE: Transaction fee required depends on block size
            bool fAllowFree = (nBlockSize + nTxSize < 4000 || CTransaction::AllowFree(dPriority));
            int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, true);

            map<uint256, std::tuple<CTxIndex, CTransaction>> mapTestPoolTmp(mapTestPool);
            if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1), pindexBest, nFees, false, true, nMinFee)) {
                continue;
            }
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nTxInblk++;
            nBlockSize += nTxSize;
            nBlockSigOps += nTxSigOps;
        }

        if (pblock->vtx.size() == 0) {
            //HCE: no any transactions
            return;
        }

        FillBlockHeader(pblock);
        ProcessBlock(nullptr, pblock.get());
    }
}

CBlockSP CreateInitBlock(uint64 amount, const CBitcoinAddress& address)
{
    CBlockIndex* pindexPrev = pindexBest;

    // Create new block
    CBlockSP spblock(new CBlock());
    if (!spblock.get())
        return NULL;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey.SetBitcoinAddress(address);
    txNew.vout[0].nValue = amount;

    // Add our coinbase tx as only transaction
    spblock->vtx.push_back(txNew);

    // Fill in header
    spblock->hashPrevBlock = pindexPrev->GetBlockHash();
    spblock->hashMerkleRoot = spblock->BuildMerkleTree();
    spblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    //HCE: call IncrementExtraNonce, update vin[0].scriptSig
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(spblock.get(), nExtraNonce);
    return spblock;
}

bool CommitChainToConsensus(vector<CBlock>& vblock, string& requestid, string& errmsg)
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();

    vector<string> vecMTRootHash;
    vector<CUInt128> vecNodeId;

    uint32_t hid = g_cryptoToken.GetHID();
    uint16 chainnum = g_cryptoToken.GetChainNum();
    uint16 localid = g_cryptoToken.GetLocalID();

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    CUInt128 mynodeid = nodemgr->getMyNodeId<CUInt128>();

    if (consensuseng) {
        vector<PostingBlock> postingchain;
        //HCE: To SER_BUDDYCONSENSUS, avoid commit the ownerNodeID member of CBlock
        CDataStream datastream(SER_BUDDYCONSENSUS);
        size_t num = vblock.size();
        for (size_t i = 0; i < num; ++i) {

            PostingBlock blk;

            datastream.clear();
            datastream << vblock[i];

            blk.payload = datastream.str();

            datastream.clear();
            datastream << vblock[i].hashMerkleRoot;
            blk.hashMTRoot = datastream.str();

            for (auto& tx : vblock[i].vtx) {
                datastream.clear();
                blk.vecMT.push_back(tx.GetHash().ToString());
            }

            blk.nodeid = mynodeid;
            postingchain.push_back(std::move(blk));
        }

        auto number = consensuseng->AddChainEx(T_APPTYPE(APPTYPE::ledger, hid, chainnum, localid), postingchain);
        DEBUG_FL("Add a ledger chain to consensus layer: %u\n", number);
        return true;
    }
    else {
        errmsg = "Cannot commit chain to consensus, Consensus engine is stopped\n";
    }
    return false;
}

bool CommitToConsensus(CBlock* pblock, string& requestid, string& errmsg)
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
        data.app = T_APPTYPE(APPTYPE::ledger, g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID());
        data.MTRootHash = datastream.str();
        data.payload = payload;

        uint32 nOrder;
        string excp_desc;

        if (consensuseng->AddNewBlockEx(data, requestid, nOrder, excp_desc)) {
            DEBUG_FL("Add a Ledger block to consensus layer,requestid: %s\n", requestid.c_str());
            return true;
        }

        return false;
    }
    else {
        errmsg = "Cannot commit consensus, Consensus engine is stopped\n";
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
        data.app = T_APPTYPE(APPTYPE::ledger, 0, 0, 0);
        data.MTRootHash = datastream.str();
        data.payload = payload;

        uint32 nOrder;
        if (consensuseng->AddNewBlockEx(data, requestid, nOrder, errmsg)) {
            DEBUG_FL("Add a Ledger block to consensus layer,requestid: %s\n", requestid.c_str());
        }
        return true;
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
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
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

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (int i = 0; i < sizeof(tmp) / 4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


void ThreadBitcoinMiner(void* parg);

void static LedgerChainMonitor(CWallet* pwallet)
{
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    //HCE: Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;


    while (!fShutdown) {
        if (AffinityBugWorkaround(ThreadBitcoinMiner))
            return;
        if (fShutdown)
            return;

        string reason;
        while (!g_chainReadyCond.EvaluateIsAllowed()) {
            if (g_chainReadyCond.IsSwitching())
                Sleep(100);
            else
                SleepFn(2);

            if (fShutdown)
                return;
        }
        //Chain is integrated,so sleep for a while
        SleepFn(20);
    }
}

void ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try {
        vnThreadsRunning[3]++;
        LedgerChainMonitor(pwallet);
        vnThreadsRunning[3]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[3]--;
        PrintException(&e, "LedgerChainMonitor()");
    }
    catch (...) {
        vnThreadsRunning[3]--;
        PrintException(NULL, "LedgerChainMonitor()");
    }
    UIThreadCall(boost::bind(CalledSetStatusBar, "", 0));
    nHPSTimerStart = 0;
    if (vnThreadsRunning[3] == 0)
        dHashesPerSec = 0;
    DEBUG_FL("LedgerChainMonitor exiting, %d threads remaining\n", vnThreadsRunning[3]);
}


//HCE: Use GenerateBitcoins to create trading block
void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    if (fGenerateBitcoins != fGenerate) {
        fGenerateBitcoins = fGenerate;
        WriteSetting("fGenerateBitcoins", fGenerateBitcoins);
        MainFrameRepaint();
    }

    return;

    //HCE: "-gen" option to control if the system generates block, not create thread
    if (fGenerateBitcoins) {
        int nProcessors = boost::thread::hardware_concurrency();
        TRACE_FL("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;
        int nAddThreads = nProcessors - vnThreadsRunning[3];

        TRACE_FL("Starting Ledger chain thread\n");
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
