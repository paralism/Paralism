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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "block.h"
#include "latestledgerblock.h"

extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");

extern CBlockCacheLocator mapBlocks;

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

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
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
    catch (std::ios_base::failure& e) {
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
    if (prevout.n >= vout.size()) {
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

CTransaction& MakeTransactionRef(CTransaction& tx, CMutableTransaction&& mtx)
{
    tx.vin = std::forward<std::vector<CTxIn>>(mtx.vin);
    tx.vout = std::forward<std::vector<CTxOut>>(mtx.vout);
    tx.nVersion = mtx.nVersion;
    tx.nLockTime = mtx.nLockTime;
    return tx;
}

CTransaction::CTransaction(const CMutableTransaction& tx) :
    vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ ComputeHash() }, m_witness_hash{ ComputeWitnessHash() }
{}

bool CBlock::AddToMemoryPool(const uint256& nBlockHash)
{
    return mapBlocks.insert(nBlockHash, *this);
}

bool CBlock::AddToMemoryPool()
{
    uint256 hash = GetHash();
    return AddToMemoryPool(hash);
}

bool CBlock::RemoveFromMemoryPool()
{
    uint256 hash = GetHash();
    return mapBlocks.erase(hash);
}

bool CBlock::ReadFromMemoryPool(uint256 nBlockHash)
{
    SetNull();

    if (mapBlocks.contain(nBlockHash)) {
        *this = mapBlocks[nBlockHash];
        return true;
    }
    return false;
}

void CBlock::SetHyperBlockInfo()
{
    nPrevHID = LatestHyperBlock::GetHID(&hashPrevHyperBlock);
}

int CBlock::CheckHyperBlockConsistence(CNode* pfrom) const
{
    if (nHeight == 0) {
        return 0;
    }

    T_HYPERBLOCK h;
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    if (hyperchainspace->getHyperBlock(nPrevHID, h)) {

        T_SHA256 hash = h.GetHashSelf();
        uint256 hashCurr(hash.toHexString());

        if (hashCurr != hashPrevHyperBlock) {
            WARNING_FL("Hyper block %d: In my storage hash %s !!!== %s",
                nPrevHID, hashCurr.ToPreViewString().c_str(),
                hashPrevHyperBlock.ToPreViewString().c_str());
            //HC:give me your hyper block, maybe better than mine
            if (pfrom) {
                RSyncRemotePullHyperBlock(nPrevHID, pfrom->nodeid);
            }
            return -1;
        }
        return 0;
    }
    RSyncRemotePullHyperBlock(nPrevHID);

    WARNING_FL("I have not Hyper block: %d", nPrevHID);
    return -2;
}
