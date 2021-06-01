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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "block.h"
#include "latestledgerblock.h"

extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");

extern CBlockCacheLocator mapBlocks;

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
    string payload;
    if (pos.addr.isValid()) {

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        if (!hyperchainspace->GetLocalBlockPayload(pos.addr, payload)) {
            DEBUG_FL("block(%s) isn't found in my local storage", pos.addr.tostring().c_str());
            return false;
        }
    }
    else {


        CBlockIndex *pIndex = pindexBest;
        bool tx_ok = false;
        while (pIndex && pIndex->nHeight >= pos.nHeight) {
            if (pIndex->nHeight == pos.nHeight) {
                CBlockDB_Wrapper blockdb;
                uint256 hash;
                blockdb.LoadBlockUnChained(*pIndex->phashBlock, [&payload, &hash](CDataStream& ssKey, CDataStream& ssValue) -> bool {
                    payload = ssValue.str();
                    ssKey >> hash;
                    return false;
                });

                if (hash == *pIndex->phashBlock) {
                    tx_ok = true;
                }
                break;
            }
            pIndex = pIndex->pprev;
        }
        if (!tx_ok)
            return ERROR_FL("Tx(%d, %d) isn't found in my local storage", pos.nHeight, pos.nTxPos);
    }

    try {
        CAutoBuffer autobuff(std::move(payload));
        autobuff.seekg(pos.nTxPos);
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
