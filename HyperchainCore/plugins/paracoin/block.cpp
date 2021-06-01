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


bool CBlock::AddToMemoryPool(const uint256 &nBlockHash)
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

CBlockIndexSP CBlockIndex::pprev() const
{
    return mapBlockIndex[hashPrev];
}

CBlockIndexSP CBlockIndex::pnext() const
{
    return mapBlockIndex[hashNext];
}

int64 CBlockIndex::GetMedianTimePast() const
{
    int64 pmedian[nMedianTimeSpan];
    int64* pbegin = &pmedian[nMedianTimeSpan];
    int64* pend = &pmedian[nMedianTimeSpan];

    auto pindex = shared_from_this();
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev())
        *(--pbegin) = pindex->GetBlockTime();

    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin) / 2];
}

int64 CBlockIndex::GetMedianTime() const
{
    auto pindex = shared_from_this();
    for (int i = 0; i < nMedianTimeSpan / 2; i++) {
        auto sp = pindex->pnext();
        if (!sp)
            return GetBlockTime();
        pindex = sp;
    }
    return pindex->GetMedianTimePast();
}

bool CBlockIndex::IsInMainChain() const
{
    return (pnext() || this == pindexBest.get());
}

//////////////////////////////////////////////////////////////////////////
CBlockBloomFilter::CBlockBloomFilter() : _filter()
{
}


//////////////////////////////////////////////////////////////////////////
//CBlockCacheLocator

void CBlockCacheLocator::setFilterReadCompleted()
{
    _filterCacheReadReady = true;
}

bool CBlockCacheLocator::contain(const uint256& hashBlock)
{
    if (!_filterReady) {
        if (_filterCacheReadReady) {

            _filterBlock = _filterBlock | blk_bf_future.get();
            _filterReady = true;
            cout << "Paracoin: read block cache completely\n";
        }
    }

    if (_filterReady && !_filterBlock.contain(hashBlock))
        return false;

    if (_mapBlock.count(hashBlock)) {
        return true;
    }


    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (blockdb.ReadBlock(hashBlock, blk)) {
        return true;
    }
    return false;
}

bool CBlockCacheLocator::insert(const uint256& hashBlock, const CBlock& blk)
{
    CBlockDB_Wrapper blockdb;
    blockdb.TxnBegin();
    blockdb.WriteBlock(hashBlock, blk);
    if (!blockdb.TxnCommit())
        return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;

    insert(hashBlock);
    return true;
}

void CBlockCacheLocator::clear()
{
    _filterBlock.clear();
    _mapBlock.clear();
    _mapTmJoined.clear();
}


bool CBlockCacheLocator::erase(const uint256& hashBlock)
{
    return true;

    //CBlockDB_Wrapper blockdb;
    //blockdb.TxnBegin();
    //blockdb.EraseBlock(hashBlock);
    //if (!blockdb.TxnCommit())
    //    return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    //_mapBlock.erase(hashBlock);
    //std::remove_if(_mapTmJoined.begin(), _mapTmJoined.end(), [&hashBlock](const auto& x) { return x.second == hashBlock; });

    //return true;
}

const CBlock& CBlockCacheLocator::operator[](const uint256& hashBlock)
{
    if (_mapBlock.count(hashBlock)) {
        return _mapBlock[hashBlock];
    }

    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (!blockdb.ReadBlock(hashBlock, blk)) {
        throw runtime_error(strprintf("Failed to Read block: %s", hashBlock.ToPreViewString().c_str()));
    }

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;
    return _mapBlock[hashBlock];
}

