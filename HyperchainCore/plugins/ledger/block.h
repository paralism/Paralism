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
#ifndef LEDGERBLOCK_H
#define LEDGERBLOCK_H

#include "headers/inter_public.h"
#include "uint256.h"
#include "bignum.h"
#include "script.h"
#include "db.h"
#include "serialize.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "headers/inter_public.h"



#include <string>
#include <vector>
#include <memory>

#define COMMANDPREFIX "token"

static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
static const int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;
static const int64 MIN_TX_FEE = 50000;
static const int64 MIN_RELAY_TX_FEE = 10000;
static const int64 MAX_MONEY = 92200000000 * COIN; //15500000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
//HCE:
static const int COINBASE_MATURITY = 10;// 100;
/**
 * A flag that is ORed into the protocol version to designate that a transaction
 * should be (un)serialized without witness data.
 * Make sure that this does not collide with any of the values in `version.h`
 * or with `ADDRV2_FORMAT`.
 */
static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;
// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
static const int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

class CTransaction;
class CBlockIndexSimplified;
class CNode;


extern int nBestHeight;
extern unsigned char pchMessageStart[4];
extern CBlockIndex* pindexBest;
extern CCriticalSection cs_main;

extern bool IsInitialBlockDownload();
extern FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode);
extern FILE* AppendBlockFile(unsigned int& nFileRet);
extern bool CheckProofOfWork(uint256 hash, unsigned int nBits);

struct deserialize_type {};
constexpr deserialize_type deserialize{};

//HCE:
//HCE: @brief Position, height, hash of a transaction block
//HCE:
class CDiskTxPos
{
public:
    //unsigned int nFile;

    //HC: 块距离文件头的offset
    //HCE: the block offset in the file
    //unsigned int nBlockPos;

    //HC: 原表示交易所在文件距离文件头的offset，现表示交易所在账本块的偏移
    //HCE: Originally indicates the offset of tx in the file from the file header, now indicates the offset of tx of the ledger block
    unsigned int nTxPos = 0;

    //HC: 所属块高度, 辅助信息
    //HCE: The block height, auxiliary information
    uint32_t nHeightBlk = 0;

    //HC: 所属Para块Hash
    //HCE: Hash of the Para block
    uint256 hashBlk;


    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nTxPosIn, int nH, const uint256& hashb) :
        nTxPos(nTxPosIn), nHeightBlk(nH), hashBlk(hashb)
    {
    }
    CDiskTxPos(unsigned int nTxPosIn) : nTxPos(nTxPosIn) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(nTxPos);
        READWRITE(nHeightBlk);
        READWRITE(hashBlk);
    )

    void SetNull() { nTxPos = 0; nHeightBlk = 0; hashBlk = 0; }
    bool IsNull() const { return (nTxPos == 0); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nTxPos == b.nTxPos && a.hashBlk == b.hashBlk);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (IsNull())
            return strprintf("null");
        else
            return strprintf("(nTxPos=%d height=%d hashBlk=%s)", nTxPos,
                nHeightBlk,
                hashBlk.ToPreViewString().c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};

class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


struct CScriptWitness
{
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    std::vector<std::vector<unsigned char> > stack;

    // Some compilers complain without a default constructor
    CScriptWitness() {}

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    std::string ToString() const;
};

//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;


    CTxIn()
    {
        nSequence = UINT_MAX;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(), unsigned int nSequenceIn = UINT_MAX)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn = CScript(), unsigned int nSequenceIn = UINT_MAX)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout == b.prevout &&
            a.scriptSig == b.scriptSig &&
            a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        std::string str;
        str += strprintf("CTxIn(");
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0, 24).c_str());
        if (nSequence != UINT_MAX)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
class CTxOut
{
public:
    int64 nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue == b.nValue &&
            a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";

        int witnessversion;
        std::vector<unsigned char> witnessprogram;

        string format = "CTxOut(nValue=%" PRI64d ".%08" PRI64d ", scriptPubKey=%s %s)";
        string witnessdetails = " ";

        if (scriptPubKey.IsPayToScriptHash()) {
            //HCE: p2pkh, legacy tx format
            witnessdetails = "PayToScriptHash";
        }
        else if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            witnessdetails = "WitnessProgram";
            if (scriptPubKey.IsPayToWitnessScriptHash())
                witnessdetails = "PayToWitnessScriptHash";
        }
        return strprintf(format.c_str(),
            nValue / COIN, nValue % COIN, scriptPubKey.ToString().c_str(),
            witnessdetails.c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


static const int TX_VERSION_V1 = 0x1;
static const int TX_VERSION_V2 = 0x2; //HCE: start to support segregated witness 

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CTxWitness wit;
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s >> tx.nVersion;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    }
    else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s)
{
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s << tx.nVersion;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}
//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//

class CTransaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = TX_VERSION_V2;

    int nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    unsigned int nLockTime;

private:
    /** Memory only. */
    uint256 hash;
    uint256 m_witness_hash;

public:
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction& tx);
    CTransaction()
    {
        SetNull();
    }

    //CTransaction& operator=(const CTransaction &from)
    //{
    //    nVersion = from.nVersion;
    //    vin = from.vin;
    //    vout = from.vout;
    //    nLockTime = from.nLockTime;
    //    hash.copy(from.hash);
    //    //m_witness_hash = (const base_uint256)from.m_witness_hash;
    //    return *this;
    //}


    unsigned int GetSerializeSize(int nType = 0, int nVersion = CTransaction::CURRENT_VERSION) const
    {
        //CSerActionGetSerializeSize ser_action;
        //const bool fGetSize = true;
        //const bool fWrite = false;
        //const bool fRead = false;
        //unsigned int nSerSize = 0;
        //ser_streamplaceholder s;
        //s.nType = nType;
        //s.nVersion = nVersion;
        //{
        //    READWRITE(this->nVersion);
        //    nVersion = this->nVersion;
        //    READWRITE(vin);
        //    READWRITE(vout);
        //    READWRITE(nLockTime);
        //}

        unsigned int nSerSize = 0;
        CDataStream stream;
        SerializeTransaction(*this, stream);
        nSerSize = stream.size();

        return nSerSize;
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType = 0, int nVersion = CTransaction::CURRENT_VERSION) const
    {
        SerializeTransaction(*this, s);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType = 0, int nVersion = CTransaction::CURRENT_VERSION)
    {
        UnserializeTransaction(*this, s);
    }

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }


    //const uint256& GetHash() const { return hash; }
    const uint256& GetWitnessHash() const { return m_witness_hash; };

    uint256 GetHash() const
    {
        return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    }

    uint256 ComputeHash() const
    {
        return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    }

    uint256 ComputeWitnessHash() const
    {
        if (!HasWitness()) {
            return hash;
        }
        return SerializeHash(*this, SER_GETHASH, 0);
    }

    //HC:nLockTime应该理解为锁定交易的期限或者block数目，若该交易的所有输入CTxIn的nSequence字段为uint32_t的最大值（0xffffffff），则忽略该字段的逻辑检查。
    //HC:当nSequence < 0xffffffff, 且nLockTime == 0，该交易可以立即被打包
    //HC:当nSequence < 0xffffffff, 且nLockTime！ = 0时：
    //HC:若nLockTime < 500000000, 则nLockTime代表区块数，该交易只能被打包进高度大于等于nLockTime的区块；
    //HC:若nLockTime>500000000，则nLockTime代表unix时间戳，该交易只能等到当前时间大于等于nLockTime才能被打包进区块

    //HCE: nLockTime should be understood as the duration or number of blocks that lock the transaction, and
    //HCE: if all input to the CTxIn nSequence field of the transaction is the maximum value (0xffffffff) of the uint32_t, the logical check of this field is ignored

    //HCE: When nSequence < 0xffffffff and nLockTime == 0, the transaction can be packaged immediately
    //HCE: When nSequence < 0xffffffff, and nLockTime! = 0:
    //HCE: If nLockTime < 500000000, nLockTime represents the number of blocks, and the transaction can only be packed into blocks with a height greater than or equal to nLockTime;
    //HCE: If nLockTime > 500000000, nLockTime represents the unix timestamp, and the transaction can only be packed into a block until the current time is greater than or equal to nLockTime

    bool IsFinal(int nBlockHeight = 0, int64 nBlockTime = 0) const
    {
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0)
            return true;
        if (nBlockHeight == 0)
            nBlockHeight = nBestHeight;
        if (nBlockTime == 0)
            nBlockTime = GetAdjustedTime();
        if ((int64)nLockTime < (nLockTime < LOCKTIME_THRESHOLD ? (int64)nBlockHeight : nBlockTime))
            return true;
        BOOST_FOREACH(const CTxIn & txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vin.size(); i++) {
            if (vin[i].nSequence != old.vin[i].nSequence) {
                if (vin[i].nSequence <= nLowest) {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest) {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    int GetSigOpCount() const
    {
        int n = 0;
        BOOST_FOREACH(const CTxIn & txin, vin)
            n += txin.scriptSig.GetSigOpCount();
        BOOST_FOREACH(const CTxOut & txout, vout)
            n += txout.scriptPubKey.GetSigOpCount();
        return n;
    }

    bool IsStandard() const
    {
        BOOST_FOREACH(const CTxIn & txin, vin)
            if (!txin.scriptSig.IsPushOnly())
                return ERROR_FL("nonstandard txin: %s", txin.scriptSig.ToString().c_str());
        BOOST_FOREACH(const CTxOut & txout, vout)
            if (!::IsStandard(txout.scriptPubKey))
                return ERROR_FL("nonstandard txout: %s", txout.scriptPubKey.ToString().c_str());
        return true;
    }

    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        BOOST_FOREACH(const CTxOut & txout, vout)
        {
            nValueOut += txout.nValue;
            if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
        return nValueOut;
    }

    static bool AllowFree(double dPriority)
    {
        // Large (in bytes) low-priority (new, small-coin) transactions
        // need a fee.
        return dPriority > COIN * 144 / 250;
    }

    int64 GetMinFee(unsigned int nBlockSize = 1, bool fAllowFree = true, bool fForRelay = false) const
    {
        // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
        int64 nBaseFee = fForRelay ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

        unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
        unsigned int nNewBlockSize = nBlockSize + nBytes;
        int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

        if (fAllowFree) {
            if (nBlockSize == 1) {
                // Transactions under 10K are free
                // (about 4500bc if made of 50bc inputs)
                if (nBytes < 10000)
                    nMinFee = 0;
            }
            else {
                // Free transaction area
                if (nNewBlockSize < 27000)
                    nMinFee = 0;
            }
        }

        // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
        if (nMinFee < nBaseFee)
            BOOST_FOREACH(const CTxOut & txout, vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;

        // Raise the price as the block approaches full
        if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN / 2) {
            if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
                return MAX_MONEY;
            nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
        }

        if (!MoneyRange(nMinFee))
            nMinFee = MAX_MONEY;
        return nMinFee;
    }

    //bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    //{
    //    CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
    //    if (!filein)
    //        return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

    //    // Read transaction
    //    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
    //        return error("CTransaction::ReadFromDisk() : fseek failed");
    //    filein >> *this;

    //    // Return file pointer
    //    if (pfileRet)
    //    {
    //        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
    //            return error("CTransaction::ReadFromDisk() : second fseek failed");
    //        *pfileRet = filein.release();
    //    }
    //    return true;
    //}

    //HCE:

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion == b.nVersion &&
            a.vin == b.vin &&
            a.vout == b.vout &&
            a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }

    std::string ToString() const;

    void print() const
    {
        printf("%s", ToString().c_str());
    }


    bool ReadFromDisk(CDiskTxPos pos);
    bool ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB_Wrapper& txdb);
    bool ConnectInputs(CTxDB_Wrapper& txdb, std::map<uint256, std::tuple<CTxIndex, CTransaction>>& mapTestPool, CDiskTxPos posThisTx,
        CBlockIndex* pindexBlock, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee = 0);
    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs = true, bool* pfMissingInputs = NULL);
    bool AcceptToMemoryPool(bool fCheckInputs = true, bool* pfMissingInputs = NULL);
protected:
    bool AddToMemoryPoolUnchecked();
public:
    bool RemoveFromMemoryPool();
};

//HCE:
//HCE: A mutable version of CTransaction
//HCE: Variable transaction class, the content is similar to CTransaction. 
//HCE: It's just that transactions can be modified directly, and transactions propagated in the broadcast and packaged into blocks are CTransaction types
//HCE: The class is mainly used for segregated witness
//HCE:
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int32_t nVersion;
    uint32_t nLockTime;

    CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
    explicit CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}


    template <typename Stream>
    inline void Serialize(Stream& s, int nType = 0, int nVersion = VERSION) const {
        SerializeTransaction(*this, s);
    }


    template <typename Stream>
    inline void Unserialize(Stream& s, int nType = 0, int nVersion = VERSION) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const
    {
        return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    }

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};


CTransaction& MakeTransactionRef(CTransaction& tx, CMutableTransaction&& mtx);

//
// A transaction with a merkle branch linking it to the block chain
//
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable char fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock = NULL);
    int GetDepthInMainChain(int& nHeightRet) const;
    int GetDepthInMainChain() const { int nHeight; return GetDepthInMainChain(nHeight); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs = true);
    bool AcceptToMemoryPool();
};




//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos == b.pos &&
            a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
    int GetDepthInMainChain() const;
};


//HCE:
//HCE: Position of a block on the Hyperchain.
//HCE:
class BLOCKTRIPLEADDRESS
{
public:
    uint32 hid = 0;            //HCE: Hyperblock ID
    uint16 chainnum = 0;       //HCE: Subchain ID
    uint16 id = 0;             //HCE: Subblock ID
    uint256 hhash;             //HCE: Hyperblock hash

public:
    BLOCKTRIPLEADDRESS() {}

    BLOCKTRIPLEADDRESS(const T_LOCALBLOCKADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
    }
    BLOCKTRIPLEADDRESS(const BLOCKTRIPLEADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
        hhash = addr.hhash;
    }

    bool isValid() const
    {
        return hid >= uint64(0) && id > (uint16)0 && id < 10000 &&
            chainnum >(uint16)0 && chainnum < 5000 && hhash > 0;
    }

    bool operator <(const BLOCKTRIPLEADDRESS& addr) const
    {
        if (hid < addr.hid) {
            return true;
        }
        else if (hid > addr.hid) {
            return false;
        }

        if (chainnum < addr.chainnum) {
            return true;
        }
        else if (chainnum > addr.chainnum) {
            return false;
        }

        if (id < addr.id) {
            return true;
        }
        else if (id > addr.id) {
            return false;
        }
        return hhash < addr.hhash;
    }

    bool operator >=(const BLOCKTRIPLEADDRESS& addr) const
    {
        if (hid > addr.hid) {
            return true;
        }
        else if (hid < addr.hid) {
            return false;
        }

        if (chainnum > addr.chainnum) {
            return true;
        }
        else if (chainnum < addr.chainnum) {
            return false;
        }

        if (id > addr.id) {
            return true;
        }
        else if (id < addr.id) {
            return false;
        }
        return hhash >= addr.hhash;
    }

    friend bool operator==(const BLOCKTRIPLEADDRESS& a, const BLOCKTRIPLEADDRESS& b)
    {
        return a.hid == b.hid && a.chainnum == b.chainnum && a.id == b.id && a.hhash == b.hhash;
    }

    friend bool operator!=(const BLOCKTRIPLEADDRESS& a, const BLOCKTRIPLEADDRESS& b)
    {
        return !(a == b);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(hid);
        READWRITE(chainnum);
        READWRITE(id);
        READWRITE(hhash);
    )

        T_LOCALBLOCKADDRESS ToAddr() const
    {
        T_LOCALBLOCKADDRESS addr;
        addr.hid = hid;
        addr.chainnum = chainnum;
        addr.id = id;
        return addr;
    }

    string ToString() const
    {
        return strprintf("[%d,%d,%d(%s)]", hid, chainnum, id, hhash.ToPreViewString().c_str());
    }
};



//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
class CBlock
{
public:
    // header
    int nVersion;
    uint256 hashPrevBlock; //HCE: hashPrevBlock is previous HyperBlock's largest ledger subblock which is different from BitCoin.
    uint256 hashMerkleRoot;
    uint32_t nHeight = 0;

    unsigned int nTime = 0;

    uint32_t nPrevHID;              //HCE: Previous Hyperblock ID
    uint256 hashPrevHyperBlock;     //HCE: Previous Hyperblock hash

    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;


    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);


        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();
    )

    void SetNull()
    {
        nVersion = 1;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nHeight = 0;
        nTime = 0;

        nPrevHID = 0;
        hashPrevHyperBlock = 0;

        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nTime == 0);
    }

    //HCE: Check if the forward Hyperblock of the transaction is legitimate
    //HCE: @param pfrom Node which block come from.
    //HCE: @returns 0 ok,  -1 Hyperblock is different, -2 no found Hyperblock.
    int CheckHyperBlockConsistence(CNode* pfrom) const;

    void SetHyperBlockInfo();

    uint256 GetHash() const
    {
        return Hash(BEGIN(nVersion), END(hashPrevHyperBlock));
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    int GetSigOpCount() const
    {
        int n = 0;
        BOOST_FOREACH(const CTransaction & tx, vtx)
            n += tx.GetSigOpCount();
        return n;
    }


    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        BOOST_FOREACH(const CTransaction & tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
            for (int i = 0; i < nSize; i += 2) {
                int i2 = std::min(i + 1, nSize - 1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j + i]), END(vMerkleTree[j + i]),
                    BEGIN(vMerkleTree[j + i2]), END(vMerkleTree[j + i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
            int i = std::min(nIndex ^ 1, nSize - 1);
            vMerkleBranch.push_back(vMerkleTree[j + i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        BOOST_FOREACH(const uint256 & otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }

    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return ERROR_FL("CBlock::WriteToDisk() : AppendBlockFile failed");

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return ERROR_FL("CBlock::WriteToDisk() : ftell failed");
        fileout << *this;

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload() || (nBestHeight + 1) % 500 == 0) {
#ifdef __WXMSW__
            _commit(_fileno(fileout));
#else
            fsync(fileno(fileout));
#endif
        }

        return true;
    }

    //HCE:
    //bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true)
    //{
    //    SetNull();

    //    // Open history file to read
    //    CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
    //    if (!filein)
    //        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    //    if (!fReadTransactions)
    //        filein.nType |= SER_BLOCKHEADERONLY;

    //    // Read block
    //    filein >> *this;

    //    // Check the header
    //    if (!CheckProofOfWork(GetHash(), nBits))
    //        return error("CBlock::ReadFromDisk() : errors in block header");

    //    return true;
    //}

    bool ReadFromDisk(const BLOCKTRIPLEADDRESS& triaddr, bool fReadTransactions = true)
    {
        T_LOCALBLOCKADDRESS addr = triaddr.ToAddr();
        return ReadFromDisk(addr, fReadTransactions);
    }

    bool ReadFromDisk(const T_LOCALBLOCKADDRESS& addr, bool fReadTransactions = true)
    {
        SetNull();
        if (!addr.isValid()) {
            DEBUG_FL("block triple address invalid(%s)", addr.tostring().c_str());
            return false;
        }

        //HCE: Read data from chain space
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        string payload;
        if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
            DEBUG_FL("block(%s) isn't found in my local storage", addr.tostring().c_str());
            return false;
        }

        try {
            CAutoBuffer autobuff(std::move(payload));
            // Read block
            if (!fReadTransactions)
                autobuff.nType |= SER_BLOCKHEADERONLY;

            autobuff >> *this;
        }
        catch (std::ios_base::failure& e) {
            return ERROR_FL("%s", e.what());
        }

        return true;
    }

    string ToString() const
    {
        string strResult = strprintf("\n\tversion: %d\n"
            "\thash: %s\n"
            "\thashPrevBlock: %s\n"
            "\thashMerkleRoot: %s\n"
            "\tHeight: %d\n",
            "\tnTime: %u\n"
            "\tvtx: %d\n",
            nVersion,
            GetHash().ToString().c_str(),
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(), nHeight,
            nTime,
            vtx.size());

        //HCE: skip txs
        //for (int i = 0; i < vtx.size(); i++) {
        //    strResult += "\t";
        //    strResult += vtx[i].ToString();
        //}
        strResult += "\tvMerkleTree: ";
        for (int i = 0; i < vMerkleTree.size(); i++)
            strResult += vMerkleTree[i].ToString().substr(0, 10);

        strResult += "\n";

        return strResult;
    }
    void print() const
    {
        printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, Height=%d, nTime=%u, vtx=%d)\n",
            GetHash().ToString().substr(0, 20).c_str(),
            nVersion,
            hashPrevBlock.ToString().substr(0, 20).c_str(),
            hashMerkleRoot.ToString().substr(0, 10).c_str(),
            nHeight,
            nTime, vtx.size());
        for (int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0, 10).c_str());
        printf("\n");
    }

    bool DisconnectBlock(CTxDB_Wrapper& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB_Wrapper& txdb, CBlockIndex* pindex);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions = true);
    bool ReadFromDisk(const CBlockIndexSimplified* pindex);
    bool SetBestChain(CTxDB_Wrapper& txdb, CBlockIndex* pindexNew);


    //HCE:
    //bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
    //bool AddToBlockIndex(const T_LOCALBLOCKADDRESS& addr);
    bool UpdateToBlockIndex(CBlockIndex* pIndex, const BLOCKTRIPLEADDRESS& blktriaddr);
    bool AddToBlockIndex(const BLOCKTRIPLEADDRESS& addr);
    bool CheckBlock() const;

    bool AcceptBlock();

    bool AddToMemoryPool();
    bool AddToMemoryPool(const uint256& nBlockHash);
    bool RemoveFromMemoryPool();
    bool ReadFromMemoryPool(uint256 nBlockHash);

    bool CheckTrans();

    bool UpdateToBlockIndex(const BLOCKTRIPLEADDRESS& blktriaddr);

private:
    bool NewBlockFromString(const CBlockIndex* pindex, string&& payload);

};

//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//

class CBlockIndex
{
public:
    //HC: 块hash指针，节约空间，more see CBlock::AddToBlockIndex
    //HCE: Block hash pointers to save space, more see CBlock::AddToBlockIndex
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;

    //HC: unused (To bitcoin:存储本区块的数据的文件，比如第100个区块，其区块文件存储在blk100.data中)
    //HCE: unused (To bitcoin: The file that stores the data of this block, such as block 100, whose block file is stored in blk100.data)
    //unsigned int nFile;     
    //unsigned int nBlockPos; //HCE: unused

    //HC: 子块逻辑地址, 带所在超块hash， Add in VERSION >= 50000
    //HCE: The logical address of the subblock, with the hash of the Hyperblock, Add in VERSION >= 50000
    BLOCKTRIPLEADDRESS triaddr; //HCE: 子块逻辑地址

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    uint32_t nHeight;
    unsigned int nTime;

    uint32 nPrevHID = 0;
    uint256 hashPrevHyperBlock = 0;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;

        nVersion = 0;
        hashMerkleRoot = 0;
        nHeight = 0;
        nTime = 0;
    }


    CBlockIndex(const BLOCKTRIPLEADDRESS& addrIn, const CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        triaddr = addrIn;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nHeight = block.nHeight;
        nTime = block.nTime;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nHeight = block.nHeight;
        nTime = block.nTime;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
    }

    //HC: 该区块的高度，从创世区块0开始算起
    //HCE: The height of the block is calculated from genesis block 0
    inline int64 Height() const {
        return nHeight;
    };                             

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight = nHeight;
        block.nTime = nTime;
        block.nPrevHID = nPrevHID;
        block.hashPrevHyperBlock = hashPrevHyperBlock;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    bool CheckIndex() const
    {
        return true;
    }

    enum { nMedianTimeSpan = 11 };

    int64 GetMedianTimePast() const
    {
        int64 pmedian[nMedianTimeSpan];
        int64* pbegin = &pmedian[nMedianTimeSpan];
        int64* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin) / 2];
    }

    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan / 2; i++)
        {
            if (!pindex->pnext)
                return GetBlockTime();
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex: \n"
            "\tmyself=%08x"
            "\tnprev=%08x"
            "\tpnext=%08x\n"
            "\tnHeight=%u"
            "\tnTime=%d\n"
            "\tnPrevHID=%d\n"
            "\thashPrevH=%s\n"
            "\taddr=%s\n"
            "\tmerkle=%s\n"
            "\thashBlock=%s\n", this,
            pprev, pnext, Height(), nTime, nPrevHID,
            hashPrevHyperBlock.ToPreViewString().c_str(),
            triaddr.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }

    void print() const
    {
        DEBUG_FL("%s\n", ToString().c_str());
    }

    bool operator<(const CBlockIndex& st) const
    {
        return (triaddr < st.triaddr);
    }
    bool operator>=(const CBlockIndex& st) const
    {
        return (triaddr >= st.triaddr);
    }
};

//
// Used to marshal pointers into hashes for db storage.
//
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    uint256 hashNext;


    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;

    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(triaddr);
        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nHeight);
        READWRITE(nTime);

        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);

    )

        uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight = nHeight;
        block.nTime = nTime;
        block.nPrevHID = nPrevHID;
        block.hashPrevHyperBlock = hashPrevHyperBlock;

        return block.GetHash();
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0, 20).c_str(),
            hashNext.ToString().substr(0, 20).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

using CBlockSP = std::shared_ptr<CBlock>;

/**
 * A UTXO entry.
 *
 * Serialized format:
 * - VARINT((coinbase ? 1 : 0) | (height << 1))
 * - the non-spent CTxOut (via TxOutCompression)
 */
class Coin
{
public:
    //! unspent transaction output
    CTxOut out;

    //! whether containing transaction was a coinbase
    unsigned int fCoinBase : 1;

    //! at which height this containing transaction was included in the active block chain
    uint32_t nHeight : 31;

    //! construct a Coin from a CTxOut and height/coinbase information.
    Coin(CTxOut&& outIn, int nHeightIn, bool fCoinBaseIn) : out(std::move(outIn)), fCoinBase(fCoinBaseIn), nHeight(nHeightIn) {}
    Coin(const CTxOut& outIn, int nHeightIn, bool fCoinBaseIn) : out(outIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn) {}

    void Clear()
    {
        out.SetNull();
        fCoinBase = false;
        nHeight = 0;
    }

    //! empty constructor
    Coin() : fCoinBase(false), nHeight(0) {}

    bool IsCoinBase() const
    {
        return fCoinBase;
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        assert(!IsSpent());

        CSerActionSerialize ser_action;
        const bool fGetSize = false;
        const bool fWrite = true;
        const bool fRead = false;
        unsigned int nSerSize = 0;
        int nType = 0;
        int nVersion = 0;

        uint32_t code = nHeight * uint32_t{ 2 } + fCoinBase;
        //::Serialize(s, VARINT(code));
        READWRITE(code);
        //::Serialize(s, Using<TxOutCompression>(out));
        //HCE: not compression
        READWRITE(out);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        CSerActionSerialize ser_action;
        const bool fGetSize = false;
        const bool fWrite = false;
        const bool fRead = true;
        unsigned int nSerSize = 0;
        int nType = 0;
        int nVersion = 0;


        uint32_t code = 0;
        //::Unserialize(s, VARINT(code));
        READWRITE(code);
        nHeight = code >> 1;
        fCoinBase = code & 1;
        //::Unserialize(s, Using<TxOutCompression>(out));
        READWRITE(out);
    }

    bool IsSpent() const
    {
        return out.IsNull();
    }

    //size_t DynamicMemoryUsage() const
    //{
    //    return memusage::DynamicUsage(out.scriptPubKey);
    //}
};

#endif
