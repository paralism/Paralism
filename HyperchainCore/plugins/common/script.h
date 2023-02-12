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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef H_BITCOIN_SCRIPT
#define H_BITCOIN_SCRIPT

#include "base58.h"
#include "keystore.h"

#include "span.h"
#include "script_error.h"
#include "pubkey.h"
#include "signingprovider.h"


#include <string>
#include <vector>

#include <boost/foreach.hpp>

class CTransaction;
class CMutableTransaction;
class CTxOut;
class CScriptNum;
struct CScriptWitness;
class SigningProvider;

/** Signature hash sizes */
static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;
static constexpr size_t WITNESS_V1_TAPROOT_SIZE = 32;


// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT = 201;

// Maximum number of public keys per multisig
static const int MAX_PUBKEYS_PER_MULTISIG = 20;

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 10000;

// Maximum number of values on script interpreter stack
static const int MAX_STACK_SIZE = 1000;



template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{
    return std::vector<unsigned char>(in.begin(), in.end());
}

// Maximum number of bytes pushable to the stack
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,

    SIGHASH_DEFAULT = 0, //!< Taproot only; implied when sighash byte is missing, and equivalent to SIGHASH_ALL
    SIGHASH_OUTPUT_MASK = 3,
    SIGHASH_INPUT_MASK = 0x80,
};


enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD = 0xba,

    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,


    OP_INVALIDOPCODE = 0xff,
};






inline const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";



    // template matching params
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";
    case OP_PUBKEY                 : return "OP_PUBKEY";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default:
        return "OP_UNKNOWN";
    }
};




inline std::string ValueString(const std::vector<unsigned char>& vch)
{
    if (vch.size() <= 4)
        return strprintf("%d", CBigNum(vch).getint());
    else
        return HexStr(vch);
}

inline std::string StackString(const std::vector<std::vector<unsigned char> >& vStack)
{
    std::string str;
    BOOST_FOREACH(const std::vector<unsigned char>& vch, vStack)
    {
        if (!str.empty())
            str += " ";
        str += ValueString(vch);
    }
    return str;
}









class CScript : public std::vector<unsigned char>
{
protected:
    CScript& push_int64(int64 n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

    CScript& push_uint64(uint64 n)
    {
        if (n >= 1 && n <= 16)
        {
            push_back(n + (OP_1 - 1));
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

public:
    CScript() { }
    CScript(const CScript& b) : std::vector<unsigned char>(b.begin(), b.end()) { }
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<unsigned char>(pbegin, pend) { }
#ifndef _MSC_VER
    CScript(const unsigned char* pbegin, const unsigned char* pend) : std::vector<unsigned char>(pbegin, pend) { }
#endif

    CScript& operator+=(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)
    {
        CScript ret = a;
        ret += b;
        return ret;
    }


    explicit CScript(char b)           { operator<<(b); }
    explicit CScript(short b)          { operator<<(b); }
    explicit CScript(int b)            { operator<<(b); }
    explicit CScript(long b)           { operator<<(b); }
    //explicit CScript(int64 b)          { operator<<(b); }
    explicit CScript(unsigned char b)  { operator<<(b); }
    explicit CScript(unsigned int b)   { operator<<(b); }
    explicit CScript(unsigned short b) { operator<<(b); }
    explicit CScript(unsigned long b)  { operator<<(b); }
    //explicit CScript(uint64 b)         { operator<<(b); }

    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const uint256& b) { operator<<(b); }
    explicit CScript(const CBigNum& b) { operator<<(b); }
    explicit CScript(const std::vector<unsigned char>& b) { operator<<(b); }


    CScript& operator<<(char b)           { return push_int64(b); }
    CScript& operator<<(short b)          { return push_int64(b); }
    CScript& operator<<(int b)            { return push_int64(b); }
    CScript& operator<<(long b)           { return push_int64(b); }
    //CScript& operator<<(int64 b)          { return push_int64(b); }
    CScript& operator<<(unsigned char b)  { return push_uint64(b); }
    CScript& operator<<(unsigned int b)   { return push_uint64(b); }
    CScript& operator<<(unsigned short b) { return push_uint64(b); }
    CScript& operator<<(unsigned long b)  { return push_uint64(b); }
    //CScript& operator<<(uint64 b)         { return push_uint64(b); }

    CScript& operator<<(opcodetype opcode)
    {
        if (opcode < 0 || opcode > 0xff)
            throw std::runtime_error("CScript::operator<<() : invalid opcode");
        insert(end(), (unsigned char)opcode);
        return *this;
    }

    CScript& operator<<(const uint160& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return *this;
    }

    CScript& operator<<(const uint256& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return *this;
    }

    CScript& operator<<(const CBigNum& b)
    {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(const std::vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= 0xff)
        {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= 0xffff)
        {
            insert(end(), OP_PUSHDATA2);
            unsigned short nSize = b.size();
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));
        }
        else
        {
            insert(end(), OP_PUSHDATA4);
            unsigned int nSize = b.size();
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    CScript& operator<<(const CScript& b)
    {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        assert(!"warning: pushing a CScript onto a CScript with << is probably not intended, use + to concatenate");
        return *this;
    }

    /**
    * Returns whether the script is guaranteed to fail at execution,
    * regardless of the initial stack. This allows outputs to be pruned
    * instantly when entering the UTXO set.
    */
    bool IsUnspendable() const
    {
        return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet)
    {
         // Wrapper so it can be called with either iterator or const_iterator
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, &vchRet);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet)
    {
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, NULL);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    {
        return GetOp2(pc, opcodeRet, NULL);
    }

    bool GetOp2(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;
        if (pvchRet)
            pvchRet->clear();
        if (pc >= end())
            return false;

        // Read instruction
        if (end() - pc < 1)
            return false;
        unsigned int opcode = *pc++;

        // Immediate operand
        if (opcode <= OP_PUSHDATA4)
        {
            unsigned int nSize;
            if (opcode < OP_PUSHDATA1)
            {
                nSize = opcode;
            }
            else if (opcode == OP_PUSHDATA1)
            {
                if (end() - pc < 1)
                    return false;
                nSize = *pc++;
            }
            else if (opcode == OP_PUSHDATA2)
            {
                if (end() - pc < 2)
                    return false;
                nSize = 0;
                memcpy(&nSize, &pc[0], 2);
                pc += 2;
            }
            else if (opcode == OP_PUSHDATA4)
            {
                if (end() - pc < 4)
                    return false;
                memcpy(&nSize, &pc[0], 4);
                pc += 4;
            }
            if (end() - pc < nSize)
                return false;
            if (pvchRet)
                pvchRet->assign(pc, pc + nSize);
            pc += nSize;
        }

        opcodeRet = (opcodetype)opcode;
        return true;
    }


    void FindAndDelete(const CScript& b)
    {
        if (b.empty())
            return;
        iterator pc = begin();
        opcodetype opcode;
        do
        {
            while (end() - pc >= b.size() && memcmp(&pc[0], &b[0], b.size()) == 0)
                erase(pc, pc + b.size());
        }
        while (GetOp(pc, opcode));
    }


    int GetSigOpCount() const
    {
        int n = 0;
        const_iterator pc = begin();
        while (pc < end())
        {
            opcodetype opcode;
            if (!GetOp(pc, opcode))
                break;
            if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
                n++;
            else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
                n += 20;
        }
        return n;
    }

    //HCE: see latest Bitcoin source code
    bool IsPushOnly(const_iterator pc) const
    {
        while (pc < end())
        {
            opcodetype opcode;
            if (!GetOp(pc, opcode))
                return false;
            // Note that IsPushOnly() *does* consider OP_RESERVED to be a
            // push-type opcode, however execution of OP_RESERVED fails, so
            // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
            // the P2SH special validation code being executed.
            if (opcode > OP_16)
                return false;
        }
        return true;
    }

    bool IsPushOnly() const
    {
        if (size() > 200)
            return false;
        return IsPushOnly(begin());
    }


    CBitcoinAddress GetBitcoinAddress() const
    {
        opcodetype opcode;
        std::vector<unsigned char> vch;
        CScript::const_iterator pc = begin();
        if (!GetOp(pc, opcode, vch) || opcode != OP_DUP) return 0;
        if (!GetOp(pc, opcode, vch) || opcode != OP_HASH160) return 0;
        if (!GetOp(pc, opcode, vch) || vch.size() != sizeof(uint160)) return 0;
        uint160 hash160 = uint160(vch);
        if (!GetOp(pc, opcode, vch) || opcode != OP_EQUALVERIFY) return 0;
        if (!GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG) return 0;
        if (pc != end()) return 0;
        return CBitcoinAddress(hash160);
    }

    void SetBitcoinAddress(const CBitcoinAddress& address)
    {
        this->clear();
        *this << OP_DUP << OP_HASH160 << address.GetHash160() << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    void SetBitcoinAddress(const std::vector<unsigned char>& vchPubKey)
    {
        SetBitcoinAddress(CBitcoinAddress(vchPubKey));
    }


    void PrintHex() const
    {
        printf("CScript(%s)\n", HexStr(begin(), end(), true).c_str());
    }

    std::string ToString() const
    {
        std::string str;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        const_iterator pc = begin();
        while (pc < end())
        {
            if (!str.empty())
                str += " ";
            if (!GetOp(pc, opcode, vch))
            {
                str += "[error]";
                return str;
            }
            if (0 <= opcode && opcode <= OP_PUSHDATA4)
                str += ValueString(vch);
            else
                str += GetOpName(opcode);
        }
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N(opcodetype opcode)
    {
        if (opcode == OP_0)
            return 0;
        assert(opcode >= OP_1 && opcode <= OP_16);
        return (int)opcode - (int)(OP_1 - 1);
    }

    static opcodetype EncodeOP_N(int n)
    {
        assert(n >= 0 && n <= 16);
        if (n == 0)
            return OP_0;
        return (opcodetype)(OP_1 + n - 1);
    }

    bool IsPayToScriptHash() const
    {
        // Extra-fast test for pay-to-script-hash CScripts:
        return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
    }

    bool IsPayToWitnessScriptHash() const
    {
        // Extra-fast test for pay-to-witness-script-hash CScripts:
        return (this->size() == 34 &&
            (*this)[0] == OP_0 &&
            (*this)[1] == 0x20);
    }

    // A witness program is any valid CScript that consists of a 1-byte push opcode
    // followed by a data push between 2 and 40 bytes.
    bool IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
    {
        if (this->size() < 4 || this->size() > 42) {
            return false;
        }
        if ((*this)[0] != OP_0 && ((*this)[0] < OP_1 || (*this)[0] > OP_16)) {
            return false;
        }
        if ((size_t)((*this)[1] + 2) == this->size()) {
            version = DecodeOP_N((opcodetype)(*this)[0]);
            program = std::vector<unsigned char>(this->begin() + 2, this->end());
            return true;
        }
        return false;
    }
};


struct PrecomputedTransactionData
{
    // BIP341 precomputed data.
    // These are single-SHA256, see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-15.
    uint256 m_prevouts_single_hash;
    uint256 m_sequences_single_hash;
    uint256 m_outputs_single_hash;
    uint256 m_spent_amounts_single_hash;
    uint256 m_spent_scripts_single_hash;
    //! Whether the 5 fields above are initialized.
    bool m_bip341_taproot_ready = false;

    // BIP143 precomputed data (double-SHA256).
    uint256 hashPrevouts, hashSequence, hashOutputs;
    //! Whether the 3 fields above are initialized.
    bool m_bip143_segwit_ready = false;

    std::vector<CTxOut> m_spent_outputs;
    //! Whether m_spent_outputs is initialized.
    bool m_spent_outputs_ready = false;

    PrecomputedTransactionData() = default;

    template <class T>
    void Init(const T& tx, std::vector<CTxOut>&& spent_outputs);

    template <class T>
    explicit PrecomputedTransactionData(const T& tx);
};


enum class SigVersion
{
    BASE = 0,        //!< Bare scripts and BIP16 P2SH-wrapped redeemscripts
    WITNESS_V0 = 1,  //!< Witness v0 (P2WPKH and P2WSH); see BIP 141
    TAPROOT = 2,     //!< Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, key path spending; see BIP 341
    TAPSCRIPT = 3,   //!< Witness v1 with 32-byte program, not BIP16 P2SH-wrapped, script path spending, leaf version 0xc0; see BIP 342
};

struct ScriptExecutionData
{
    //! Whether m_tapleaf_hash is initialized.
    bool m_tapleaf_hash_init = false;
    //! The tapleaf hash.
    uint256 m_tapleaf_hash;

    //! Whether m_codeseparator_pos is initialized.
    bool m_codeseparator_pos_init = false;
    //! Opcode position of the last executed OP_CODESEPARATOR (or 0xFFFFFFFF if none executed).
    uint32_t m_codeseparator_pos;

    //! Whether m_annex_present and (when needed) m_annex_hash are initialized.
    bool m_annex_init = false;
    //! Whether an annex is present.
    bool m_annex_present;
    //! Hash of the annex data.
    uint256 m_annex_hash;

    //! Whether m_validation_weight_left is initialized.
    bool m_validation_weight_left_init = false;
    //! How much validation weight is left (decremented for every successful non-empty signature check).
    int64_t m_validation_weight_left;
};

typedef int64_t CAmount;

class BaseSignatureChecker
{
public:
    virtual bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return false;
    }

    virtual bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, const ScriptExecutionData& execdata, ScriptError* serror = nullptr) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
        return false;
    }

    virtual bool CheckSequence(const CScriptNum& nSequence) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const T* txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;

protected:
    virtual bool VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
    virtual bool VerifySchnorrSignature(Span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const;

public:
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}
    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, const ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
};

using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* error = nullptr);
bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags);

int FindAndDelete(CScript& script, const CScript& b);

class scriptnum_error : public std::runtime_error
{
public:
    explicit scriptnum_error(const std::string& str) : std::runtime_error(str) {}
};


class CScriptNum
{
    /**
     * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
     * The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
     * but results may overflow (and are valid as long as they are not used in a subsequent
     * numeric operation). CScriptNum enforces those semantics by storing results as
     * an int64 and allowing out-of-range values to be returned as a vector of bytes but
     * throwing an exception if arithmetic is done or the result is interpreted as an integer.
     */
public:

    explicit CScriptNum(const int64_t& n)
    {
        m_value = n;
    }

    static const size_t nDefaultMaxNumSize = 4;

    explicit CScriptNum(const std::vector<unsigned char>& vch, bool fRequireMinimal,
        const size_t nMaxNumSize = nDefaultMaxNumSize)
    {
        if (vch.size() > nMaxNumSize) {
            throw scriptnum_error("script number overflow");
        }
        if (fRequireMinimal && vch.size() > 0) {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if ((vch.back() & 0x7f) == 0) {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if (vch.size() <= 1 || (vch[vch.size() - 2] & 0x80) == 0) {
                    throw scriptnum_error("non-minimally encoded script number");
                }
            }
        }
        m_value = set_vch(vch);
    }

    inline bool operator==(const int64_t& rhs) const { return m_value == rhs; }
    inline bool operator!=(const int64_t& rhs) const { return m_value != rhs; }
    inline bool operator<=(const int64_t& rhs) const { return m_value <= rhs; }
    inline bool operator< (const int64_t& rhs) const { return m_value < rhs; }
    inline bool operator>=(const int64_t& rhs) const { return m_value >= rhs; }
    inline bool operator> (const int64_t& rhs) const { return m_value > rhs; }

    inline bool operator==(const CScriptNum& rhs) const { return operator==(rhs.m_value); }
    inline bool operator!=(const CScriptNum& rhs) const { return operator!=(rhs.m_value); }
    inline bool operator<=(const CScriptNum& rhs) const { return operator<=(rhs.m_value); }
    inline bool operator< (const CScriptNum& rhs) const { return operator< (rhs.m_value); }
    inline bool operator>=(const CScriptNum& rhs) const { return operator>=(rhs.m_value); }
    inline bool operator> (const CScriptNum& rhs) const { return operator> (rhs.m_value); }

    inline CScriptNum operator+(const int64_t& rhs)    const { return CScriptNum(m_value + rhs); }
    inline CScriptNum operator-(const int64_t& rhs)    const { return CScriptNum(m_value - rhs); }
    inline CScriptNum operator+(const CScriptNum& rhs) const { return operator+(rhs.m_value); }
    inline CScriptNum operator-(const CScriptNum& rhs) const { return operator-(rhs.m_value); }

    inline CScriptNum& operator+=(const CScriptNum& rhs) { return operator+=(rhs.m_value); }
    inline CScriptNum& operator-=(const CScriptNum& rhs) { return operator-=(rhs.m_value); }

    inline CScriptNum operator&(const int64_t& rhs)    const { return CScriptNum(m_value & rhs); }
    inline CScriptNum operator&(const CScriptNum& rhs) const { return operator&(rhs.m_value); }

    inline CScriptNum& operator&=(const CScriptNum& rhs) { return operator&=(rhs.m_value); }

    inline CScriptNum operator-()                         const
    {
        assert(m_value != std::numeric_limits<int64_t>::min());
        return CScriptNum(-m_value);
    }

    inline CScriptNum& operator=(const int64_t& rhs)
    {
        m_value = rhs;
        return *this;
    }

    inline CScriptNum& operator+=(const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value <= std::numeric_limits<int64_t>::max() - rhs) ||
            (rhs < 0 && m_value >= std::numeric_limits<int64_t>::min() - rhs));
        m_value += rhs;
        return *this;
    }

    inline CScriptNum& operator-=(const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value >= std::numeric_limits<int64_t>::min() + rhs) ||
            (rhs < 0 && m_value <= std::numeric_limits<int64_t>::max() + rhs));
        m_value -= rhs;
        return *this;
    }

    inline CScriptNum& operator&=(const int64_t& rhs)
    {
        m_value &= rhs;
        return *this;
    }

    int getint() const
    {
        if (m_value > std::numeric_limits<int>::max())
            return std::numeric_limits<int>::max();
        else if (m_value < std::numeric_limits<int>::min())
            return std::numeric_limits<int>::min();
        return m_value;
    }

    std::vector<unsigned char> getvch() const
    {
        return serialize(m_value);
    }

    static std::vector<unsigned char> serialize(const int64_t& value)
    {
        if (value == 0)
            return std::vector<unsigned char>();

        std::vector<unsigned char> result;
        const bool neg = value < 0;
        uint64_t absvalue = neg ? ~static_cast<uint64_t>(value) + 1 : static_cast<uint64_t>(value);

        while (absvalue)         {
            result.push_back(absvalue & 0xff);
            absvalue >>= 8;
        }

        //    - If the most significant byte is >= 0x80 and the value is positive, push a
        //    new zero-byte to make the significant byte < 0x80 again.

        //    - If the most significant byte is >= 0x80 and the value is negative, push a
        //    new 0x80 byte that will be popped off when converting to an integral.

        //    - If the most significant byte is < 0x80 and the value is negative, add
        //    0x80 to it, since it will be subtracted and interpreted as a negative when
        //    converting to an integral.

        if (result.back() & 0x80)
            result.push_back(neg ? 0x80 : 0);
        else if (neg)
            result.back() |= 0x80;

        return result;
    }

private:
    static int64_t set_vch(const std::vector<unsigned char>& vch)
    {
        if (vch.empty())
            return 0;

        int64_t result = 0;
        for (size_t i = 0; i != vch.size(); ++i)
            result |= static_cast<int64_t>(vch[i]) << 8 * i;

        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if (vch.back() & 0x80)
            return -((int64_t)(result & ~(0x80ULL << (8 * (vch.size() - 1)))));

        return result;
    }

    int64_t m_value;
};


bool IsStandard(const CScript& scriptPubKey);
bool IsMine(const CKeyStore& keystore, const CScript& scriptPubKey);
bool ExtractAddress(const CScript& scriptPubKey, const CKeyStore* pkeystore, CBitcoinAddress& addressRet);
bool ExtractAddress(const CScript& scriptPubKey, std::vector<unsigned char>& vchPubKey);
bool SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, CScript scriptPrereq=CScript());
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType=0);



//////////////////////////////////////////////////////////////////////////

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr);


/** Interface for signature creators. */
class BaseSignatureCreator
{
public:
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const = 0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const = 0;
};


bool IsSolvable(const SigningProvider& provider, const CScript& script);

std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode = false);

#endif
