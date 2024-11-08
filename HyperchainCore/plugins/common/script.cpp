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
#include "headers.h"

#include "crypto/sha1.h"

#include "key_secp256k1.h"
#include "script.h"
#include "serialize.h"
#include "keyorigin.h"
#include "signingprovider.h"
#include "AppPlugins.h"
#include "sysexceptions.h"

using namespace std;
using namespace boost;

bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

const uint256 uint256::ZERO(0);
const uint256 uint256::ONE(1);


typedef vector<unsigned char> valtype;
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);
static const size_t nMaxNumSize = 4;


namespace {

    inline bool set_success(ScriptError* ret)
    {
        if (ret)
            *ret = SCRIPT_ERR_OK;
        return true;
    }

    inline bool set_error(ScriptError* ret, const ScriptError serror)
    {
        if (ret)
            *ret = serror;
        return false;
    }

} // namespace

CBigNum CastToBigNum(const valtype& vch)
{
    if (vch.size() > nMaxNumSize)
        throw runtime_error("CastToBigNum() : overflow");
    // Get rid of extra leading zeros
    return CBigNum(CBigNum(vch).getvch());
}

bool CastToBool(const valtype& vch)
{
    for (int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

void MakeSameSize(valtype& vch1, valtype& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        vch2.resize(vch1.size(), 0);
}



//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack() : stack empty");
    stack.pop_back();
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    // Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert(0 <= opcode && opcode <= OP_PUSHDATA4);
    if (data.size() == 0) {
        // Should have used OP_0.
        return opcode == OP_0;
    }
    else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Should have used OP_1 .. OP_16.
        return false;
    }
    else if (data.size() == 1 && data[0] == 0x81) {
        // Should have used OP_1NEGATE.
        return false;
    }
    else if (data.size() <= 75) {
        // Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    }
    else if (data.size() <= 255) {
        // Must have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    }
    else if (data.size() <= 65535) {
        // Must have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}


int FindAndDelete(CScript& script, const CScript& b)
{
    int nFound = 0;
    if (b.empty())
        return nFound;
    CScript result;
    CScript::const_iterator pc = script.begin(), pc2 = script.begin(), end = script.end();
    opcodetype opcode;
    do {
        result.insert(result.end(), pc2, pc);
        while (static_cast<size_t>(end - pc) >= b.size() && std::equal(b.begin(), b.end(), pc)) {
            pc = pc + b.size();
            ++nFound;
        }
        pc2 = pc;
    } while (script.GetOp(pc, opcode));

    if (nFound > 0) {
        result.insert(result.end(), pc2, end);
        script = std::move(result);
    }

    return nFound;
}

namespace {
    /** A data type to abstract out the condition stack during script execution.
     *
     * Conceptually it acts like a vector of booleans, one for each level of nested
     * IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
     * each.
     *
     * The elements on the stack cannot be observed individually; we only need to
     * expose whether the stack is empty and whether or not any false values are
     * present at all. To implement OP_ELSE, a toggle_top modifier is added, which
     * flips the last value without returning it.
     *
     * This uses an optimized implementation that does not materialize the
     * actual stack. Instead, it just stores the size of the would-be stack,
     * and the position of the first false value in it.
     */
    class ConditionStack {
    private:
        //! A constant for m_first_false_pos to indicate there are no falses.
        static constexpr uint32_t NO_FALSE = std::numeric_limits<uint32_t>::max();

        //! The size of the implied stack.
        uint32_t m_stack_size = 0;
        //! The position of the first false value on the implied stack, or NO_FALSE if all true.
        uint32_t m_first_false_pos = NO_FALSE;

    public:
        bool empty() { return m_stack_size == 0; }
        bool all_true() { return m_first_false_pos == NO_FALSE; }
        void push_back(bool f)
        {
            if (m_first_false_pos == NO_FALSE && !f) {
                // The stack consists of all true values, and a false is added.
                // The first false value will appear at the current size.
                m_first_false_pos = m_stack_size;
            }
            ++m_stack_size;
        }
        void pop_back()
        {
            assert(m_stack_size > 0);
            --m_stack_size;
            if (m_first_false_pos == m_stack_size) {
                // When popping off the first false value, everything becomes true.
                m_first_false_pos = NO_FALSE;
            }
        }
        void toggle_top()
        {
            assert(m_stack_size > 0);
            if (m_first_false_pos == NO_FALSE) {
                // The current stack is all true values; the first false will be the top.
                m_first_false_pos = m_stack_size - 1;
            }
            else if (m_first_false_pos == m_stack_size - 1) {
                // The top is the first false value; toggling it will make everything true.
                m_first_false_pos = NO_FALSE;
            }
            else {
                // There is a false value, but not on top. No action is needed as toggling
                // anything but the first false value is unobservable.
            }
        }
    };
}

bool static IsCompressedOrUncompressedPubKey(const valtype& vchPubKey)
{
    if (vchPubKey.size() < CPubKey::COMPRESSED_SIZE) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != CPubKey::SIZE) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    }
    else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != CPubKey::COMPRESSED_SIZE) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    }
    else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

bool static IsCompressedPubKey(const valtype& vchPubKey)
{
    if (vchPubKey.size() != CPubKey::COMPRESSED_SIZE) {
        //  Non-canonical public key: invalid length for compressed key
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03) {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char>& sig)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integer (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype& vchSig, ScriptError* serror)
{
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    // https://bitcoin.stackexchange.com/a/12556:
    //     Also note that inside transaction signatures, an extra hashtype byte
    //     follows the actual signature data.
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    // If the S value is above the order of the curve divided by two, its
    // complement modulo the order could have been used instead, which is
    // one byte shorter when encoded correctly.
    if (!CPubKey::CheckLowS(vchSigCopy)) {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype& vchSig)
{
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const std::vector<unsigned char>& vchSig, unsigned int flags, ScriptError* serror)
{
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    }
    else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckPubKeyEncoding(const valtype& vchPubKey, unsigned int flags, const SigVersion& sigversion, ScriptError* serror)
{
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    // Only compressed keys are accepted in segwit
    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigversion == SigVersion::WITNESS_V0 && !IsCompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    return true;
}

static bool EvalChecksigPreTapscript(const valtype& vchSig, const valtype& vchPubKey, CScript::const_iterator pbegincodehash, CScript::const_iterator pend, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& fSuccess)
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);

    // Subset of script starting at the most recent codeseparator
    CScript scriptCode(pbegincodehash, pend);

    // Drop the signature in pre-segwit scripts but not segwit scripts
    if (sigversion == SigVersion::BASE) {
        int found = FindAndDelete(scriptCode, CScript() << vchSig);
        if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
            return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
    }

    if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
        //serror is set
        return false;
    }
    fSuccess = checker.CheckECDSASignature(vchSig, vchPubKey, scriptCode, sigversion);

    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

    return true;
}

/** Helper for OP_CHECKSIG, OP_CHECKSIGVERIFY, and (in Tapscript) OP_CHECKSIGADD.
 *
 * A return value of false means the script fails entirely. When true is returned, the
 * success variable indicates whether the signature check itself succeeded.
 */
static bool EvalChecksig(const valtype& sig, const valtype& pubkey, CScript::const_iterator pbegincodehash, CScript::const_iterator pend,
                        ScriptExecutionData& execdata, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& success)
{
    switch (sigversion) {
    case SigVersion::BASE:
    case SigVersion::WITNESS_V0:
        return EvalChecksigPreTapscript(sig, pubkey, pbegincodehash, pend, flags, checker, sigversion, serror, success);
    case SigVersion::TAPSCRIPT:
        //HCE: not support
        return false;
    case SigVersion::TAPROOT:
        // Key path spending in Taproot has no script, so this is unreachable.
        break;
    }
    assert(false);
}


bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    // static const CScriptNum bnFalse(0);
    // static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    // static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    // sigversion cannot be TAPROOT here, as it admits no script execution.
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0 || sigversion == SigVersion::TAPSCRIPT);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    ConditionStack vfExec;
    std::vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if ((sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) && script.size() > MAX_SCRIPT_SIZE) {
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    }
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    uint32_t opcode_pos = 0;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;

    try
    {
        for (; pc < pend; ++opcode_pos) {
            bool fExec = vfExec.all_true();

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            if (sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) {
                // Note how OP_RESERVED does not count towards the opcode limit.
                if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT) {
                    return set_error(serror, SCRIPT_ERR_OP_COUNT);
                }
            }

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes (CVE-2010-5137).

            // With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is rejected even in an unexecuted branch
            if (opcode == OP_CODESEPARATOR && sigversion == SigVersion::BASE && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
                return set_error(serror, SCRIPT_ERR_OP_CODESEPARATOR);

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            }
            else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
                switch (opcode)
                {
                    //
                    // Push value
                    //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_NOP1: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                        if (sigversion == SigVersion::TAPSCRIPT) {
                            // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                            // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                            if (vch.size() > 1 || (vch.size() == 1 && vch[0] != 1)) {
                                return set_error(serror, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
                            }
                        }
                        // Under witness v0 rules it is only a policy rule, enabled through SCRIPT_VERIFY_MINIMALIF.
                        if (sigversion == SigVersion::WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF)) {
                            if (vch.size() > 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                            if (vch.size() == 1 && vch[0] != 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.toggle_top();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end() - 6, stack.end() - 4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n - 1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end() - n - 1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end() - 2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                    //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                        CHash160().Write(vch).Finalize(vchHash);
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch).Finalize(vchHash);
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // If SCRIPT_VERIFY_CONST_SCRIPTCODE flag is set, use of OP_CODESEPARATOR is rejected in pre-segwit
                    // script, even in an unexecuted branch (this is checked above the opcode case statement).

                    // Hash starts after the code separator
                    pbegincodehash = pc;
                    execdata.m_codeseparator_pos = opcode_pos;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);

                    bool fSuccess = true;
                    if (!EvalChecksig(vchSig, vchPubKey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, fSuccess)) return false;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKSIGADD:
                {
                    // OP_CHECKSIGADD is only available in Tapscript
                    if (sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) return set_error(serror, SCRIPT_ERR_BAD_OPCODE);

                    // (sig num pubkey -- num)
                    if (stack.size() < 3) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const valtype& sig = stacktop(-3);
                    const CScriptNum num(stacktop(-2), fRequireMinimal);
                    const valtype& pubkey = stacktop(-1);

                    bool success = true;
                    if (!EvalChecksig(sig, pubkey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, success)) return false;
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back((num + (success ? 1 : 0)).getvch());
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    if (sigversion == SigVersion::TAPSCRIPT) return set_error(serror, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);

                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    nOpCount += nKeysCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int ikey = ++i;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    int ikey2 = nKeysCount + 2;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig - k);
                        if (sigversion == SigVersion::BASE) {
                            int found = FindAndDelete(scriptCode, CScript() << vchSig);
                            if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
                                return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
                        }
                    }

                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        // See the script_(in)valid tests for details.
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                            // serror is set
                            return false;
                        }

                        // Check signature
                        bool fOk = checker.CheckECDSASignature(vchSig, vchPubKey, scriptCode, sigversion);

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                        if (ikey2 > 0)
                            ikey2--;
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                break;

                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}



//bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType)
//bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags,
//    const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror)
//{
//    CAutoBN_CTX pctx;
//    CScript::const_iterator pc = script.begin();
//    CScript::const_iterator pend = script.end();
//    CScript::const_iterator pbegincodehash = script.begin();
//    opcodetype opcode;
//    valtype vchPushValue;
//    vector<bool> vfExec;
//    vector<valtype> altstack;
//    if (script.size() > 10000)
//        return false;
//    int nOpCount = 0;
//
//
//    try
//    {
//        while (pc < pend)
//        {
//            bool fExec = !count(vfExec.begin(), vfExec.end(), false);
//
//            //
//            // Read instruction
//            //
//            if (!script.GetOp(pc, opcode, vchPushValue))
//                return false;
//            if (vchPushValue.size() > 520)
//                return false;
//            if (opcode > OP_16 && ++nOpCount > 201)
//                return false;
//
//            if (opcode == OP_CAT ||
//                opcode == OP_SUBSTR ||
//                opcode == OP_LEFT ||
//                opcode == OP_RIGHT ||
//                opcode == OP_INVERT ||
//                opcode == OP_AND ||
//                opcode == OP_OR ||
//                opcode == OP_XOR ||
//                opcode == OP_2MUL ||
//                opcode == OP_2DIV ||
//                opcode == OP_MUL ||
//                opcode == OP_DIV ||
//                opcode == OP_MOD ||
//                opcode == OP_LSHIFT ||
//                opcode == OP_RSHIFT)
//                return false;
//
//            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
//                stack.push_back(vchPushValue);
//            else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
//            switch (opcode)
//            {
//                //
//                // Push value
//                //
//                case OP_1NEGATE:
//                case OP_1:
//                case OP_2:
//                case OP_3:
//                case OP_4:
//                case OP_5:
//                case OP_6:
//                case OP_7:
//                case OP_8:
//                case OP_9:
//                case OP_10:
//                case OP_11:
//                case OP_12:
//                case OP_13:
//                case OP_14:
//                case OP_15:
//                case OP_16:
//                {
//                    // ( -- value)
//                    CBigNum bn((int)opcode - (int)(OP_1 - 1));
//                    stack.push_back(bn.getvch());
//                }
//                break;
//
//
//                //
//                // Control
//                //
//                case OP_NOP:
//                case OP_NOP1: case OP_NOP2: case OP_NOP3: case OP_NOP4: case OP_NOP5:
//                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
//                break;
//
//                case OP_IF:
//                case OP_NOTIF:
//                {
//                    // <expression> if [statements] [else [statements]] endif
//                    bool fValue = false;
//                    if (fExec)
//                    {
//                        if (stack.size() < 1)
//                            return false;
//                        valtype& vch = stacktop(-1);
//                        fValue = CastToBool(vch);
//                        if (opcode == OP_NOTIF)
//                            fValue = !fValue;
//                        popstack(stack);
//                    }
//                    vfExec.push_back(fValue);
//                }
//                break;
//
//                case OP_ELSE:
//                {
//                    if (vfExec.empty())
//                        return false;
//                    vfExec.back() = !vfExec.back();
//                }
//                break;
//
//                case OP_ENDIF:
//                {
//                    if (vfExec.empty())
//                        return false;
//                    vfExec.pop_back();
//                }
//                break;
//
//                case OP_VERIFY:
//                {
//                    // (true -- ) or
//                    // (false -- false) and return
//                    if (stack.size() < 1)
//                        return false;
//                    bool fValue = CastToBool(stacktop(-1));
//                    if (fValue)
//                        popstack(stack);
//                    else
//                        return false;
//                }
//                break;
//
//                case OP_RETURN:
//                {
//                    return false;
//                }
//                break;
//
//
//                //
//                // Stack ops
//                //
//                case OP_TOALTSTACK:
//                {
//                    if (stack.size() < 1)
//                        return false;
//                    altstack.push_back(stacktop(-1));
//                    popstack(stack);
//                }
//                break;
//
//                case OP_FROMALTSTACK:
//                {
//                    if (altstack.size() < 1)
//                        return false;
//                    stack.push_back(altstacktop(-1));
//                    popstack(altstack);
//                }
//                break;
//
//                case OP_2DROP:
//                {
//                    // (x1 x2 -- )
//                    if (stack.size() < 2)
//                        return false;
//                    popstack(stack);
//                    popstack(stack);
//                }
//                break;
//
//                case OP_2DUP:
//                {
//                    // (x1 x2 -- x1 x2 x1 x2)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype vch1 = stacktop(-2);
//                    valtype vch2 = stacktop(-1);
//                    stack.push_back(vch1);
//                    stack.push_back(vch2);
//                }
//                break;
//
//                case OP_3DUP:
//                {
//                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
//                    if (stack.size() < 3)
//                        return false;
//                    valtype vch1 = stacktop(-3);
//                    valtype vch2 = stacktop(-2);
//                    valtype vch3 = stacktop(-1);
//                    stack.push_back(vch1);
//                    stack.push_back(vch2);
//                    stack.push_back(vch3);
//                }
//                break;
//
//                case OP_2OVER:
//                {
//                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
//                    if (stack.size() < 4)
//                        return false;
//                    valtype vch1 = stacktop(-4);
//                    valtype vch2 = stacktop(-3);
//                    stack.push_back(vch1);
//                    stack.push_back(vch2);
//                }
//                break;
//
//                case OP_2ROT:
//                {
//                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
//                    if (stack.size() < 6)
//                        return false;
//                    valtype vch1 = stacktop(-6);
//                    valtype vch2 = stacktop(-5);
//                    stack.erase(stack.end()-6, stack.end()-4);
//                    stack.push_back(vch1);
//                    stack.push_back(vch2);
//                }
//                break;
//
//                case OP_2SWAP:
//                {
//                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
//                    if (stack.size() < 4)
//                        return false;
//                    swap(stacktop(-4), stacktop(-2));
//                    swap(stacktop(-3), stacktop(-1));
//                }
//                break;
//
//                case OP_IFDUP:
//                {
//                    // (x - 0 | x x)
//                    if (stack.size() < 1)
//                        return false;
//                    valtype vch = stacktop(-1);
//                    if (CastToBool(vch))
//                        stack.push_back(vch);
//                }
//                break;
//
//                case OP_DEPTH:
//                {
//                    // -- stacksize
//                    CBigNum bn(stack.size());
//                    stack.push_back(bn.getvch());
//                }
//                break;
//
//                case OP_DROP:
//                {
//                    // (x -- )
//                    if (stack.size() < 1)
//                        return false;
//                    popstack(stack);
//                }
//                break;
//
//                case OP_DUP:
//                {
//                    // (x -- x x)
//                    if (stack.size() < 1)
//                        return false;
//                    valtype vch = stacktop(-1);
//                    stack.push_back(vch);
//                }
//                break;
//
//                case OP_NIP:
//                {
//                    // (x1 x2 -- x2)
//                    if (stack.size() < 2)
//                        return false;
//                    stack.erase(stack.end() - 2);
//                }
//                break;
//
//                case OP_OVER:
//                {
//                    // (x1 x2 -- x1 x2 x1)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype vch = stacktop(-2);
//                    stack.push_back(vch);
//                }
//                break;
//
//                case OP_PICK:
//                case OP_ROLL:
//                {
//                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
//                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
//                    if (stack.size() < 2)
//                        return false;
//                    int n = CastToBigNum(stacktop(-1)).getint();
//                    popstack(stack);
//                    if (n < 0 || n >= stack.size())
//                        return false;
//                    valtype vch = stacktop(-n-1);
//                    if (opcode == OP_ROLL)
//                        stack.erase(stack.end()-n-1);
//                    stack.push_back(vch);
//                }
//                break;
//
//                case OP_ROT:
//                {
//                    // (x1 x2 x3 -- x2 x3 x1)
//                    //  x2 x1 x3  after first swap
//                    //  x2 x3 x1  after second swap
//                    if (stack.size() < 3)
//                        return false;
//                    swap(stacktop(-3), stacktop(-2));
//                    swap(stacktop(-2), stacktop(-1));
//                }
//                break;
//
//                case OP_SWAP:
//                {
//                    // (x1 x2 -- x2 x1)
//                    if (stack.size() < 2)
//                        return false;
//                    swap(stacktop(-2), stacktop(-1));
//                }
//                break;
//
//                case OP_TUCK:
//                {
//                    // (x1 x2 -- x2 x1 x2)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype vch = stacktop(-1);
//                    stack.insert(stack.end()-2, vch);
//                }
//                break;
//
//
//                //
//                // Splice ops
//                //
//                case OP_CAT:
//                {
//                    // (x1 x2 -- out)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype& vch1 = stacktop(-2);
//                    valtype& vch2 = stacktop(-1);
//                    vch1.insert(vch1.end(), vch2.begin(), vch2.end());
//                    popstack(stack);
//                    if (stacktop(-1).size() > 520)
//                        return false;
//                }
//                break;
//
//                case OP_SUBSTR:
//                {
//                    // (in begin size -- out)
//                    if (stack.size() < 3)
//                        return false;
//                    valtype& vch = stacktop(-3);
//                    int nBegin = CastToBigNum(stacktop(-2)).getint();
//                    int nEnd = nBegin + CastToBigNum(stacktop(-1)).getint();
//                    if (nBegin < 0 || nEnd < nBegin)
//                        return false;
//                    if (nBegin > vch.size())
//                        nBegin = vch.size();
//                    if (nEnd > vch.size())
//                        nEnd = vch.size();
//                    vch.erase(vch.begin() + nEnd, vch.end());
//                    vch.erase(vch.begin(), vch.begin() + nBegin);
//                    popstack(stack);
//                    popstack(stack);
//                }
//                break;
//
//                case OP_LEFT:
//                case OP_RIGHT:
//                {
//                    // (in size -- out)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype& vch = stacktop(-2);
//                    int nSize = CastToBigNum(stacktop(-1)).getint();
//                    if (nSize < 0)
//                        return false;
//                    if (nSize > vch.size())
//                        nSize = vch.size();
//                    if (opcode == OP_LEFT)
//                        vch.erase(vch.begin() + nSize, vch.end());
//                    else
//                        vch.erase(vch.begin(), vch.end() - nSize);
//                    popstack(stack);
//                }
//                break;
//
//                case OP_SIZE:
//                {
//                    // (in -- in size)
//                    if (stack.size() < 1)
//                        return false;
//                    CBigNum bn(stacktop(-1).size());
//                    stack.push_back(bn.getvch());
//                }
//                break;
//
//
//                //
//                // Bitwise logic
//                //
//                case OP_INVERT:
//                {
//                    // (in - out)
//                    if (stack.size() < 1)
//                        return false;
//                    valtype& vch = stacktop(-1);
//                    for (int i = 0; i < vch.size(); i++)
//                        vch[i] = ~vch[i];
//                }
//                break;
//
//                case OP_AND:
//                case OP_OR:
//                case OP_XOR:
//                {
//                    // (x1 x2 - out)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype& vch1 = stacktop(-2);
//                    valtype& vch2 = stacktop(-1);
//                    MakeSameSize(vch1, vch2);
//                    if (opcode == OP_AND)
//                    {
//                        for (int i = 0; i < vch1.size(); i++)
//                            vch1[i] &= vch2[i];
//                    }
//                    else if (opcode == OP_OR)
//                    {
//                        for (int i = 0; i < vch1.size(); i++)
//                            vch1[i] |= vch2[i];
//                    }
//                    else if (opcode == OP_XOR)
//                    {
//                        for (int i = 0; i < vch1.size(); i++)
//                            vch1[i] ^= vch2[i];
//                    }
//                    popstack(stack);
//                }
//                break;
//
//                case OP_EQUAL:
//                case OP_EQUALVERIFY:
//                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
//                {
//                    // (x1 x2 - bool)
//                    if (stack.size() < 2)
//                        return false;
//                    valtype& vch1 = stacktop(-2);
//                    valtype& vch2 = stacktop(-1);
//                    bool fEqual = (vch1 == vch2);
//                    // OP_NOTEQUAL is disabled because it would be too easy to say
//                    // something like n != 1 and have some wiseguy pass in 1 with extra
//                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
//                    //if (opcode == OP_NOTEQUAL)
//                    //    fEqual = !fEqual;
//                    popstack(stack);
//                    popstack(stack);
//                    stack.push_back(fEqual ? vchTrue : vchFalse);
//                    if (opcode == OP_EQUALVERIFY)
//                    {
//                        if (fEqual)
//                            popstack(stack);
//                        else
//                            return false;
//                    }
//                }
//                break;
//
//
//                //
//                // Numeric
//                //
//                case OP_1ADD:
//                case OP_1SUB:
//                case OP_2MUL:
//                case OP_2DIV:
//                case OP_NEGATE:
//                case OP_ABS:
//                case OP_NOT:
//                case OP_0NOTEQUAL:
//                {
//                    // (in -- out)
//                    if (stack.size() < 1)
//                        return false;
//                    CBigNum bn = CastToBigNum(stacktop(-1));
//                    switch (opcode)
//                    {
//                    case OP_1ADD:       bn += bnOne; break;
//                    case OP_1SUB:       bn -= bnOne; break;
//                    case OP_2MUL:       bn <<= 1; break;
//                    case OP_2DIV:       bn >>= 1; break;
//                    case OP_NEGATE:     bn = -bn; break;
//                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
//                    case OP_NOT:        bn = (bn == bnZero); break;
//                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
//                    default:            assert(!"invalid opcode"); break;
//                    }
//                    popstack(stack);
//                    stack.push_back(bn.getvch());
//                }
//                break;
//
//                case OP_ADD:
//                case OP_SUB:
//                case OP_MUL:
//                case OP_DIV:
//                case OP_MOD:
//                case OP_LSHIFT:
//                case OP_RSHIFT:
//                case OP_BOOLAND:
//                case OP_BOOLOR:
//                case OP_NUMEQUAL:
//                case OP_NUMEQUALVERIFY:
//                case OP_NUMNOTEQUAL:
//                case OP_LESSTHAN:
//                case OP_GREATERTHAN:
//                case OP_LESSTHANOREQUAL:
//                case OP_GREATERTHANOREQUAL:
//                case OP_MIN:
//                case OP_MAX:
//                {
//                    // (x1 x2 -- out)
//                    if (stack.size() < 2)
//                        return false;
//                    CBigNum bn1 = CastToBigNum(stacktop(-2));
//                    CBigNum bn2 = CastToBigNum(stacktop(-1));
//                    CBigNum bn;
//                    switch (opcode)
//                    {
//                    case OP_ADD:
//                        bn = bn1 + bn2;
//                        break;
//
//                    case OP_SUB:
//                        bn = bn1 - bn2;
//                        break;
//
//                    case OP_MUL:
//                        if (!BN_mul(&bn, &bn1, &bn2, pctx))
//                            return false;
//                        break;
//
//                    case OP_DIV:
//                        if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
//                            return false;
//                        break;
//
//                    case OP_MOD:
//                        if (!BN_mod(&bn, &bn1, &bn2, pctx))
//                            return false;
//                        break;
//
//                    case OP_LSHIFT:
//                        if (bn2 < bnZero || bn2 > CBigNum(2048))
//                            return false;
//                        bn = bn1 << bn2.getulong();
//                        break;
//
//                    case OP_RSHIFT:
//                        if (bn2 < bnZero || bn2 > CBigNum(2048))
//                            return false;
//                        bn = bn1 >> bn2.getulong();
//                        break;
//
//                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
//                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
//                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
//                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
//                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
//                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
//                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
//                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
//                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
//                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
//                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
//                    default:                     assert(!"invalid opcode"); break;
//                    }
//                    popstack(stack);
//                    popstack(stack);
//                    stack.push_back(bn.getvch());
//
//                    if (opcode == OP_NUMEQUALVERIFY)
//                    {
//                        if (CastToBool(stacktop(-1)))
//                            popstack(stack);
//                        else
//                            return false;
//                    }
//                }
//                break;
//
//                case OP_WITHIN:
//                {
//                    // (x min max -- out)
//                    if (stack.size() < 3)
//                        return false;
//                    CBigNum bn1 = CastToBigNum(stacktop(-3));
//                    CBigNum bn2 = CastToBigNum(stacktop(-2));
//                    CBigNum bn3 = CastToBigNum(stacktop(-1));
//                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
//                    popstack(stack);
//                    popstack(stack);
//                    popstack(stack);
//                    stack.push_back(fValue ? vchTrue : vchFalse);
//                }
//                break;
//
//
//                //
//                // Crypto
//                //
//                case OP_RIPEMD160:
//                case OP_SHA1:
//                case OP_SHA256:
//                case OP_HASH160:
//                case OP_HASH256:
//                {
//                    // (in -- hash)
//                    if (stack.size() < 1)
//                        return false;
//                    valtype& vch = stacktop(-1);
//                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
//                    if (opcode == OP_RIPEMD160)
//                        RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
//                    else if (opcode == OP_SHA1)
//                        SHA1(&vch[0], vch.size(), &vchHash[0]);
//                    else if (opcode == OP_SHA256)
//                        SHA256(&vch[0], vch.size(), &vchHash[0]);
//                    else if (opcode == OP_HASH160)
//                    {
//                        uint160 hash160 = Hash160(vch);
//                        memcpy(&vchHash[0], &hash160, sizeof(hash160));
//                    }
//                    else if (opcode == OP_HASH256)
//                    {
//                        uint256 hash = Hash(vch.begin(), vch.end());
//                        memcpy(&vchHash[0], &hash, sizeof(hash));
//                    }
//                    popstack(stack);
//                    stack.push_back(vchHash);
//                }
//                break;
//
//                case OP_CODESEPARATOR:
//                {
//                    // Hash starts after the code separator
//                    pbegincodehash = pc;
//                }
//                break;
//
//                case OP_CHECKSIG:
//                case OP_CHECKSIGVERIFY:
//                {
//                    // (sig pubkey -- bool)
//                    if (stack.size() < 2)
//                        return false;
//
//                    valtype& vchSig    = stacktop(-2);
//                    valtype& vchPubKey = stacktop(-1);
//
//                    ////// debug print
//                    //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
//                    //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");
//
//                    // Subset of script starting at the most recent codeseparator
//                    //CScript scriptCode(pbegincodehash, pend);
//
//                    // Drop the signature, since there's no way for a signature to sign itself
//                    //scriptCode.FindAndDelete(CScript(vchSig));
//
//                    bool fSuccess = true; // = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);
//                    if (!EvalChecksig(vchSig, vchPubKey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, fSuccess)) return false;
//
//                    popstack(stack);
//                    popstack(stack);
//                    stack.push_back(fSuccess ? vchTrue : vchFalse);
//                    if (opcode == OP_CHECKSIGVERIFY)
//                    {
//                        if (fSuccess)
//                            popstack(stack);
//                        else
//                            return false;
//                    }
//                }
//                break;
//
//                case OP_CHECKMULTISIG:
//                case OP_CHECKMULTISIGVERIFY:
//                {
//                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
//
//                    int i = 1;
//                    if (stack.size() < i)
//                        return false;
//
//                    int nKeysCount = CastToBigNum(stacktop(-i)).getint();
//                    if (nKeysCount < 0 || nKeysCount > 20)
//                        return false;
//                    nOpCount += nKeysCount;
//                    if (nOpCount > 201)
//                        return false;
//                    int ikey = ++i;
//                    i += nKeysCount;
//                    if (stack.size() < i)
//                        return false;
//
//                    int nSigsCount = CastToBigNum(stacktop(-i)).getint();
//                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
//                        return false;
//                    int isig = ++i;
//                    i += nSigsCount;
//                    if (stack.size() < i)
//                        return false;
//
//                    // Subset of script starting at the most recent codeseparator
//                    //CScript scriptCode(pbegincodehash, pend);
//
//                    // Drop the signatures, since there's no way for a signature to sign itself
//                    //for (int k = 0; k < nSigsCount; k++)
//                    //{
//                    //    valtype& vchSig = stacktop(-isig-k);
//                    //    scriptCode.FindAndDelete(CScript(vchSig));
//                    //}
//
//                    bool fSuccess = true;
//                    while (fSuccess && nSigsCount > 0)
//                    {
//                        valtype& vchSig    = stacktop(-isig);
//                        valtype& vchPubKey = stacktop(-ikey);
//
//                        // Check signature
//                        //if (CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType))
//                        if (EvalChecksig(vchSig, vchPubKey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, fSuccess))
//                        {
//                            isig++;
//                            nSigsCount--;
//                        }
//                        ikey++;
//                        nKeysCount--;
//
//                        // If there are more signatures left than keys left,
//                        // then too many signatures have failed
//                        if (nSigsCount > nKeysCount)
//                            fSuccess = false;
//                    }
//
//                    while (i-- > 0)
//                        popstack(stack);
//                    stack.push_back(fSuccess ? vchTrue : vchFalse);
//
//                    if (opcode == OP_CHECKMULTISIGVERIFY)
//                    {
//                        if (fSuccess)
//                            popstack(stack);
//                        else
//                            return false;
//                    }
//                }
//                break;
//
//                default:
//                    return false;
//            }
//
//            // Size limits
//            if (stack.size() + altstack.size() > 1000)
//                return false;
//        }
//    }
//    catch (...)
//    {
//        return false;
//    }
//
//
//    if (!vfExec.empty())
//        return false;
//
//    return true;
//}
//
//







uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    CTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lockin the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
            return 1;
        }
        txTmp.vout.resize(nOut+1);
        for (int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    CDataStream ss(SER_GETHASH);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return Hash(ss.begin(), ss.end());
}


bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    CPubKey key(vchPubKey);

    if (!key.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back();

    return key.Verify(SignatureHash(scriptCode, txTo, nIn, nHashType), vchSig);
}










bool Solver(const CScript& scriptPubKey, vector<pair<opcodetype, valtype> >& vSolutionRet)
{
    // Templates
    static vector<CScript> vTemplates;
    if (vTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        vTemplates.push_back(CScript() << OP_PUBKEY << OP_CHECKSIG);

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        vTemplates.push_back(CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG);
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    BOOST_FOREACH(const CScript& script2, vTemplates)
    {
        vSolutionRet.clear();
        opcodetype opcode1, opcode2;
        vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        loop
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                reverse(vSolutionRet.begin(), vSolutionRet.end());
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;
            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 120)
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                break;
            }
        }
    }

    vSolutionRet.clear();
    return false;
}


bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    scriptSigRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    // Compile solution
    BOOST_FOREACH(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEY)
        {
            // Sign
            const valtype& vchPubKey = item.second;
            CKey key;
            //HCE: get key pair(public key and private key) from keystore
            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;
            if (hash != 0)
            {
                vector<unsigned char> vchSig;
                if (!key.Sign(hash, vchSig))
                    return false;
                vchSig.push_back((unsigned char)nHashType);
                scriptSigRet << vchSig;
            }
        }
        else if (item.first == OP_PUBKEYHASH)
        {
            // Sign and give pubkey
            CKey key;
            if (!keystore.GetKey(uint160(item.second), key))
                return false;
            if (hash != 0)
            {
                vector<unsigned char> vchSig;
                if (!key.Sign(hash, vchSig))
                    return false;
                vchSig.push_back((unsigned char)nHashType);
                scriptSigRet << vchSig << key.GetPubKey();
            }
        }
        else
        {
            return false;
        }
    }

    return true;
}


bool IsStandard(const CScript& scriptPubKey)
{
    TxoutType whichType;
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    }
    else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }
    else if (whichType == TxoutType::NULL_DATA &&
        (!fAcceptDatacarrier || scriptPubKey.size() > nMaxDatacarrierBytes)) {
        return false;
    }

    return true;
}

[[deprecated("::IsMine is deprecated, replaced by LegacyScriptPubKeyMan::IsMine")]]
bool IsMine(const CKeyStore &keystore, const CScript& scriptPubKey)
{
    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    //std::vector<valtype> vSolutions;
    //TxoutType whichType = Solver(scriptPubKey, vSolutions);


    // Compile solution
    BOOST_FOREACH(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEY)
        {
            const valtype& vchPubKey = item.second;
            vector<unsigned char> vchPubKeyFound;
            if (!keystore.GetPubKey(Hash160(vchPubKey), vchPubKeyFound))
                return false;
            if (vchPubKeyFound != vchPubKey)
                return false;
        }
        else if (item.first == OP_PUBKEYHASH)
        {
            if (!keystore.HaveKey(uint160(item.second)))
                return false;
        }
        else
        {
            return false;
        }
    }

    return true;
}

bool static ExtractAddressInner(const CScript& scriptPubKey, const CKeyStore* keystore, CBitcoinAddress& addressRet)
{
    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    BOOST_FOREACH(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEY)
            addressRet.SetPubKey(item.second);
        else if (item.first == OP_PUBKEYHASH)
            addressRet.SetHash160((uint160)item.second);
        if (keystore == NULL || keystore->HaveKey(addressRet))
            return true;
    }
    return false;
}

bool ExtractAddress(const CScript& scriptPubKey, std::vector<unsigned char>& vchPubKey)
{
    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    BOOST_FOREACH(PAIRTYPE(opcodetype, valtype) & item, vSolution)
    {
        if (item.first == OP_PUBKEY) {
            vchPubKey = item.second;
            return true;
        }
    }
    return false;
}


bool ExtractAddress(const CScript& scriptPubKey, const CKeyStore* keystore, CBitcoinAddress& addressRet)
{
    if (keystore)
        return ExtractAddressInner(scriptPubKey, keystore, addressRet);
    else
        return ExtractAddressInner(scriptPubKey, NULL, addressRet);
    return false;
}


//////////////////////////////////////////////////////////////////////////
///HCE: SegWit
///
///


namespace {

    /**
     * Wrapper that serializes like CTransaction, but with the modifications
     *  required for the signature hash done in-place
     */
    template <class T>
    class CTransactionSignatureSerializer
    {
    private:
        const T& txTo;             //!< reference to the spending transaction (the one being serialized)
        const CScript& scriptCode; //!< output script being consumed
        const unsigned int nIn;    //!< input index of txTo being signed
        const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
        const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
        const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

    public:
        CTransactionSignatureSerializer(const T& txToIn, const CScript& scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
            txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
            fAnyoneCanPay(!!(nHashTypeIn& SIGHASH_ANYONECANPAY)),
            fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
            fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE)
        {
        }

        /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
        template<typename S>
        void SerializeScriptCode(S& s) const
        {
            CScript::const_iterator it = scriptCode.begin();
            CScript::const_iterator itBegin = it;
            opcodetype opcode;
            unsigned int nCodeSeparators = 0;
            while (scriptCode.GetOp(it, opcode)) {
                if (opcode == OP_CODESEPARATOR)
                    nCodeSeparators++;
            }
            ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
            it = itBegin;
            while (scriptCode.GetOp(it, opcode)) {
                if (opcode == OP_CODESEPARATOR) {
                    s.write((char*)&itBegin[0], it - itBegin - 1);
                    itBegin = it;
                }
            }
            if (itBegin != scriptCode.end())
                s.write((char*)&itBegin[0], it - itBegin);
        }

        /** Serialize an input of txTo */
        template<typename S>
        void SerializeInput(S& s, unsigned int nInput, long nType, int nVersion = VERSION) const
        {
            CSerActionSerialize ser_action;
            unsigned int nSerSize = 0;

            // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
            if (fAnyoneCanPay)
                nInput = nIn;
            // Serialize the prevout
            //::Serialize(s, txTo.vin[nInput].prevout, nType, nVersion);
            READWRITE(txTo.vin[nInput].prevout);
            // Serialize the script
            if (nInput != nIn)
                // Blank out other inputs' signatures
                //::Serialize(s, CScript(), nType, nVersion);
                READWRITE(CScript());
            else
                SerializeScriptCode(s);
            // Serialize the nSequence
            if (nInput != nIn && (fHashSingle || fHashNone)) {
                // let the others update at will
                //::Serialize(s, (int)0, nType, nVersion);
                int i = 0;
                READWRITE(i);
            }
            else
                //::Serialize(s, txTo.vin[nInput].nSequence, nType, nVersion);
                READWRITE(txTo.vin[nInput].nSequence);
        }

        /** Serialize an output of txTo */
        template<typename S>
        void SerializeOutput(S& s, unsigned int nOutput, long nType, int nVersion = VERSION) const
        {
            CSerActionSerialize ser_action;
            unsigned int nSerSize = 0;

            if (fHashSingle && nOutput != nIn)
                // Do not lock-in the txout payee at other indices as txin
                //::Serialize(s, CTxOut(), nType, nVersion);
                READWRITE(CTxOut());
            else
                //::Serialize(s, txTo.vout[nOutput], nType, nVersion);
                READWRITE(txTo.vout[nOutput]);
        }

        /** Serialize txTo */
        template<typename S>
        void Serialize(S& s, long nType, int nVersion = VERSION) const
        {
            //CSerActionSerialize ser_action;
            //const bool fGetSize = true;
            //const bool fWrite = false;
            //const bool fRead = false;
            //unsigned int nSerSize = 0;

            // Serialize nVersion
            WRITEDATA(s, txTo.nVersion);
            //::Serialize(s, (int)txTo.nVersion, nType, nVersion);
            // Serialize vin
            unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
            ::WriteCompactSize(s, nInputs);
            for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                SerializeInput(s, nInput, nType, nVersion);
            // Serialize vout
            unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn + 1 : txTo.vout.size());
            ::WriteCompactSize(s, nOutputs);
            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                SerializeOutput(s, nOutput, nType, nVersion);
            //Serialize nLockTime
            //::Serialize(s, txTo.nLockTime, nType, nVersion);
            WRITEDATA(s, txTo.nLockTime);
        }
    };

    /** Compute the (single) SHA256 of the concatenation of all prevouts of a tx. */
    template <class T>
    uint256 GetPrevoutsSHA256(const T& txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txin : txTo.vin) {
            ss << txin.prevout;
        }
        return ss.GetSHA256();
    }

    /** Compute the (single) SHA256 of the concatenation of all nSequences of a tx. */
    template <class T>
    uint256 GetSequencesSHA256(const T& txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txin : txTo.vin) {
            ss << txin.nSequence;
        }
        return ss.GetSHA256();
    }

    /** Compute the (single) SHA256 of the concatenation of all txouts of a tx. */
    template <class T>
    uint256 GetOutputsSHA256(const T& txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txout : txTo.vout) {
            ss << txout;
        }
        return ss.GetSHA256();
    }

    /** Compute the (single) SHA256 of the concatenation of all amounts spent by a tx. */
    uint256 GetSpentAmountsSHA256(const std::vector<CTxOut>& outputs_spent)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txout : outputs_spent) {
            ss << txout.nValue;
        }
        return ss.GetSHA256();
    }

    /** Compute the (single) SHA256 of the concatenation of all scriptPubKeys spent by a tx. */
    uint256 GetSpentScriptsSHA256(const std::vector<CTxOut>& outputs_spent)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& txout : outputs_spent) {
            ss << txout.scriptPubKey;
        }
        return ss.GetSHA256();
    }


} // namespace


template <class T>
void PrecomputedTransactionData::Init(const T& txTo, std::vector<CTxOut>&& spent_outputs)
{
    assert(!m_spent_outputs_ready);

    m_spent_outputs = std::move(spent_outputs);
    if (!m_spent_outputs.empty()) {
        assert(m_spent_outputs.size() == txTo.vin.size());
        m_spent_outputs_ready = true;
    }

    // Determine which precomputation-impacting features this transaction uses.
    bool uses_bip143_segwit = false;
    bool uses_bip341_taproot = false;
    for (size_t inpos = 0; inpos < txTo.vin.size(); ++inpos) {
        if (!txTo.vin[inpos].scriptWitness.IsNull()) {
            if (m_spent_outputs_ready && m_spent_outputs[inpos].scriptPubKey.size() == 2 + WITNESS_V1_TAPROOT_SIZE &&
                m_spent_outputs[inpos].scriptPubKey[0] == OP_1) {
                // Treat every witness-bearing spend with 34-byte scriptPubKey that starts with OP_1 as a Taproot
                // spend. This only works if spent_outputs was provided as well, but if it wasn't, actual validation
                // will fail anyway. Note that this branch may trigger for scriptPubKeys that aren't actually segwit
                // but in that case validation will fail as SCRIPT_ERR_WITNESS_UNEXPECTED anyway.
                uses_bip341_taproot = true;
            }
            else {
                // Treat every spend that's not known to native witness v1 as a Witness v0 spend. This branch may
                // also be taken for unknown witness versions, but it is harmless, and being precise would require
                // P2SH evaluation to find the redeemScript.
                uses_bip143_segwit = true;
            }
        }
        if (uses_bip341_taproot && uses_bip143_segwit) break; // No need to scan further if we already need all.
    }

    if (uses_bip143_segwit || uses_bip341_taproot) {
        // Computations shared between both sighash schemes.
        m_prevouts_single_hash = GetPrevoutsSHA256(txTo);
        m_sequences_single_hash = GetSequencesSHA256(txTo);
        m_outputs_single_hash = GetOutputsSHA256(txTo);
    }
    if (uses_bip143_segwit) {
        hashPrevouts = SHA256Uint256(m_prevouts_single_hash);
        hashSequence = SHA256Uint256(m_sequences_single_hash);
        hashOutputs = SHA256Uint256(m_outputs_single_hash);
        m_bip143_segwit_ready = true;
    }
    if (uses_bip341_taproot) {
        m_spent_amounts_single_hash = GetSpentAmountsSHA256(m_spent_outputs);
        m_spent_scripts_single_hash = GetSpentScriptsSHA256(m_spent_outputs);
        m_bip341_taproot_ready = true;
    }
}

template <class T>
PrecomputedTransactionData::PrecomputedTransactionData(const T& txTo)
{
    Init(txTo, {});
}

// explicit instantiation
template void PrecomputedTransactionData::Init(const CTransaction& txTo, std::vector<CTxOut>&& spent_outputs);
//template void PrecomputedTransactionData::Init(const CMutableTransaction& txTo, std::vector<CTxOut>&& spent_outputs);
template PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo);
//template PrecomputedTransactionData::PrecomputedTransactionData(const CMutableTransaction& txTo);


static const CHashWriter HASHER_TAPSIGHASH = TaggedHash("TapSighash");
static const CHashWriter HASHER_TAPLEAF = TaggedHash("TapLeaf");
static const CHashWriter HASHER_TAPBRANCH = TaggedHash("TapBranch");
static const CHashWriter HASHER_TAPTWEAK = TaggedHash("TapTweak");

template<typename T>
bool SignatureHashSchnorr(uint256& hash_out, const ScriptExecutionData& execdata, const T& tx_to, uint32_t in_pos, uint8_t hash_type, SigVersion sigversion, const PrecomputedTransactionData& cache)
{
    uint8_t ext_flag, key_version;
    switch (sigversion) {
    case SigVersion::TAPROOT:
        ext_flag = 0;
        // key_version is not used and left uninitialized.
        break;
    case SigVersion::TAPSCRIPT:
        ext_flag = 1;
        // key_version must be 0 for now, representing the current version of
        // 32-byte public keys in the tapscript signature opcode execution.
        // An upgradable public key version (with a size not 32-byte) may
        // request a different key_version with a new sigversion.
        key_version = 0;
        break;
    default:
        assert(false);
    }
    assert(in_pos < tx_to.vin.size());
    assert(cache.m_bip341_taproot_ready && cache.m_spent_outputs_ready);

    CHashWriter ss = HASHER_TAPSIGHASH;

    // Epoch
    static constexpr uint8_t EPOCH = 0;
    ss << EPOCH;

    // Hash type
    const uint8_t output_type = (hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type & SIGHASH_OUTPUT_MASK); // Default (no sighash byte) is equivalent to SIGHASH_ALL
    const uint8_t input_type = hash_type & SIGHASH_INPUT_MASK;
    if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))) return false;
    ss << hash_type;

    // Transaction level data
    ss << tx_to.nVersion;
    ss << tx_to.nLockTime;
    if (input_type != SIGHASH_ANYONECANPAY) {
        ss << cache.m_prevouts_single_hash;
        ss << cache.m_spent_amounts_single_hash;
        ss << cache.m_spent_scripts_single_hash;
        ss << cache.m_sequences_single_hash;
    }
    if (output_type == SIGHASH_ALL) {
        ss << cache.m_outputs_single_hash;
    }

    // Data about the input/prevout being spent
    assert(execdata.m_annex_init);
    const bool have_annex = execdata.m_annex_present;
    const uint8_t spend_type = (ext_flag << 1) + (have_annex ? 1 : 0); // The low bit indicates whether an annex is present.
    ss << spend_type;
    if (input_type == SIGHASH_ANYONECANPAY) {
        ss << tx_to.vin[in_pos].prevout;
        ss << cache.m_spent_outputs[in_pos];
        ss << tx_to.vin[in_pos].nSequence;
    }
    else {
        ss << in_pos;
    }
    if (have_annex) {
        ss << execdata.m_annex_hash;
    }

    // Data about the output (if only one).
    if (output_type == SIGHASH_SINGLE) {
        if (in_pos >= tx_to.vout.size()) return false;
        CHashWriter sha_single_output(SER_GETHASH, 0);
        sha_single_output << tx_to.vout[in_pos];
        ss << sha_single_output.GetSHA256();
    }

    // Additional data for BIP 342 signatures
    if (sigversion == SigVersion::TAPSCRIPT) {
        assert(execdata.m_tapleaf_hash_init);
        ss << execdata.m_tapleaf_hash;
        ss << key_version;
        assert(execdata.m_codeseparator_pos_init);
        ss << execdata.m_codeseparator_pos;
    }

    hash_out = ss.GetSHA256();
    return true;
}

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    assert(nIn < txTo.vin.size());

    if (sigversion == SigVersion::WITNESS_V0) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        const bool cacheready = cache && cache->m_bip143_segwit_ready;

        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            hashPrevouts = cacheready ? cache->hashPrevouts : SHA256Uint256(GetPrevoutsSHA256(txTo));
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashSequence = cacheready ? cache->hashSequence : SHA256Uint256(GetSequencesSHA256(txTo));
        }


        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashOutputs = cacheready ? cache->hashOutputs : SHA256Uint256(GetOutputsSHA256(txTo));
        }
        else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << scriptCode;
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return uint256::ONE;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer<T> txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

template <class T>
bool GenericTransactionSignatureChecker<T>::VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

template <class T>
bool GenericTransactionSignatureChecker<T>::VerifySchnorrSignature(Span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.VerifySchnorr(sighash, sig);
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckECDSASignature(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    std::vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->txdata);

    if (!VerifyECDSASignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey_in, SigVersion sigversion, const ScriptExecutionData& execdata, ScriptError* serror) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);
    // Schnorr signatures have 32-byte public keys. The caller is responsible for enforcing this.
    assert(pubkey_in.size() == 32);
    // Note that in Tapscript evaluation, empty signatures are treated specially (invalid signature that does not
    // abort script execution). This is implemented in EvalChecksigTapscript, which won't invoke
    // CheckSchnorrSignature in that case. In other contexts, they are invalid like every other signature with
    // size different from 64 or 65.
    if (sig.size() != 64 && sig.size() != 65) return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_SIZE);

    XOnlyPubKey pubkey{ pubkey_in };

    uint8_t hashtype = SIGHASH_DEFAULT;
    if (sig.size() == 65) {
        hashtype = SpanPopBack(sig);
        if (hashtype == SIGHASH_DEFAULT) return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE);
    }
    uint256 sighash;
    assert(this->txdata);
    if (!SignatureHashSchnorr(sighash, execdata, *txTo, nIn, hashtype, sigversion, *this->txdata)) {
        return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE);
    }
    if (!VerifySchnorrSignature(sig, pubkey, sighash)) return set_error(serror, SCRIPT_ERR_SCHNORR_SIG);
    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
        (txTo->nLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
        (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
        ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
        return false;

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
        (txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        )) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

// explicit instantiation
template class GenericTransactionSignatureChecker<CTransaction>;
//template class GenericTransactionSignatureChecker<CMutableTransaction>;


static bool ExecuteWitnessScript(const Span<const valtype>& stack_span, const CScript& scriptPubKey, unsigned int flags, SigVersion sigversion,
                                const BaseSignatureChecker& checker, ScriptExecutionData& execdata, ScriptError* serror)
{
    std::vector<valtype> stack{ stack_span.begin(), stack_span.end() };

    if (sigversion == SigVersion::TAPSCRIPT) {
        //HCE: not support
        return false;
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for (const valtype& elem : stack) {
        if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE) return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }

    // Run the script interpreter.
    if (!EvalScript(stack, scriptPubKey, flags, checker, sigversion, execdata, serror)) return false;

    // Scripts inside witness implicitly require cleanstack behaviour
    if (stack.size() != 1) return set_error(serror, SCRIPT_ERR_CLEANSTACK);
    if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}


extern uint256 to_uint256(const T_SHA256& hash);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

//HC: 验证etherum链上的交易
bool VerifyEthTx(const EthInPoint &ethinputpt, const std::vector<CTxIn> &vin, const std::vector<CTxOut> &vout)
{
    int n = vin[0].prevout.n;
    if (vout.size() > 2)
        return false;

    CTransaction pretx;
    if (!pretx.ReadFromDisk(vin[0].prevout)) {
        BOOST_THROW_EXCEPTION(hc::TransactionVinPrevoutNotExists() << hc::errinfo_comment(vin[0].prevout.ToString()));
        return false;
    }

    CAmount amount;
    //HC: 分析跨链交易的二个输出部分: 提取转入金额、检查找零输出的合法性
    for (CTxOut out : vout) {
        int witnessversion;
        std::vector<unsigned char> witnessprogram;
        if (!out.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        if (witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
            //HC: 跨链交易转入金额
            amount = out.nValue;
        }
        else if (witnessversion == 16 && witnessprogram.size() == WITNESS_CROSSCHAIN_SIZE) {
            //HC: 检查跨链找零部分，将作为下次跨链的输入
            CTxDestination address;
            if (!ExtractDestination(pretx.vout[n].scriptPubKey, address))
                return false;
            WitnessCrossChainHash witnessCC = boost::get<WitnessCrossChainHash>(address);
            witnessCC.recv_address = BaseHash<uint160>();
            witnessCC.sender_prikey = uint256();

            CTxDestination addressTxDest(witnessCC);
            CScript scriptChange = GetScriptForDestination(addressTxDest);
            if (scriptChange != out.scriptPubKey) {
                return false;
            }
        }
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    T_LOCALBLOCK localblock;
    T_LOCALBLOCKADDRESS addr;
    addr.set(ethinputpt.hid, ethinputpt.chainid, ethinputpt.localid);

    //HC: 读取交易所在子块
    if (hyperchainspace->GetLocalBlock(addr, localblock)) {
        auto chaintype = localblock.GetAppType();
        uint32_t genesishid;
        uint16 genesischainnum;
        uint16 genesislocalid;

        chaintype.get(genesishid, genesischainnum, genesislocalid);

        T_LOCALBLOCK genesislocalblock;
        T_LOCALBLOCKADDRESS genesisblkaddr;
        genesisblkaddr.set(genesishid, genesischainnum, genesislocalid);

        if (!hyperchainspace->GetLocalBlock(genesisblkaddr, genesislocalblock)) {
            throw hc::MissingHyperBlock();
        }

        //HC：验证Eth交易的合法性
        string strerr;
        string strAmount = StringFormat("%lld", amount);
        return AppPlugins::callFunction<bool>("aleth", 
                    "VerifyTx",
                    genesislocalblock.GetPayLoad(),
                    ethinputpt.eth_genesis_block_hash.GetHexNoReverse(),
                    localblock.GetPayLoad(),
                    ethinputpt.eth_tx_hash.GetHexNoReverse(),
                    ethinputpt.eth_tx_publickey.GetHexNoReverse(),
                    strAmount, strerr);

    } else {
        throw hc::MissingHyperBlock();
    }

    return false;
}

static bool VerifyWitnessProgram(const CScriptWitness& witness, int witversion, const std::vector<unsigned char>& program, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror, bool is_p2sh)
{
    CScript exec_script; //!< Actually executed script (last stack item in P2WSH; implied P2PKH script in P2WPKH; leaf script in P2TR)
    Span<const valtype> stack{ witness.stack };
    ScriptExecutionData execdata;

    if (witversion == 0) {
        if (program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            // BIP141 P2WSH: 32-byte witness v0 program (which encodes SHA256(script))
            if (stack.size() == 0) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
            }
            const valtype& script_bytes = SpanPopBack(stack);
            exec_script = CScript(script_bytes.begin(), script_bytes.end());
            //HCE: use Hash function
            uint256 hash_exec_script = Hash(exec_script.begin(), exec_script.end());
            //CSHA256().Write(&exec_script[0], exec_script.size()).Finalize(hash_exec_script.begin());
            if (memcmp(hash_exec_script.begin(), program.data(), 32)) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::WITNESS_V0, checker, execdata, serror);
        }
        else if (program.size() == WITNESS_V0_KEYHASH_SIZE) {
            // BIP141 P2WPKH: 20-byte witness v0 program (which encodes Hash160(pubkey))
            if (stack.size() != 2) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
            }
            exec_script << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::WITNESS_V0, checker, execdata, serror);
        }
        else {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
        }
    }
    else if (witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh) {
        // BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
        //HCE: future softfork compatibility
        return true;
    }
    else if (witversion == 16 && program.size() == WITNESS_CROSSCHAIN_SIZE) {
        if (stack.size() == 0) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
        }

        //HC: 扩展的跨链类型
        const valtype& script_bytes = SpanPopBack(stack);
        CScript scr(script_bytes.begin(), script_bytes.end());

        EthInPoint ethinputpoint;
        if (ExtractCrossChainInPoint(scr, ethinputpoint)) {
            //HC: 对跨链清算交易，验证Eth链上是否有这笔交易, 并且当前转入与Eth交易的转出金额是否一致
            string errinfo;
            try {
                const auto* che = dynamic_cast<const MutableTransactionSignatureChecker*>(&checker);
                if (che) {
                    auto* t = che->GetTxTo();
                    return VerifyEthTx(ethinputpoint, t->vin, t->vout);
                }

                const auto* cheT = dynamic_cast<const TransactionSignatureChecker*>(&checker);
                if (!cheT) {
                    cerr << "VerifyWitnessProgram: unknown checker " << endl;
                    return false;
                }
                auto* t = cheT->GetTxTo();
                return VerifyEthTx(ethinputpoint, t->vin, t->vout);

            } catch (hc::MissingHyperBlock&) {
                RSyncRemotePullHyperBlock(ethinputpoint.hid);
                errinfo = "MissingHyperBlock";
            } catch (hc::Exception& e) {
                auto err = boost::get_error_info<hc::errinfo_comment>(e);
                errinfo = StringFormat("%s: %s", e.what(), *err);
            }

            set_error(serror, SCRIPT_ERR_VERIFY_ETH_TX);
            cerr << "VerifyWitnessProgram: VerifyEthTx exception: " << errinfo << endl;
            return false;
        }
        else {
            //HC: to do
            //HC: 对跨链Para转出到Eth, 如何验证交易合法性呢？
            return true;
        }
    }
    else {
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
        }
        // Other version/size/p2sh combinations return true for future softfork compatibility
        return true;
    }
    // There is intentionally no return statement here, to be able to use "control reaches end of non-void function" warnings to detect gaps in the logic above.
}


bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    //static const CScriptWitness emptyWitness;
    //if (witness == nullptr) {
    //    witness = &emptyWitness;
    //}

    //ScriptError serror;
    //ScriptExecutionData execdata;
    //vector<vector<unsigned char> > stack;

    //unsigned int flags = 0;
    //CAmount amount(0);
    //PrecomputedTransactionData txdata(txTo);

    ////HCE: Here only support a kind of checker, maybe we need more types in the future
    //auto checker = TransactionSignatureChecker(&txTo, nIn, amount, txdata);
    //if (!EvalScript(stack, scriptSig, flags, checker, SigVersion::BASE, execdata, &serror))
    //    //if (!EvalScript(stack, scriptSig, txTo, nIn, nHashType))
    //    return false;
    //if (!EvalScript(stack, scriptPubKey, flags, checker, SigVersion::BASE, execdata, &serror))
    //    //if (!EvalScript(stack, scriptPubKey, txTo, nIn, nHashType))
    //    return false;
    //if (stack.empty())
    //    return false;
    //if (!CastToBool(stack.back()))
    //    return false;

    //bool hadWitness = false;

    static const CScriptWitness emptyWitness;
    if (witness == nullptr) {
        witness = &emptyWitness;
    }
    bool hadWitness = false;

    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    // scriptSig and scriptPubKey must be evaluated sequentially on the same stack
    // rather than being simply concatenated (see CVE-2010-5141)
    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, SigVersion::BASE, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, SigVersion::BASE, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Bare witness programs
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            hadWitness = true;
            if (scriptSig.size() != 0) {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return false;
            }
            if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror, /* is_p2sh */ false)) {
                return false;
            }
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.resize(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, SigVersion::BASE, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS) {
            if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
                hadWitness = true;
                if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
                if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror, /* is_p2sh */ true)) {
                    return false;
                }
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.resize(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS) {
        // We can't check for correct unexpected witness data if P2SH was off, so require
        // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        // possible, which is not a softfork.
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (!hadWitness && !witness->IsNull()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
    }

    return set_success(serror);
}


//HCE: a converter function
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    unsigned int flags = 0;
    CAmount amount(0);
    PrecomputedTransactionData txdata(txTo);

    auto checker = TransactionSignatureChecker(&txTo, nIn, amount, txdata);

    return VerifyScript(scriptSig, scriptPubKey, witness, flags, checker);

    //static const CScriptWitness emptyWitness;
    //if (witness == nullptr) {
    //    witness = &emptyWitness;
    //}

    //ScriptError serror;
    //ScriptExecutionData execdata;
    //vector<vector<unsigned char> > stack;

    //unsigned int flags = 0;
    //CAmount amount(0);
    //PrecomputedTransactionData txdata(txTo);

    ////HCE: Here only support a kind of checker, maybe we need more types in the future
    //auto checker = TransactionSignatureChecker(&txTo, nIn, amount, txdata);
    //if (!EvalScript(stack, scriptSig, flags, checker, SigVersion::BASE, execdata, &serror))
    ////if (!EvalScript(stack, scriptSig, txTo, nIn, nHashType))
    //    return false;
    //if (!EvalScript(stack, scriptPubKey, flags, checker, SigVersion::BASE, execdata, &serror))
    ////if (!EvalScript(stack, scriptPubKey, txTo, nIn, nHashType))
    //    return false;
    //if (stack.empty())
    //    return false;
    //if(!CastToBool(stack.back()))
    //    return false;

    //bool hadWitness = false;

    //// Bare witness programs
    //int witnessversion;
    //std::vector<unsigned char> witnessprogram;
    //if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    //    hadWitness = true;
    //    if (scriptSig.size() != 0) {
    //        // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
    //        return false;
    //    }
    //    flags = SCRIPT_VERIFY_WITNESS;
    //    if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, &serror, /* is_p2sh */ false)) {
    //        return false;
    //    }
    //    // Bypass the cleanstack check at the end. The actual stack is obviously not clean
    //    // for witness programs.
    //    stack.resize(1);
    //}
}

//bool SignSignature(const SigningProvider& provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType)
//{
//    assert(nIn < txTo.vin.size());
//
//    MutableTransactionSignatureCreator creator(&txTo, nIn, amount, nHashType);
//
//    SignatureData sigdata;
//    bool ret = ProduceSignature(provider, creator, fromPubKey, sigdata);
//    UpdateInput(txTo.vin.at(nIn), sigdata);
//    return ret;
//}

//HCE: here is core how to support witness,
//HCE: see SignTransaction in bitcoin source code
bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType, CScript scriptPrereq)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);

    if (!Solver(keystore, txout.scriptPubKey, hash, nHashType, txin.scriptSig))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // Test solution
    if (scriptPrereq.empty())
        if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, &txin.scriptWitness, txTo, nIn, 0))
            return false;

    return true;
}


bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, &txin.scriptWitness, txTo, nIn, nHashType))
        return false;

    return true;
}


//HCE: SegWit


/** A signature creator for transactions. */
class MutableTransactionSignatureCreator : public BaseSignatureCreator
{
    const CMutableTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const MutableTransactionSignatureChecker checker;

public:
    MutableTransactionSignatureCreator(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn = SIGHASH_ALL)
        : txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn) {}
    const BaseSignatureChecker& Checker() const override { return checker; }
    const CMutableTransaction* Tx() const { return txTo; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const override
    {
        //CKey key;
        CKey_Secp256k1 key;
        if (!provider.GetKey(address, key))
            return false;

        // Signing with uncompressed keys is disabled in witness scripts
        if (sigversion == SigVersion::WITNESS_V0 && !key.IsCompressed())
            return false;

        // Signing for witness scripts needs the amount.
        if (sigversion == SigVersion::WITNESS_V0 && amount < 0) return false;

        uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
        if (!key.Sign(hash, vchSig))
            return false;
        vchSig.push_back((unsigned char)nHashType);
        return true;
    }
};


/** A signature creator that just produces 71-byte empty signatures. */
extern const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR;
/** A signature creator that just produces 72-byte empty signatures. */
extern const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR;

typedef std::pair<CPubKey, std::vector<unsigned char>> SigPair;

// This struct contains information from a transaction input and also contains signatures for that input.
// The information contained here can be used to create a signature and is also filled by ProduceSignature
// in order to construct final scriptSigs and scriptWitnesses.
struct SignatureData
{
    bool complete = false; ///< Stores whether the scriptSig and scriptWitness are complete
    bool witness = false; ///< Stores whether the input this SigData corresponds to is a witness input
    CScript scriptSig; ///< The scriptSig of an input. Contains complete signatures or the traditional partial signatures format
    CScript redeem_script; ///< The redeemScript (if any) for the input
    CScript witness_script; ///< The witnessScript (if any) for the input. witnessScripts are used in P2WSH outputs.
    CScriptWitness scriptWitness; ///< The scriptWitness of an input. Contains complete signatures or the traditional partial signatures format. scriptWitness is part of a transaction input per BIP 144.
    std::map<CKeyID, SigPair> signatures; ///< BIP 174 style partial signatures for the input. May contain all signatures necessary for producing a final scriptSig or scriptWitness.
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> misc_pubkeys;
    std::vector<CKeyID> missing_pubkeys; ///< KeyIDs of pubkeys which could not be found
    std::vector<CKeyID> missing_sigs; ///< KeyIDs of pubkeys for signatures which could not be found
    uint160 missing_redeem_script; ///< ScriptID of the missing redeemScript (if any)
    uint256 missing_witness_script; ///< SHA256 of the missing witnessScript (if any)

    SignatureData() {}
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};


void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    }
    else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}


static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey list
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(keyid, std::make_pair(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    // Could not make signature or signature not found, add keyid to missing
    sigdata.missing_sigs.push_back(keyid);
    return false;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TxoutType::SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
    std::vector<valtype>& ret, TxoutType& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;

    //HC: 从脚本中提取公钥或者公钥hash或者其他，取决于具体的脚本类型
    //HC: 用于计算签名
    whichTypeRet = Solver(scriptPubKey, vSolutions);

    switch (whichTypeRet)     {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
        return false;
    case TxoutType::PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TxoutType::PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TxoutType::SCRIPTHASH:
        h160 = uint160(vSolutions[0]);
        if (GetCScript(provider, sigdata, CScriptID{ h160 }, scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        // Could not find redeemScript, add to missing
        sigdata.missing_redeem_script = h160;
        return false;

    case TxoutType::MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey(vSolutions[i]);
            // We need to always call CreateSig in order to fill sigdata with all
            // possible signatures that we can create. This will allow further PSBT
            // processing to work as it needs all possible signature and pubkey pairs
            if (CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                if (ret.size() < required + 1) {
                    ret.push_back(std::move(sig));
                }
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.push_back(valtype());
        }
        return ok;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TxoutType::WITNESS_V0_SCRIPTHASH:
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160.begin());
        if (GetCScript(provider, sigdata, CScriptID{ h160 }, scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        // Could not find witnessScript, add to missing
        sigdata.missing_witness_script = uint256(vSolutions[0]);
        return false;

    case TxoutType::WITNESS_CROSSCHAIN:
        //HC: 签名已经存在tx->fromscriptSig中，所以这里无需任何操作
        return true;

    default:
        return false;
    }
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        }
        else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        }
        else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        }
        else {
            result << v;
        }
    }
    return result;
}


static constexpr unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                        SCRIPT_VERIFY_DERSIG |
                        SCRIPT_VERIFY_STRICTENC |
                        SCRIPT_VERIFY_MINIMALDATA |
                        SCRIPT_VERIFY_NULLDUMMY |
                        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                        SCRIPT_VERIFY_CLEANSTACK |
                        SCRIPT_VERIFY_MINIMALIF |
                        SCRIPT_VERIFY_NULLFAIL |
                        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                        SCRIPT_VERIFY_LOW_S |
                        SCRIPT_VERIFY_WITNESS |
                        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                        SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                        SCRIPT_VERIFY_CONST_SCRIPTCODE |
                        SCRIPT_VERIFY_TAPROOT |
                        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
                        SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
                        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;

//HC: sigdata：返回的签名，其后通过UpdateInput函数赋值给交易的输入
bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    if (sigdata.complete) return true;

    std::vector<valtype> result;
    TxoutType whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;
    sigdata.scriptWitness.stack.clear();

    if (solved && whichType == TxoutType::SCRIPTHASH) {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        sigdata.redeem_script = subscript;
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TxoutType::SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TxoutType::WITNESS_V0_KEYHASH) {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata);
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V0_SCRIPTHASH) {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata) && subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH && subType != TxoutType::WITNESS_V0_KEYHASH;
        result.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_CROSSCHAIN) {
        //HC: 本交易所用的输入交易为跨链交易
        const MutableTransactionSignatureCreator* mutabletxcreator
            = reinterpret_cast<const MutableTransactionSignatureCreator*>(&creator);
        const CMutableTransaction* tx = mutabletxcreator->Tx();

        result.push_back(std::vector<unsigned char>(tx->fromscriptSig.begin(), tx->fromscriptSig.end()));
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_UNKNOWN) {
        sigdata.witness = true;
    }

    if (P2SH) {
        result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
    return sigdata.complete;
}


namespace {
    class SignatureExtractorChecker final : public BaseSignatureChecker
    {
    private:
        SignatureData& sigdata;
        BaseSignatureChecker& checker;

    public:
        SignatureExtractorChecker(SignatureData& sigdata, BaseSignatureChecker& checker) : sigdata(sigdata), checker(checker) {}
        bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
        {
            if (checker.CheckECDSASignature(scriptSig, vchPubKey, scriptCode, sigversion)) {
                CPubKey pubkey(vchPubKey);
                sigdata.signatures.emplace(pubkey.GetID(), SigPair(pubkey, scriptSig));
                return true;
            }
            return false;
        }
    };

    struct Stacks
    {
        std::vector<valtype> script;
        std::vector<valtype> witness;

        Stacks() = delete;
        Stacks(const Stacks&) = delete;
        explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack)
        {
            EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
        }
    };
}

// Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    Stacks stack(data);

    // Get signatures
    MutableTransactionSignatureChecker tx_checker(&tx, nIn, txout.nValue);
    SignatureExtractorChecker extractor_checker(data, tx_checker);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(txout.scriptPubKey, solutions);
    SigVersion sigversion = SigVersion::BASE;
    CScript next_script = txout.scriptPubKey;

    if (script_type == TxoutType::SCRIPTHASH && !stack.script.empty() && !stack.script.back().empty()) {
        // Get the redeemScript
        CScript redeem_script(stack.script.back().begin(), stack.script.back().end());
        data.redeem_script = redeem_script;
        next_script = std::move(redeem_script);

        // Get redeemScript type
        script_type = Solver(next_script, solutions);
        stack.script.pop_back();
    }
    if (script_type == TxoutType::WITNESS_V0_SCRIPTHASH && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V0;
    }
    if (script_type == TxoutType::MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size() - 2;
        unsigned int last_success_key = 0;
        for (const valtype& sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype& pubkey = solutions[i + 1];
                // We either have a signature for this pubkey, or we have found a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) || extractor_checker.CheckECDSASignature(sig, pubkey, next_script, sigversion)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

namespace {
    /** Dummy signature checker which accepts all signatures. */
    class DummySignatureChecker final : public BaseSignatureChecker
    {
    public:
        DummySignatureChecker() {}
        bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return true; }
    };
    const DummySignatureChecker DUMMY_CHECKER;

    class DummySignatureCreator final : public BaseSignatureCreator {
    private:
        char m_r_len = 32;
        char m_s_len = 32;
    public:
        DummySignatureCreator(char r_len, char s_len) : m_r_len(r_len), m_s_len(s_len) {}
        const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
        bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override
        {
            // Create a dummy signature that is a valid DER-encoding
            vchSig.assign(m_r_len + m_s_len + 7, '\000');
            vchSig[0] = 0x30;
            vchSig[1] = m_r_len + m_s_len + 4;
            vchSig[2] = 0x02;
            vchSig[3] = m_r_len;
            vchSig[4] = 0x01;
            vchSig[4 + m_r_len] = 0x02;
            vchSig[5 + m_r_len] = m_s_len;
            vchSig[6 + m_r_len] = 0x01;
            vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL;
            return true;
        }
    };

}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(32, 32);
const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(33, 32);

bool IsSolvable(const SigningProvider& provider, const CScript& script)
{
    // This check is to make sure that the script we created can actually be solved for and signed by us
    // if we were to have the private keys. This is just to make sure that the script is valid and that,
    // if found in a transaction, we would still accept and relay that transaction. In particular,
    // it will reject witness outputs that require signing with an uncompressed public key.
    SignatureData sigs;
    // Make sure that STANDARD_SCRIPT_VERIFY_FLAGS includes SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, the most
    // important property this function is designed to test for.
    static_assert(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, "IsSolvable requires standard script flags to include WITNESS_PUBKEYTYPE");
    if (ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, script, sigs)) {
        // VerifyScript check is just defensive, and should never fail.
        bool verified = VerifyScript(sigs.scriptSig, script, &sigs.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, DUMMY_CHECKER);
        assert(verified);
        return true;
    }
    return false;
}

bool IsSegWitOutput(const SigningProvider& provider, const CScript& script)
{
    std::vector<valtype> solutions;
    auto whichtype = Solver(script, solutions);
    if (whichtype == TxoutType::WITNESS_V0_SCRIPTHASH || whichtype == TxoutType::WITNESS_V0_KEYHASH || whichtype == TxoutType::WITNESS_UNKNOWN) return true;
    if (whichtype == TxoutType::SCRIPTHASH) {
        auto h160 = uint160(solutions[0]);
        CScript subscript;
        if (provider.GetCScript(CScriptID{ h160 }, subscript)) {
            whichtype = Solver(subscript, solutions);
            if (whichtype == TxoutType::WITNESS_V0_SCRIPTHASH || whichtype == TxoutType::WITNESS_V0_KEYHASH || whichtype == TxoutType::WITNESS_UNKNOWN) return true;
        }
    }
    return false;
}

//HCE: how to convert CTransaction to CMutableTransaction
//HCE: see static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, std::string>& input_errors)
{
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);
    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = "Input not found or already spent";
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;

        SignatureData sigdata = DataFromTransaction(mtx, i, coin->second.out);
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.vout.size())) {
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(&mtx, i, amount, nHashType), prevPubKey, sigdata);
        }

        UpdateInput(txin, sigdata);

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = "Missing amount";
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = "Unable to sign input, invalid stack size (possibly missing key)";
            }
            else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = "CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)";
            }
            else {
                input_errors[i] = ScriptErrorString(serror);
            }
        }
        else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
    }
    return input_errors.empty();
}



void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
}

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    ScriptExecutionData execdata;
    return EvalScript(stack, script, flags, checker, sigversion, execdata, serror);
}


const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")},
};


std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            }
            else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        const auto it = mapSigHashTypes.find(chSigHashType);
                        if (it != mapSigHashTypes.end()) {
                            strSigHashDecode = "[" + it->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                }
                else {
                    str += HexStr(vch);
                }
            }
        }
        else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

