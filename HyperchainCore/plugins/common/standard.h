// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include <uint256.h>

#include <boost/mpl/find.hpp>
#include <boost/variant.hpp>

#include <string>


static const bool DEFAULT_ACCEPT_DATACARRIER = true;

/** Script verification flags.
 *
 *  All flags are intended to be soft forks: the set of acceptable scripts under
 *  flags (A | B) is a subset of the acceptable scripts under flag (A).
 */
enum
{
    SCRIPT_VERIFY_NONE = 0,

    // Evaluate P2SH subscripts (BIP16).
    SCRIPT_VERIFY_P2SH = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    // NOPs that have associated forks to give them new meaning (CLTV, CSV)
    // are not subject to this rule.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    // Note: WITNESS_V0 and TAPSCRIPT script execution have behavior similar to CLEANSTACK as part of their
    //       consensus rules. It is automatic there and does not need this flag.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS = (1U << 11),

    // Making v1-v16 witness program non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    // Note: TAPSCRIPT script execution has behavior similar to MINIMALIF as part of its consensus
    //       rules. It is automatic there and does not depend on this flag.
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in segregated witness scripts must be compressed
    //
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),

    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    //
    SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 16),

    // Taproot/Tapscript validation (BIPs 341 & 342)
    //
    SCRIPT_VERIFY_TAPROOT = (1U << 17),

    // Making unknown Taproot leaf versions non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1U << 18),

    // Making unknown OP_SUCCESS non-standard
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = (1U << 19),

    // Making unknown public key versions (in BIP 342 scripts) non-standard
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1U << 20),
};


class CKeyID;
class CScript;
struct ScriptHash;


template<typename HashType>
class BaseHash
{
protected:
    HashType m_hash;

public:
    BaseHash() : m_hash() {}
    explicit BaseHash(const HashType& in) : m_hash(in) {}

    unsigned char* begin()
    {
        return m_hash.begin();
    }

    const unsigned char* begin() const
    {
        return m_hash.begin();
    }

    unsigned char* end()
    {
        return m_hash.end();
    }

    const unsigned char* end() const
    {
        return m_hash.end();
    }

    operator std::vector<unsigned char>() const
    {
        return std::vector<unsigned char>{m_hash.begin(), m_hash.end()};
    }

    std::string ToString() const
    {
        return m_hash.ToString();
    }

    bool operator==(const BaseHash<HashType>& other) const noexcept
    {
        return m_hash == other.m_hash;
    }

    bool operator!=(const BaseHash<HashType>& other) const noexcept
    {
        return !(m_hash == other.m_hash);
    }

    bool operator<(const BaseHash<HashType>& other) const noexcept
    {
        return m_hash < other.m_hash;
    }

    size_t size() const
    {
        return m_hash.size();
    }

    unsigned char* data() { return m_hash.data(); }
    const unsigned char* data() const { return m_hash.data(); }
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public BaseHash<uint160>
{
public:
    CScriptID() : BaseHash() {}
    explicit CScriptID(const CScript& in);
    explicit CScriptID(const uint160& in) : BaseHash(in) {}
    explicit CScriptID(const ScriptHash& in);
};

/**
 * Default setting for nMaxDatacarrierBytes. 80 bytes of data, +1 for OP_RETURN,
 * +2 for the pushdata opcodes.
 */
static const unsigned int MAX_OP_RETURN_RELAY = 83;

/**
 * A data carrying output is an unspendable output containing data. The script
 * type is designated as TxoutType::NULL_DATA.
 */
extern bool fAcceptDatacarrier;

/** Maximum size of TxoutType::NULL_DATA scripts that this node considers standard. */
extern unsigned nMaxDatacarrierBytes;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputScripts() for
 * details.
 */
static const unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

enum class TxoutType {
    NONSTANDARD,
    // 'standard' transaction types:
    PUBKEY,
    PUBKEYHASH,
    SCRIPTHASH,
    MULTISIG,
    NULL_DATA, //!< unspendable OP_RETURN script that carries data
    WITNESS_V0_SCRIPTHASH,
    WITNESS_V0_KEYHASH,
    WITNESS_V1_TAPROOT,
    WITNESS_CROSSCHAIN_IMMABLE,
    WITNESS_CROSSCHAIN,
    WITNESS_UNKNOWN, //!< Only for Witness versions not already defined above
};

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

struct PKHash : public BaseHash<uint160>
{
    PKHash() : BaseHash() {}
    explicit PKHash(const uint160& hash) : BaseHash(hash) {}
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};


CKeyID ToKeyID(const PKHash& key_hash);

struct ImmutableWitnessCrossChainHash {
    static unsigned int version; //HCE: Using maximum value 16 for Witness, more see 'EncodeOP_N'

    uint32_t genesis_hid = 0;          //HCE: hyper block id where genesis block in local block is located
    uint16_t genesis_chainid = 0;
    uint16_t genesis_localid = 0;
    BaseHash<uint160> hhash;                //HCE: the last 20 bytes of hyper block hash

    BaseHash<uint160> genesis_block_hash;   //HCE: Hash of genesis block of target local chain

    vector<unsigned char> serialize() const;
    void unserialize(vector<unsigned char> scrptdata);

    static int size() {
        //serialize length: 50
        //hhash: 20 + 1
        //genesis_block_hash: 20 + 1
        return sizeof(uint32_t) + 2 * sizeof(uint16_t) +  20 + 1 + 20 + 1;
    }

    friend bool operator==(const ImmutableWitnessCrossChainHash& w1, const ImmutableWitnessCrossChainHash& w2) {
        if (w1.version != w2.version) return false;
        if (w1.genesis_hid != w2.genesis_hid || w1.genesis_chainid != w2.genesis_chainid 
            || w1.genesis_localid != w2.genesis_localid
            || w1.hhash != w2.hhash || w1.genesis_block_hash != w2.genesis_block_hash
            ) {
            return false;
        }
        return true;
    }

    friend bool operator<(const ImmutableWitnessCrossChainHash& w1, const ImmutableWitnessCrossChainHash& w2) {
        if (w1.version < w2.version) return true;
        if (w1.version > w2.version) return false;

        if (w1.genesis_hid < w2.genesis_hid)  return true;
        if (w2.genesis_hid < w1.genesis_hid)  return false;

        if (w1.genesis_chainid < w2.genesis_chainid)  return true;
        if (w2.genesis_chainid < w1.genesis_chainid)  return false;

        if (w1.genesis_localid < w2.genesis_localid)  return true;
        if (w2.genesis_localid < w1.genesis_localid)  return false;

        bool rc = std::lexicographical_compare(w1.hhash.begin(), w1.hhash.end(), w2.hhash.begin(), w2.hhash.end());
        if (rc)  return true;

        rc = std::lexicographical_compare(w2.hhash.begin(), w2.hhash.end(), w1.hhash.begin(), w1.hhash.end());
        if (rc)  return false;

        rc = std::lexicographical_compare(w1.genesis_block_hash.begin(), w1.genesis_block_hash.end(), w2.genesis_block_hash.begin(), w2.genesis_block_hash.end());
        if (rc)  return true;

        rc = std::lexicographical_compare(w2.genesis_block_hash.begin(), w2.genesis_block_hash.end(), w1.genesis_block_hash.begin(), w1.genesis_block_hash.end());
        if (rc)  return false;
    }

};

struct WitnessCrossChainHash : public ImmutableWitnessCrossChainHash {
    BaseHash<uint160> recv_address;         //HCE: A receiving address of target local chain

    uint256 sender_prikey;                  //HCE: Private key of sender of target transaction

    WitnessCrossChainHash() {};
    WitnessCrossChainHash(ImmutableWitnessCrossChainHash && immwcch) :
        ImmutableWitnessCrossChainHash(std::forward<ImmutableWitnessCrossChainHash>(immwcch))
    { }

    vector<unsigned char> serialize() const;
    void unserialize(vector<unsigned char> scrptdata);

    static int size() {
        //serialize length (104) is equal to the following three parts:
        //ImmutableWitnessCrossChainHash : 50
        //recv_address: 20 + 1
        //sender_prikey: 32 + 1
        return ImmutableWitnessCrossChainHash::size() + 20 + 1 + 32 + 1;
    }

    friend bool operator==(const WitnessCrossChainHash& w1, const WitnessCrossChainHash& w2) {

        if ((ImmutableWitnessCrossChainHash)w1 == (ImmutableWitnessCrossChainHash)w2) {
            if (w1.recv_address == w2.recv_address
                && w1.sender_prikey == w2.sender_prikey) {
                return true;
            }
        }
        return false;
    }

    friend bool operator<(const WitnessCrossChainHash& w1, const WitnessCrossChainHash& w2) {

        if ((ImmutableWitnessCrossChainHash)w1 < (ImmutableWitnessCrossChainHash)w2) {

            bool rc = std::lexicographical_compare(w1.recv_address.begin(), w1.recv_address.end(), w2.recv_address.begin(), w2.recv_address.end());
            if (rc)  return true;

            rc = std::lexicographical_compare(w2.recv_address.begin(), w2.recv_address.end(), w1.recv_address.begin(), w1.recv_address.end());
            if (rc)  return false;

            rc = std::lexicographical_compare(w1.sender_prikey.begin(), w1.sender_prikey.end(), w2.sender_prikey.begin(), w2.sender_prikey.end());
            if (rc)  return true;

            rc = std::lexicographical_compare(w2.sender_prikey.begin(), w2.sender_prikey.end(), w1.sender_prikey.begin(), w1.sender_prikey.end());
            if (rc)  return false;
        }
        return false;
    }
};


struct WitnessV0KeyHash;
struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};

struct WitnessV0ScriptHash : public BaseHash<uint256>
{
    WitnessV0ScriptHash() : BaseHash() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV0ScriptHash(const CScript& script);
};

struct WitnessV0KeyHash : public BaseHash<uint160>
{
    WitnessV0KeyHash() : BaseHash() {}
    explicit WitnessV0KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
    explicit WitnessV0KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash);

//! CTxDestination subtype to encode any future Witness version
struct WitnessUnknown
{
    unsigned int version;
    unsigned int length;
    unsigned char program[40];

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.version != w2.version) return false;
        if (w1.length != w2.length) return false;
        return std::equal(w1.program, w1.program + w1.length, w2.program);
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.version < w2.version) return true;
        if (w1.version > w2.version) return false;
        if (w1.length < w2.length) return true;
        if (w1.length > w2.length) return false;
        return std::lexicographical_compare(w1.program, w1.program + w1.length, w2.program, w2.program + w2.length);
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH)
 *  * WitnessCrossChain: TxoutType::WITNESS_V16_KEYHASH destination (P2WPKH), cross chain transaction
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN/WITNESS_V1_TAPROOT destination (P2W???)
 *    (taproot outputs do not require their own type as long as no wallet support exists)
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
typedef boost::variant<CNoDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash,
    ImmutableWitnessCrossChainHash,
    WitnessCrossChainHash, WitnessUnknown> CTxDestination;

template <class Which>
int TxDestinationIndex()
{
    size_t pos = boost::mpl::distance
        <typename boost::mpl::begin<typename CTxDestination::types>::type,
        typename boost::mpl::find<typename CTxDestination::types, Which>::type
        >::type::value;

    size_t last = boost::mpl::distance
        <typename boost::mpl::begin<typename CTxDestination::types>::type,
        typename boost::mpl::end<typename CTxDestination::types>::type
        >::type::value;

    return pos != last ? pos : -1;
}

/** Check whether a CTxDestination is a CNoDestination. */
bool IsValidDestination(const CTxDestination& dest);


/** Get the name of a TxoutType as a string */
std::string GetTxnOutputType(TxoutType t);

/**
 * Parse a scriptPubKey and identify script type for standard scripts. If
 * successful, returns script type and parsed pubkeys or hashes, depending on
 * the type. For example, for a P2SH script, vSolutionsRet will contain the
 * script hash, for P2PKH it will contain the key hash, etc.
 *
 * @param[in]   scriptPubKey   Script to parse
 * @param[out]  vSolutionsRet  Vector of parsed pubkeys and hashes
 * @return                     The script type. TxoutType::NONSTANDARD represents a failed solve.
 */
TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet);

/**
 * Parse a standard scriptPubKey for the destination address. Assigns result to
 * the addressRet parameter and returns true if successful. For multisig
 * scripts, instead use ExtractDestinations. Currently only works for P2PK,
 * P2PKH, P2SH, P2WPKH, and P2WSH scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Parse a standard scriptPubKey with one or more destination addresses. For
 * multisig scripts, this populates the addressRet vector with the pubkey IDs
 * and nRequiredRet with the n required to spend. For other destinations,
 * addressRet is populated with a single value and nRequiredRet is set to 1.
 * Returns true if successful.
 *
 * Note: this function confuses destinations (a subset of CScripts that are
 * encodable as an address) with key identifiers (of keys involved in a
 * CScript), and its use should be phased out.
 */
bool ExtractDestinations(const CScript& scriptPubKey, TxoutType& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet);

/**
 * Generate a Bitcoin scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

/** Generate a P2PK script for the given pubkey. */
CScript GetScriptForRawPubKey(const CPubKey& pubkey);

/** Generate a multisig script. */
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);

struct EthInPoint {
    uint256 eth_tx_hash;
    base_uint<512> eth_tx_publickey;

    uint32_t hid;
    uint16_t chainid;
    uint16_t localid;
    uint256 eth_genesis_block_hash;
};

bool ExtractCrossChainInPoint(const CScript& scriptSig, EthInPoint& ethinputpoint);


#endif // BITCOIN_SCRIPT_STANDARD_H
