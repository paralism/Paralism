// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "keyorigin.h"
#include "outputtype.h"
#include <scriptpubkeyman.h>
#include "key_io.h"

//! Value for the first BIP 32 hardened derivation. Can be used as a bit mask and as a value. See BIP 32 for more details.
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

extern bool IsSolvable(const SigningProvider& provider, const CScript& script);

bool LegacyScriptPubKeyMan::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        //WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}
bool LegacyScriptPubKeyMan::TopUp(unsigned int kpSize)
{
    UNUSED(kpSize);
    if (!m_pwallet->IsLocked())
        m_pwallet->TopUpKeyPool();
    return true;
}


uint256 LegacyScriptPubKeyMan::GetID() const
{
    return uint256::ONE;
}


bool LegacyScriptPubKeyMan::GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    CBitcoinAddress bitcoinaddr;
    bitcoinaddr.SetHash160(address);
    std::vector<unsigned char> vchPubKey;
    bool ret = m_pwallet->GetPubKey(bitcoinaddr, vchPubKey);
    if (ret) {
        vchPubKeyOut = CPubKey(vchPubKey);
    }
    return ret;

}

//HCE: see reference to Bitcoin: LegacyScriptPubKeyMan::ImportScripts(const std::set<CScript> scripts, int64_t timestamp)
void LegacyScriptPubKeyMan::ImportScripts(const CPubKey& pubKey, const CKey& key)
{
    //CPubKey new_key = CPubKey::NewPubKeyCompressed(key.GetPubKey());
    OutputType type = OutputType::LEGACY;
    if (pubKey.IsCompressed()) {
        type = DEFAULT_ADDRESS_TYPE;
    }
    LearnRelatedScripts(pubKey, type);
}

bool LegacyScriptPubKeyMan::GetNewDestination(const OutputType type,
    std::vector<unsigned char> & vecPubKey,
    CTxDestination& dest, std::string& error)
{
    LOCK(cs_KeyStore);
    error.clear();

    // Generate a new key that is added to wallet
    std::vector<unsigned char> vctKey;
    if (!m_pwallet->GetKeyFromPool(vctKey, false)) {
        //error = _("Error: Keypool ran out, please call keypoolrefill first").translated;
        error = "Error: Keypool ran out, please call keypoolrefill first";
        return false;
    }

    bool fcompressed = (type == OutputType::LEGACY ? false : true);
    CPubKey new_key = CPubKey::NewPubKey(vctKey, fcompressed);

    vecPubKey.clear();
    vecPubKey.insert(vecPubKey.end(), new_key.begin(), new_key.end());

    //HCE: By default, only compressed public key has been put into wallet.
    if (!HaveKey(new_key.GetID())) {
        CPubKey another_key = CPubKey::NewPubKey(vctKey, !fcompressed);
        CKey keyOut;
        if (!m_pwallet->GetKey(another_key.GetID(), keyOut)) {
            return false;
        }
        m_pwallet->AddKey(vecPubKey, keyOut);
    }

    LearnRelatedScripts(new_key, type);
    dest = GetDestinationForKey(new_key, type);
    if (!IsValidDestination(dest)) {
        return false;
    }

    return true;
}

typedef std::vector<unsigned char> valtype;

namespace {

    /**
     * This is an enum that tracks the execution context of a script, similar to
     * SigVersion in script/interpreter. It is separate however because we want to
     * distinguish between top-level scriptPubKey execution and P2SH redeemScript
     * execution (a distinction that has no impact on consensus rules).
     */
    enum class IsMineSigVersion
    {
        TOP = 0,        //!< scriptPubKey execution
        P2SH = 1,       //!< P2SH redeemScript
        WITNESS_V0 = 2, //!< P2WSH witness script execution
    };

    /**
     * This is an internal representation of isminetype + invalidity.
     * Its order is significant, as we return the max of all explored
     * possibilities.
     */
    enum class IsMineResult
    {
        NO = 0,         //!< Not ours
        WATCH_ONLY = 1, //!< Included in watch-only balance
        SPENDABLE = 2,  //!< Included in all balances
        INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
    };

    bool PermitsUncompressed(IsMineSigVersion sigversion)
    {
        return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
    }

    bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyScriptPubKeyMan& keystore)
    {
        for (const valtype& pubkey : pubkeys) {
            CKeyID keyID = CPubKey(pubkey).GetID();
            if (!keystore.HaveKey(keyID)) return false;
        }
        return true;
    }

    //! Recursively solve script and return spendable/watchonly/invalid status.
    //!
    //! @param keystore            legacy key and script store
    //! @param script              script to solve
    //! @param sigversion          script type (top-level / redeemscript / witnessscript)
    //! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
    //!                            scripts or simply treat any script that has been
    //!                            stored in the keystore as spendable
    IsMineResult IsMineInner(const LegacyScriptPubKeyMan& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash = true)
    {
        IsMineResult ret = IsMineResult::NO;

        std::vector<valtype> vSolutions;
        TxoutType whichType = Solver(scriptPubKey, vSolutions);

        CKeyID keyID;
        switch (whichType)
        {
        case TxoutType::NONSTANDARD:
        case TxoutType::NULL_DATA:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
            break;
        case TxoutType::PUBKEY:
            keyID = CPubKey(vSolutions[0]).GetID();
            if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
                return IsMineResult::INVALID;
            }
            if (keystore.HaveKey(keyID)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        case TxoutType::WITNESS_V0_KEYHASH:
        {
            if (sigversion == IsMineSigVersion::WITNESS_V0) {
                // P2WPKH inside P2WSH is invalid.
                return IsMineResult::INVALID;
            }
            if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
                // We do not support bare witness outputs unless the P2SH version of it would be
                // acceptable as well. This protects against matching before segwit activates.
                // This also applies to the P2WSH case.
                break;
            }
            ret = std::max(ret, IsMineInner(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
            break;
        }
        case TxoutType::PUBKEYHASH:
            keyID = CKeyID(uint160(vSolutions[0]));
            if (!PermitsUncompressed(sigversion)) {
                CPubKey pubkey;
                if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                    return IsMineResult::INVALID;
                }
            }
            if (keystore.HaveKey(keyID)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        case TxoutType::SCRIPTHASH:
        {
            if (sigversion != IsMineSigVersion::TOP) {
                // P2SH inside P2WSH or P2SH is invalid.
                return IsMineResult::INVALID;
            }
            CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
            CScript subscript;
            if (keystore.GetCScript(scriptID, subscript)) {
                ret = std::max(ret, recurse_scripthash ? IsMineInner(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
            }
            break;
        }
        case TxoutType::WITNESS_V0_SCRIPTHASH:
        {
            if (sigversion == IsMineSigVersion::WITNESS_V0) {
                // P2WSH inside P2WSH is invalid.
                return IsMineResult::INVALID;
            }
            if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
                break;
            }
            uint160 hash;
            CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(hash.begin());
            CScriptID scriptID = CScriptID(hash);
            CScript subscript;
            if (keystore.GetCScript(scriptID, subscript)) {
                ret = std::max(ret, recurse_scripthash ? IsMineInner(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
            }
            break;
        }

        case TxoutType::MULTISIG:
        {
            // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
            if (sigversion == IsMineSigVersion::TOP) {
                break;
            }

            // Only consider transactions "mine" if we own ALL the
            // keys involved. Multi-signature transactions that are
            // partially owned (somebody else has a key that can spend
            // them) enable spend-out-from-under-you attacks, especially
            // in shared-wallet situations.
            std::vector<valtype> keys(vSolutions.begin() + 1, vSolutions.begin() + vSolutions.size() - 1);
            if (!PermitsUncompressed(sigversion)) {
                for (size_t i = 0; i < keys.size(); i++) {
                    if (keys[i].size() != 33) {
                        return IsMineResult::INVALID;
                    }
                }
            }
            if (HaveKeys(keys, keystore)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        }
        }

        //HCE: watch not support
        //if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        //    ret = std::max(ret, IsMineResult::WATCH_ONLY);
        //}
        return ret;
    }

} // namespace

bool LegacyScriptPubKeyMan::IsMine(const CScript& script) const
{
    switch (IsMineInner(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return false;
    case IsMineResult::WATCH_ONLY:
        return false;
    case IsMineResult::SPENDABLE:
        return true;
    }
    assert(false);
}

void LegacyScriptPubKeyMan::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    if (key.IsCompressed() && (type == OutputType::P2SH_SEGWIT || type == OutputType::BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        assert(IsSolvable(*this, witprog));
        AddCScript(witprog);
    }
}

bool LegacyScriptPubKeyMan::AddCScript(const CScript& redeemScript)
{
    return AddCScriptWithDB(redeemScript);
}

bool LegacyScriptPubKeyMan::AddCScriptWithDB(const CScript& redeemScript)
{
    if (!FillableSigningProvider::AddCScript(redeemScript))
        return false;

    if (m_pwallet->WriteCScript(Hash160(redeemScript), redeemScript)) {
        return true;
    }
    return false;
}


extern
bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, std::string>& input_errors);

bool LegacyScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, std::string>& input_errors) const
{
    return ::SignTransaction(tx, this, coins, sighash, input_errors);
}

bool LegacyScriptPubKeyMan::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    //HCE: we use a simple way, to bitcoin use creation time of the key as fingerprint, see LegacyScriptPubKeyMan::GenerateNewKey
    std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    return true;

    //CKeyMetadata meta;
    //{
    //    LOCK(cs_KeyStore);
    //    auto it = mapKeyMetadata.find(keyID);
    //    if (it != mapKeyMetadata.end()) {
    //        meta = it->second;
    //    }
    //}
    //if (meta.has_key_origin) {
    //    std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
    //    info.path = meta.key_origin.path;
    //}
    //else { // Single pubkeys get the master fingerprint of themselves
    //    std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    //}
    //return true;
}

bool LegacyScriptPubKeyMan::GetKey(const CKeyID& address, CKey_Secp256k1& keyOut) const
{
    //HCE: for old version, format of keys in the wallet is type of CKey
    //HCE: but to witness functionality, it is CKey_Secp256k1,
    //HCE: so here we need convert key object from type CKey into CKey_Secp256k1
    //HCE: In fact, class 'CKey_Secp256k1' is taken from the 'CKey' of latest source code of Bitcoin
    CBitcoinAddress bitcoinaddr;
    bitcoinaddr.SetHash160(address);
    CKey key;
    bool ret = m_pwallet->GetKey(bitcoinaddr, key);
    if (ret) {
        CPrivKey pri = key.GetPrivKey();
        std::vector<unsigned char> vchPubKeyOut;

        CPubKey pub;
        if (!GetPubKey(address, pub)) {
            return false;
        }
        ret = keyOut.Load(pri, pub, false);
    }
    return ret;

    //LOCK(cs_KeyStore);
    //if (!m_storage.HasEncryptionKeys()) {
    //    return FillableSigningProvider::GetKey(address, keyOut);
    //}

    //CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    //if (mi != mapCryptedKeys.end())
    //{
    //    const CPubKey& vchPubKey = (*mi).second.first;
    //    const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
    //    return DecryptKey(m_storage.GetEncryptionKey(), vchCryptedSecret, vchPubKey, keyOut);
    //}
    //return false;
}

bool LegacyScriptPubKeyMan::HaveKey(const CKeyID& address) const
{
    CBitcoinAddress bitcoinaddr;
    bitcoinaddr.SetHash160(address);

    bool ret = m_pwallet->HaveKey(bitcoinaddr);
    return ret;
}

