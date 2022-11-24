// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_SCRIPTPUBKEYMAN_H

#include "block.h"
#include <signingprovider.h>
#include <standard.h>
#include <boost/signals2/signal.hpp>

#include <unordered_map>

enum class OutputType;
struct bilingual_str;

//! Default for -keypool
static const unsigned int DEFAULT_KEYPOOL_SIZE = 1000;


/** A key from a CWallet's keypool
 *
 * The wallet holds one (for pre HD-split wallets) or several keypools. These
 * are sets of keys that have not yet been used to provide addresses or receive
 * change.
 *
 * The Bitcoin Core wallet was originally a collection of unrelated private
 * keys with their associated addresses. If a non-HD wallet generated a
 * key/address, gave that address out and then restored a backup from before
 * that key's generation, then any funds sent to that address would be
 * lost definitively.
 *
 * The keypool was implemented to avoid this scenario (commit: 10384941). The
 * wallet would generate a set of keys (100 by default). When a new public key
 * was required, either to give out as an address or to use in a change output,
 * it would be drawn from the keypool. The keypool would then be topped up to
 * maintain 100 keys. This ensured that as long as the wallet hadn't used more
 * than 100 keys since the previous backup, all funds would be safe, since a
 * restored wallet would be able to scan for all owned addresses.
 *
 * A keypool also allowed encrypted wallets to give out addresses without
 * having to be decrypted to generate a new private key.
 *
 * With the introduction of HD wallets (commit: f1902510), the keypool
 * essentially became an address look-ahead pool. Restoring old backups can no
 * longer definitively lose funds as long as the addresses used were from the
 * wallet's HD seed (since all private keys can be rederived from the seed).
 * However, if many addresses were used since the backup, then the wallet may
 * not know how far ahead in the HD chain to look for its addresses. The
 * keypool is used to implement a 'gap limit'. The keypool maintains a set of
 * keys (by default 1000) ahead of the last used key and scans for the
 * addresses of those keys.  This avoids the risk of not seeing transactions
 * involving the wallet's addresses, or of re-using the same address.
 * In the unlikely case where none of the addresses in the `gap limit` are
 * used on-chain, the look-ahead will not be incremented to keep
 * a constant size and addresses beyond this range will not be detected by an
 * old backup. For this reason, it is not recommended to decrease keypool size
 * lower than default value.
 *
 * The HD-split wallet feature added a second keypool (commit: 02592f4c). There
 * is an external keypool (for addresses to hand out) and an internal keypool
 * (for change addresses).
 *
 * Keypool keys are stored in the wallet/keystore's keymap. The keypool data is
 * stored as sets of indexes in the wallet (setInternalKeyPool,
 * setExternalKeyPool and set_pre_split_keypool), and a map from the key to the
 * index (m_pool_key_to_index). The CKeyPool object is used to
 * serialize/deserialize the pool data to/from the database.
 */

 /*
  * A class implementing ScriptPubKeyMan manages some (or all) scriptPubKeys used in a wallet.
  * It contains the scripts and keys related to the scriptPubKeys it manages.
  * A ScriptPubKeyMan will be able to give out scriptPubKeys to be used, as well as marking
  * when a scriptPubKey has been used. It also handles when and how to store a scriptPubKey
  * and its related scripts and keys, including encryption.
  */
class ScriptPubKeyMan
{
protected:
    CWallet* m_pwallet;

public:
    explicit ScriptPubKeyMan(CWallet* pwallet) : m_pwallet(pwallet) {}
    virtual ~ScriptPubKeyMan() {};

    virtual bool GetNewDestination(const OutputType type, std::vector<unsigned char>& vecPubKey, CTxDestination& dest, std::string& error) { return false; }
    virtual bool IsMine(const CScript& script) const { return false; }



    /** Creates new signatures and adds them to the transaction. Returns whether all inputs were signed */
    virtual bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, std::string>& input_errors) const { return false; }

    /** Fills internal address pool. Use within ScriptPubKeyMan implementations should be used sparingly and only
      * when something from the address pool is removed, excluding GetNewDestination and GetReservedDestination.
      * External wallet code is primarily responsible for topping up prior to fetching new addresses
      */
    virtual bool TopUp(unsigned int size = 0) { return false; }

    virtual uint256 GetID() const { return uint256(); }

};

class LegacyScriptPubKeyMan : public ScriptPubKeyMan, public FillableSigningProvider
{
public:
    using ScriptPubKeyMan::ScriptPubKeyMan;

    bool GetNewDestination(const OutputType type,
        std::vector<unsigned char>& vecPubKey, CTxDestination& dest, std::string& error) override;
    bool IsMine(const CScript& script) const override;

    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, std::string>& input_errors) const;
    bool GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const override;
    bool GetKey(const CKeyID& address, CKey_Secp256k1& keyOut) const override;
    bool HaveKey(const CKeyID& address) const override;

    //! Adds a CScript to the store
    bool LoadCScript(const CScript& redeemScript);
    bool AddCScript(const CScript& redeemScript) override;

    bool TopUp(unsigned int size = 0) override;

    uint256 GetID() const override;

    bool GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const override;

    void ImportScripts(const CPubKey& pubKey, const CKey& key);

    /**
     * Explicitly make the wallet learn the related scripts for outputs to the
     * given key. This is purely to make the wallet file compatible with older
     * software, as FillableSigningProvider automatically does this implicitly for all
     * keys now.
     */
    void LearnRelatedScripts(const CPubKey& key, OutputType);

private:
    //! Adds a script to the store and saves it to disk
    bool AddCScriptWithDB(const CScript& script);

};

/** Wraps a LegacyScriptPubKeyMan so that it can be returned in a new unique_ptr. Does not provide privkeys */
class LegacySigningProvider : public SigningProvider
{
private:
    const LegacyScriptPubKeyMan& m_spk_man;
public:
    explicit LegacySigningProvider(const LegacyScriptPubKeyMan& spk_man) : m_spk_man(spk_man) {}

    bool GetCScript(const CScriptID &scriptid, CScript& script) const override { return m_spk_man.GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID &scriptid) const override { return m_spk_man.HaveCScript(scriptid); }
    bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const override { return m_spk_man.GetPubKey(address, pubkey); }
    bool GetKey(const CKeyID &address, CKey_Secp256k1& key) const override { return false; }
    bool HaveKey(const CKeyID &address) const override { return false; }
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return m_spk_man.GetKeyOrigin(keyid, info); }
};

#endif // BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
