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

#include "cryptopp/sha.h"
#include "headers.h"
#include "db.h"
#include "crypter.h"
#include "scriptpubkeyman.h"
#include "key_io.h"

#include <random>
#include <algorithm>
using namespace std;


//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//
void CWallet::ImportScripts(const vector<unsigned char>& vchPubKey, const CKey& key)
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return;
    }
    CPubKey pubkey(vchPubKey);

    LOCK(spk_man->cs_KeyStore);
    spk_man->ImportScripts(pubkey, key);
}

bool CWallet::LoadKey(const vector<unsigned char>& vchPubKey, const CKey& key)
{
    return CCryptoKeyStore::AddKey(vchPubKey, key);
}

//HC: see reference to Bitcoin: RPCHelpMan dumpprivkey()
CBitcoinAddress CWallet::GetKeyFromDestination(const CTxDestination& address, CKey& keyOut, string& error) const
{
    CBitcoinAddress legacyaddress;
    do {
        if (!IsValidDestination(address)) {
            error = "Invalid address";
            break;
        }

        auto spk_man = GetLegacyScriptPubKeyMan();
        if (!spk_man) {
            error = "Invalid LegacyScriptPubKeyMan";
            break;
        }

        CKeyID keyid = GetKeyForDestination(*spk_man, address);
        if (keyid.IsNull()) {
            error = "Address does not refer to a key";
            break;
        }

        legacyaddress.SetHash160(keyid);
        if (!CCryptoKeyStore::GetKey(legacyaddress, keyOut)) {
            error = "Private key for address is not known";
            legacyaddress = CBitcoinAddress();
            break;
        }
    } while (false);

    return legacyaddress;
}

bool CWallet::AddKey(const vector<unsigned char>& vchPubKey, const CKey& key)
{
    if (!CCryptoKeyStore::AddKey(vchPubKey, key))
        return false;

    //HC: At the same time, import SegWit script
    ImportScripts(vchPubKey, key);

    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB_Wrapper(strWalletFile).WriteKey(vchPubKey, key.GetPrivKey());
    return true;
}

bool CWallet::AddCryptedKey(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    CRITICAL_BLOCK(cs_wallet)
    {
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB_Wrapper(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
}

bool CWallet::Unlock(const string& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    CRITICAL_BLOCK(cs_wallet)
        BOOST_FOREACH(const MasterKeyMap::value_type & pMasterKey, mapMasterKeys)
    {
        if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
            return false;
        if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
            return false;
        if (CCryptoKeyStore::Unlock(vMasterKey))
            return true;
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const string& strOldWalletPassphrase, const string& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    CRITICAL_BLOCK(cs_wallet)
    {
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type & pMasterKey, mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                DEBUG_FL("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB_Wrapper(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}


// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::EncryptWallet(const string& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    //HC: Compute Key and IV by password，Key and IV is used by encryption or decryption
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    DEBUG_FL("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    CRITICAL_BLOCK(cs_wallet)
    {
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB_Wrapper(strWalletFile);
            pwalletdbEncryption->TxnBegin();
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }
        //HC: Encrypt bitcoin's key pair using vMasterkey
        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        if (fFileBacked)
        {
            CCorruptAddress corruptAddress;
            pwalletdbEncryption->WriteSetting("addrIncoming", corruptAddress);
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            pwalletdbEncryption->Close();
            pwalletdbEncryption = NULL;
        }

        Lock();
    }

    return true;
}

void CWallet::WalletUpdateSpent(const CTransaction& tx)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    CRITICAL_BLOCK(cs_wallet)
    {
        BOOST_FOREACH(const CTxIn & txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    DEBUG_FL("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    //vWalletUpdated.push_back(txin.prevout.hash);
                }
            }
        }
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_wallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.pwallet = this;
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        DEBUG_FL("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0, 10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;

        // If default receiving address gets used, replace it with a new one
        //HC: To make use of default key continuously, comment the following code,
        //CScript scriptDefaultKey;
        //scriptDefaultKey.SetBitcoinAddress(vchDefaultKey);
        //BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        //{
        //    if (txout.scriptPubKey == scriptDefaultKey)
        //    {
        //        std::vector<unsigned char> newDefaultKey;
        //        if (GetKeyFromPool(newDefaultKey, false))
        //        {
        //            SetDefaultKey(newDefaultKey);
        //            CPubKey new_key(newDefaultKey);
        //            CTxDestination dest = GetDestinationForKey(new_key, defaultType);
        //            SetAddressBookName(dest, "");
        //        }
        //    }
        //}

        // Notify UI
        //vWalletUpdated.push_back(hash);

        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx);
    }

    // Refresh UI
    MainFrameRepaint();
    return true;
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate)
{
    uint256 hash = tx.GetHash();
    CRITICAL_BLOCK(cs_wallet)
    {
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this, tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(pblock);
            return AddToWallet(wtx);
        }
        else
            WalletUpdateSpent(tx);
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    CRITICAL_BLOCK(cs_wallet)
    {
        if (mapWallet.erase(hash))
            CWalletDB_Wrapper(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn& txin) const
{
    CRITICAL_BLOCK(cs_wallet)
    {
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

//HC: 从前一笔交易的输出中提取可用额度
int64 CWallet::GetDebit(const CTxIn& txin) const
{
    CRITICAL_BLOCK(cs_wallet)
    {
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

int64 CWalletTx::GetTxTime() const
{
    return nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    CRITICAL_BLOCK(pwallet->cs_wallet)
    {
        if (IsCoinBase())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetReceiveOrSent(list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent) const
{
    // debit>0 means we signed/sent this transaction
    int64 nDebit = GetDebit();

    // Sent/received.  Standard client will never generate a send-to-multiple-recipients,
    // but non-standard clients might (so return a list of address/amount pairs)
    int i = 0;
    BOOST_FOREACH(const CTxOut & txout, vout)
    {
        CTxDestination address;
        vector<unsigned char> vchPubKey;
        if (!ExtractDestination(txout.scriptPubKey, address)) {
            WARNING_FL("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                this->GetHash().ToString().c_str());
            //address = " unknown ";
        }

        // Don't report 'change' txouts
        if (nDebit > 0 && pwallet->IsChange(txout))
            continue;

        if (nDebit > 0)
            listSent.push_back(make_pair(address, txout.nValue));

        if (pwallet->IsMine(txout))
            listReceived.push_back(make_pair(address, txout.nValue));
    }
}

void CWalletTx::GetAmounts(int64& nGeneratedImmature, int64& nGeneratedMature, list<pair<CTxDestination, int64> >& listReceived,
    list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
    nGeneratedImmature = nGeneratedMature = nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    if (IsCoinBase())
    {
        //HC: for CoinBase, it is possible have two txouts because light nodes take part in mining
        int n = vout.size();
        for (int i = 0; i < n; ++i) {
            if (pwallet->IsMine(vout[i])) {
                if (GetBlocksToMaturity() > 0)
                    nGeneratedImmature += pwallet->GetCredit(*this);
                else
                    nGeneratedMature += GetCredit();
            }
        }
        return;
    }

    // Compute fee:
    int64 nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64 nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }
    GetReceiveOrSent(listReceived, listSent);
}


void CWalletTx::GetReceiveOrSentForBalance(list<DestReceived>& listReceived, int nMinDepth) const
{
    // debit>0 means we signed/sent this transaction
    int64 nDebit = GetDebit();

    bool fmature = GetDepthInMainChain() > nMinDepth;
    int i = 0;
    BOOST_FOREACH(const CTxOut & txout, vout)
    {
        //HC: check if every txout has spent
        if (IsSpent(i++)) {
            continue;
        }

        CTxDestination address;
        vector<unsigned char> vchPubKey;
        if (!ExtractDestination(txout.scriptPubKey, address)) {
            WARNING_FL("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                this->GetHash().ToString().c_str());
            //address = " unknown ";
        }

        // Don't report 'change' txouts
        if (nDebit > 0 && pwallet->IsChange(txout))
            continue;

        if (pwallet->IsMine(txout))
            listReceived.push_back(std::make_tuple(address, txout.nValue, fmature));
    }
}

void CWalletTx::GetAmountsForBalance(list<DestReceived>& listReceived, int64& nFee, int nMinDepth) const
{
    nFee = 0;
    listReceived.clear();

    if (IsCoinBase())
    {
        //HC: for CoinBase, it is possible have two txouts because light nodes take part in mining
        int n = vout.size();
        for (int i = 0; i < n; ++i) {
            if (IsSpent(i)) {
                continue;
            }

            if (pwallet->IsMine(vout[i])) {

                CTxDestination address;
                vector<unsigned char> vchPubKey;
                ExtractDestination(vout[i].scriptPubKey, address);
                listReceived.push_back(std::make_tuple(address, vout[i].nValue, GetBlocksToMaturity() <= 0));

                //if (GetBlocksToMaturity() > 0)
                //    nGeneratedImmature += pwallet->GetCredit(*this);
                //else
                //    nGeneratedMature += GetCredit();
            }
        }
        return;
    }

    // Compute fee:
    int64 nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64 nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }
    GetReceiveOrSentForBalance(listReceived, nMinDepth);
}


void CWalletTx::GetAmountsEx(int64& nGeneratedImmature, int64& nGeneratedMature, list<pair<CTxDestination, int64> >& listReceived,
    list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount, bool& isCoinbase) const
{
    isCoinbase = false;
    GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);
    if (IsCoinBase()) {
        GetReceiveOrSent(listReceived, listSent);
        isCoinbase = true;
    }
}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64& nGenerated, int64& nReceived,
    int64& nSent, int64& nFee) const
{
    nGenerated = nReceived = nSent = nFee = 0;

    int64 allGeneratedImmature, allGeneratedMature, allFee;
    allGeneratedImmature = allGeneratedMature = allFee = 0;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);

    if (strAccount == "")
        nGenerated = allGeneratedMature;
    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64) & s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    CRITICAL_BLOCK(pwallet->cs_wallet)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64) & r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions(CTxDB_Wrapper& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn & txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        CRITICAL_BLOCK(pwallet->cs_wallet)
        {
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx & txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    WARNING_FL("unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                    BOOST_FOREACH(const CTxIn & txin, tx.vin)
                    vWorkQueue.push_back(txin.prevout.hash);
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB_Wrapper(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

int CWallet::ScanForWalletTransactions(CBlockIndexSP pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndexSP pindex = pindexStart;
    CRITICAL_BLOCK(cs_wallet)
    {
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction & tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext();
        }
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    CTxDB_Wrapper txdb;
    bool fRepeat = true;
    while (fRepeat) CRITICAL_BLOCK(cs_wallet)
    {
        fRepeat = false;
        vector<CDiskTxPos> vMissingTx;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx) & item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (wtx.IsCoinBase() && wtx.IsSpent(0))
                continue;

            CTxIndex txindex;
            bool fUpdated = false;
            if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                if (txindex.vSpent.size() != wtx.vout.size())
                {
                    ERROR_FL("txindex.vSpent.size() %d != wtx.vout.size() %d\n", txindex.vSpent.size(), wtx.vout.size());
                    continue;
                }
                for (int i = 0; i < txindex.vSpent.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        vMissingTx.push_back(txindex.vSpent[i]);
                    }
                }
                if (fUpdated)
                {
                    DEBUG_FL("ReacceptWalletTransactions found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Reaccept any txes of ours that aren't already in a block
                if (!wtx.IsCoinBase())
                    wtx.AcceptWalletTransaction(txdb, false);
            }
        }
        if (!vMissingTx.empty())
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do Reaccept.
        }
    }
}

void CWalletTx::RelayWalletTransaction(CTxDB_Wrapper& txdb)
{
    BOOST_FOREACH(const CMerkleTx & tx, vtxPrev)
    {
        if (!tx.IsCoinBase())
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
        }
    }
    if (!IsCoinBase())
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            DEBUG_FL("Relaying wtx %s\n", hash.ToString().substr(0, 10).c_str());
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
    CTxDB_Wrapper txdb;
    RelayWalletTransaction(txdb);
}

void CWallet::ResendWalletTransactions()
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    static int64 nNextTime;
    if (GetTime() < nNextTime)
        return;
    bool fFirst = (nNextTime == 0);
    nNextTime = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    static int64 nLastTime;
    if (nTimeBestReceived < nLastTime)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    DEBUG_FL("ResendWalletTransactions()\n");
    CTxDB_Wrapper txdb;
    CRITICAL_BLOCK(cs_wallet)
    {
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx) & item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*) & item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction(txdb);
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CWallet::GetBalance() const
{
    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_wallet)
    {
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                continue;
            nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}


bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, int64& nValueRet,
                                const list<CTxDestination>& fromaddrs) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    //int a = 0, b = 0, c = 0;
    //int aa = 0, bb = 0, cc = 0;
    //CSpentTime spend;

    // List of values less than target
    pair<int64, pair<const CWalletTx*, unsigned int> > coinLowestLarger;
    coinLowestLarger.first = INT64_MAX;
    coinLowestLarger.second.first = NULL;
    vector<pair<int64, pair<const CWalletTx*, unsigned int> > > vValue;
    int64 nTotalLower = 0;

    std::random_device rd;
    std::mt19937 g(rd());

    CRITICAL_BLOCK(cs_wallet)
    {
        vector<const CWalletTx*> vCoins;
        vCoins.reserve(mapWallet.size());
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
            vCoins.push_back(&(*it).second);
        std::shuffle(vCoins.begin(), vCoins.end(), g);

        //a = spend.Elapse();
        //spend.Reset();

        CSpentTime spendA;
        BOOST_FOREACH(const CWalletTx * pcoin, vCoins)
        {
            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
                continue;

            //aa += spendA.Elapse();
            //spend.Reset();

            for (int i = 0; i < pcoin->vout.size(); i++) {
                if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]))
                    continue;

                int64 n = pcoin->vout[i].nValue;

                if (n <= 0)
                    continue;

                //HC: select coins matches specified addresses
                CTxDestination addrRet;
                if (fromaddrs.size() > 0) {
                    if (!ExtractDestination(pcoin->vout[i].scriptPubKey, addrRet))
                        continue;

                    bool isMatched = false;
                    for (auto& faddr : fromaddrs) {
                        if (faddr == addrRet) {
                            isMatched = true;
                            break;
                        }
                    }

                    if (!isMatched) {
                        continue;
                    }
                }

                pair<int64, pair<const CWalletTx*, unsigned int> > coin = make_pair(n, make_pair(pcoin, i));

                if (n == nTargetValue)
                {
                    setCoinsRet.insert(coin.second);
                    nValueRet += coin.first;
                    return true;
                }
                else if (n < nTargetValue + CENT)
                {
                    vValue.push_back(coin);
                    nTotalLower += n;
                }
                else if (n < coinLowestLarger.first)
                {
                    coinLowestLarger = coin;
                }
            }

            //bb += spend.Elapse();
            //spendA.Reset();
        }
    }

    if (nTotalLower == nTargetValue || nTotalLower == nTargetValue + CENT)
    {
        for (int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue + (coinLowestLarger.second.first ? CENT : 0))
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    if (nTotalLower >= nTargetValue + CENT)
        nTargetValue += CENT;

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend());
    vector<char> vfIncluded;
    vector<char> vfBest(vValue.size(), true);
    int64 nBest = nTotalLower;

    for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // If the next larger is still closer, return it
    if (coinLowestLarger.second.first && coinLowestLarger.first - nTargetValue <= nBest - nTargetValue)
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        //// debug print
        TRACE_FL("SelectCoins() best subset: ");
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                TRACE_FL("%s ", FormatMoney(vValue[i].first).c_str());
        TRACE_FL("total %s\n", FormatMoney(nBest).c_str());
    }

    //b = spend.Elapse();
    //cout << StringFormat("SelectCoinsMinConf: %d %d \n", a, b);
    //cout << StringFormat("SelectCoinsMinConf: %d %d \n", aa, bb);

    return true;
}

//HC: if bfromaddr is true, only select coin which belong to fromAddr
bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, int64& nValueRet,
   const list<CTxDestination> &fromaddrs) const
{
    return (SelectCoinsMinConf(nTargetValue, 1, 6, setCoinsRet, nValueRet, fromaddrs) ||
        SelectCoinsMinConf(nTargetValue, 1, 1, setCoinsRet, nValueRet, fromaddrs) ||
        SelectCoinsMinConf(nTargetValue, 0, 1, setCoinsRet, nValueRet, fromaddrs));
}


OutputType CWallet::TransactionChangeType(const std::vector<pair<CScript, int64>>& vecSend)
{
    // if any destination is P2WPKH or P2WSH, use P2WPKH for the change
    // output.
    for (const auto& recipient : vecSend) {
        // Check if any destination contains a witness program:
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (recipient.first.IsWitnessProgram(witnessversion, witnessprogram)) {
            return OutputType::BECH32;
        }
    }

    // else use m_default_address_type for change
    return defaultType;
}


bool CWallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64) & s, vecSend)
    {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.pwallet = this;

    //HC:
    bool bfromaddr = false;
    list<CTxDestination> fromaddrs;
    if (!wtxNew.strFromAccount.empty()) {
        for (auto& acc : this->mapAddressBook) {
            if (acc.second == wtxNew.strFromAccount) {
                fromaddrs.push_back(acc.first);
            }
        }
    }

    OutputType change_type = TransactionChangeType(vecSend);
    CTxDestination sender_address = GetDefaultKey();

    bool fsendvalid = false;
    if (IsValidDestination(sender_address)) {
        fsendvalid = true;
    }

    CRITICAL_BLOCK_T_MAIN(cs_main)
        CRITICAL_BLOCK(cs_wallet)
    {
        // txdb must be opened before the mapWallet lock
        CTxDB_Wrapper txdb;
        {
            nFeeRet = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64 nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH(const PAIRTYPE(CScript, int64) & s, vecSend)
                    wtxNew.vout.push_back(CTxOut(s.second, s.first));

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64 nValueIn = 0;
                if (!SelectCoins(nTotalValue, setCoins, nValueIn, fromaddrs))
                    return false;

                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
                    dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain();
                }

                int64 nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
                // or until nChange becomes zero
                if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
                {
                    int64 nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                if (nChange > 0)
                {
                    // Note: We use a new key here to keep it from being obvious which side is the change.
                    //  The drawback is that by not reusing a previous key, the change may be lost if a
                    //  backup is restored, if the backup doesn't have the new private key for the change.
                    //  If we reused the old key, it would be possible to add code to look for and
                    //  rediscover unknown transactions that were written with keys of ours to recover
                    //  post-backup change.

                    // Reserve a new key pair from key pool
                    vector<unsigned char> vchPubKey = reservekey.GetReservedKey();
                    // assert(mapKeys.count(vchPubKey));

                    // Fill a vout to ourself, using same address type as the payment
                    CScript scriptChange;
                    //HC: SegWit
                    if (fromaddrs.size() > 0) {
                        scriptChange = GetScriptForDestination(*fromaddrs.begin());
                    } else if (fsendvalid) {
                        //HC: Specify sender's first address as address of change txn
                        scriptChange = GetScriptForDestination(sender_address);
                    } else {
                        //HC: In fact, this case has never occurred.
                        bool fcompressed = (change_type == OutputType::LEGACY ? false : true);

                        CPubKey new_key = CPubKey::NewPubKey(vchPubKey, fcompressed);
                        CTxDestination dest = GetDestinationForKey(new_key, change_type);
                        scriptChange = GetScriptForDestination(dest);

                        SetDefaultKey(vchPubKey, change_type);
                        if (!HavingAddressBookName(dest))
                            SetAddressBookName(dest, "");
                    }

                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = wtxNew.vout.begin() + GetRandInt(wtxNew.vout.size());
                    wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                //BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                //    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                CMutableTransaction mutabletx(wtxNew);
                if (!SignTransaction(mutabletx, setCoins))
                    return false;

                MakeTransactionRef(wtxNew, std::move(mutabletx));

                //int nIn = 0;
                //BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                //    if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
                //        return false;

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK);
                if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
                    return false;
                dPriority /= nBytes;

                // Check that enough fee is included
                int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
                bool fAllowFree = CTransaction::AllowFree(dPriority);
                int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

//HC: witness support, more see bitcoin source code: CWallet::SignTransaction
bool CWallet::SignTransaction(CMutableTransaction& tx, set<pair<const CWalletTx*, unsigned int>>& setCoins)
{
    // Build coins map
    std::map<COutPoint, Coin> coins;
    for (auto& coin : setCoins) {
        COutPoint prevout(coin.first->GetHash(), coin.second);
        tx.vin.push_back(CTxIn(prevout));

        const CWalletTx *wtx = coin.first;
        //HC:
        //coins[prevout] = Coin(wtx->vout[input.prevout.n], wtx->m_confirm.block_height, wtx->IsCoinBase());
        coins[prevout] = Coin(wtx->vout[prevout.n], wtx->GetDepthInMainChain(), wtx->IsCoinBase());
    }

    std::map<int, std::string> input_errors;
    return SignTransaction(tx, coins, SIGHASH_ALL, input_errors);
}

//HC: witness support, more see bitcoin source code: CWallet::SignTransaction
bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, std::string>& input_errors)
{
    // Try to sign with all ScriptPubKeyMans
    //for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
    //    // spk_man->SignTransaction will return true if the transaction is complete,
    //    // so we can exit early and return true if that happens
    //    if (spk_man->SignTransaction(tx, coins, sighash, input_errors)) {
    //        return true;
    //    }
    //}
    //
    //HC: use LegacyScriptPubKeyMan class
    LegacyScriptPubKeyMan man(this);
    if (man.SignTransaction(tx, coins, sighash, input_errors)) {
        return true;
    }

    // At this point, one input was not fully signed otherwise we would have exited already
    return false;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
}

// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    CRITICAL_BLOCK_T_MAIN(cs_main)
        CRITICAL_BLOCK(cs_wallet)
    {
        // This is only to keep the database open to defeat the auto-flush for the
        // duration of this scope.  This is the only place where this optimization
        // maybe makes sense; please don't do it anywhere else.
        CWalletDB_Wrapper walletdb(strWalletFile);

        if (!walletdb.TxnBegin()) {
            ERROR_FL("cannot begin db Tx");
            return false;
        }

        DEBUG_FL("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            BOOST_FOREACH(const CTxIn &txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.pwallet = this;
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                //HC: UI
                //vWalletUpdated.push_back(coin.GetHash());
            }
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool())
        {
            // This must not fail. The transaction has already been signed and recorded.
            //HC: why not remove the tx in BitCoin version?
            //HC: Unmark old coins as spent
            BOOST_FOREACH(const CTxIn & txin, wtxNew.vin)
            {
                CWalletTx& coin = mapWallet[txin.prevout.hash];
                coin.UnmarkSpent(txin.prevout.n);
            }

            EraseFromWallet(wtxNew.GetHash());
            ERROR_FL("CommitTransaction() : Error: Transaction not valid");

            walletdb.TxnAbort();
            return false;
        }

        if (!walletdb.TxnCommit()) {
            walletdb.TxnAbort();
            ERROR_FL("cannot commit db Tx");
            return false;
        }
        wtxNew.RelayWalletTransaction();

    }
    MainFrameRepaint();
    return true;
}




string CWallet::SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        ERROR_FL("SendMoney() : %s", strError.c_str());
        return strError;
    }
    CSpentTime spend;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        ERROR_FL("SendMoney() : %s", strError.c_str());
        return strError;
    }

    auto a = spend.Elapse();
    spend.Reset();

    if (fAskFee && !ThreadSafeAskFee(nFeeRequired, _("Sending..."), NULL))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    auto b = spend.Elapse();
    cout << StringFormat("SendMoney: CreateTransaction:%d,  CommitTransaction: %d\n", a, b);

    MainFrameRepaint();
    return "";
}



string CWallet::SendMoneyToBitcoinAddress(const CBitcoinAddress& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetBitcoinAddress(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}




int CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return false;
    fFirstRunRet = false;
    int nLoadWalletRet = CWalletDB_Wrapper(strWalletFile, "cr+").LoadWallet(this);
    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = vchDefaultKey.empty();

    if (fFirstRunRet || !HaveKey(Hash160(vchDefaultKey)))
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        OutputType output_type{ DEFAULT_ADDRESS_TYPE };
        std::vector<unsigned char> newDefaultKey;
        CTxDestination address;
        std::string error;

        if (!GetNewDestination(output_type, "", newDefaultKey, address, error)) {
            return DB_LOAD_FAIL;
        }

        if (!SetDefaultKey(newDefaultKey, output_type))
            return DB_LOAD_FAIL;
    }

    m_threadFlushWallet.reset(new std::thread(&ThreadFlushWalletDB, &strWalletFile));
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    mapAddressBook[address] = strName;
    if (!fFileBacked)
        return false;
    //return CWalletDB_Wrapper(strWalletFile).WriteName(address.ToString(), strName);
    return CWalletDB_Wrapper(strWalletFile).WriteName(EncodeDestination(address), strName);
}

bool CWallet::HavingAddressBookName(const CTxDestination& address)
{
    return mapAddressBook.count(address) > 0;
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    if (!fFileBacked)
        return false;
    return CWalletDB_Wrapper(strWalletFile).EraseName(EncodeDestination(address));
}


void CWallet::PrintWallet(const CBlock& block)
{
    CRITICAL_BLOCK(cs_wallet)
    {
        if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx &wtx)
{
    CRITICAL_BLOCK(cs_wallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const std::vector<unsigned char> &vchPubKey, OutputType utype)
{
    CPubKey new_key(vchPubKey);
    CTxDestination dest = GetDestinationForKey(new_key, utype);
    if (!IsValidDestination(dest)) {
        //Error: Invalid address
        return false;
    }

    if (fFileBacked)
    {
        bool isSuccess = false;
        CWalletDB_Wrapper dbwrapper(strWalletFile);
        if (dbwrapper.TxnBegin()) {
            if (dbwrapper.WriteDefaultKey(vchPubKey)) {
                if (dbwrapper.WriteDefaultKeyType(utype)) {
                    isSuccess = dbwrapper.TxnCommit();
                }
            }
        }

        if (!isSuccess) {
            return false;
        }
    }
    vchDefaultKey = vchPubKey;
    defaultType = utype;

    return true;
}


CTxDestination CWallet::GetDefaultKey()
{
    CPubKey new_key(vchDefaultKey);
    CTxDestination dest = GetDestinationForKey(new_key, defaultType);
    if (!IsValidDestination(dest)) {
        //Error: Invalid address
        return CNoDestination();
    }
    return dest;
}

bool GetWalletFile(CWallet *pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

bool CWallet::TopUpKeyPool()
{
    CRITICAL_BLOCK(cs_wallet)
    {
        if (IsLocked())
            return false;

        CWalletDB_Wrapper walletdb(strWalletFile);

        // Top up key pool
        int64 nTargetSize = max(GetArg("-keypool", 100), (int64)0);
        while (setKeyPool.size() < nTargetSize + 1)
        {
            int64 nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            TRACE_FL("keypool added key %" PRI64d ", size=%d\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey.clear();
    CRITICAL_BLOCK(cs_wallet)
    {
        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if (setKeyPool.empty())
            return;

        CWalletDB_Wrapper walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(Hash160(keypool.vchPubKey)))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(!keypool.vchPubKey.empty());
        TRACE_FL("keypool reserve %" PRI64d "\n", nIndex);
    }
}

void CWallet::KeepKey(int64 nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB_Wrapper walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    TRACE_FL("keypool keep %" PRI64d "\n", nIndex);
}

void CWallet::ReturnKey(int64 nIndex)
{
    // Return to key pool
    CRITICAL_BLOCK(cs_wallet)
        setKeyPool.insert(nIndex);
    TRACE_FL("keypool return %" PRI64d "\n", nIndex);
}

//HC: note: by GetNewDestination to get new key
bool CWallet::GetKeyFromPool(vector<unsigned char>& result, bool fAllowReuse)
{
    int64 nIndex = 0;
    CKeyPool keypool;
    CRITICAL_BLOCK(cs_wallet)
    {
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && !vchDefaultKey.empty())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

//HC: SegWit

LegacyScriptPubKeyMan* CWallet::GetLegacyScriptPubKeyMan() const
{
    //if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
    //    return nullptr;
    //}
    // Legacy wallets only have one ScriptPubKeyMan which is a LegacyScriptPubKeyMan.
    // Everything in m_internal_spk_managers and m_external_spk_managers point to the same legacyScriptPubKeyMan.
    auto it = m_internal_spk_managers.find(OutputType::LEGACY);
    if (it == m_internal_spk_managers.end()) return nullptr;
    return dynamic_cast<LegacyScriptPubKeyMan*>(it->second);
}

LegacyScriptPubKeyMan* CWallet::GetOrCreateLegacyScriptPubKeyMan()
{
    SetupLegacyScriptPubKeyMan();
    return GetLegacyScriptPubKeyMan();
}

void CWallet::SetupLegacyScriptPubKeyMan()
{
    if (!m_internal_spk_managers.empty() || !m_external_spk_managers.empty() || !m_spk_managers.empty()) {
        return;
    }

    auto spk_manager = std::unique_ptr<ScriptPubKeyMan>(new LegacyScriptPubKeyMan(this));
    for (const auto& type : OUTPUT_TYPES) {
        m_internal_spk_managers[type] = spk_manager.get();
        m_external_spk_managers[type] = spk_manager.get();
    }
    m_spk_managers[spk_manager->GetID()] = std::move(spk_manager);
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const OutputType& type, bool internal) const
{
    const std::map<OutputType, ScriptPubKeyMan*>& spk_managers = internal ? m_internal_spk_managers : m_external_spk_managers;
    std::map<OutputType, ScriptPubKeyMan*>::const_iterator it = spk_managers.find(type);
    if (it == spk_managers.end()) {
        WARNING_FL("%s scriptPubKey Manager for output type %d does not exist\n", internal ? "Internal" : "External", static_cast<int>(type));
        return nullptr;
    }
    return it->second;
}


bool CWallet::GetNewDestination(const OutputType type, const std::string label, std::vector<unsigned char>& vchPubKey, CTxDestination& dest, std::string& error)
{
    CRITICAL_BLOCK(cs_wallet);
    error.clear();
    bool result = false;
    auto spk_man = GetScriptPubKeyMan(type, false /* internal */);
    if (spk_man) {
        spk_man->TopUp();
        result = spk_man->GetNewDestination(type, vchPubKey, dest, error);
    }
    else {
        error = strprintf("Error: No %s addresses available.", FormatOutputType(type));
    }

    if (result) {
        //SetAddressBook(dest, label, "receive");
        SetAddressBookName(dest, label);
    }

    return result;
}


int64 CWallet::GetOldestKeyPoolTime()
{
    int64 nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

CScript CReserveKey::GetDefaultKeyScript()
{
    CTxDestination address = pwallet->GetDefaultKey();

    CScript coinbase_script = GetScriptForDestination(address);
    return coinbase_script;
}

vector<unsigned char> CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            TRACE_FL("CReserveKey::GetReservedKey(): Warning: using default key instead of a new key, top up your keypool.");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    assert(!vchPubKey.empty());
    return vchPubKey;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey.clear();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey.clear();
}

