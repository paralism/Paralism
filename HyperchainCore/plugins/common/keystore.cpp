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
#include "db.h"
#include "crypter.h"

std::vector<unsigned char> CKeyStore::GenerateNewKey()
{
    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey();

    //HCE: the default public key is uncompressed,
    //HCE: therefore for supporting SegWit, please use compressed key
    std::vector<unsigned char> vch = key.GetPubKey();

    //HCE: compressed key
    //CPubKey publickey = CPubKey::NewPubKey(vch, true);
    //std::vector<unsigned char> vch_short;
    //vch_short.insert(vch_short.end(), publickey.begin(), publickey.end());

    if (!AddKey(vch, key))
        throw std::runtime_error("CKeyStore::GenerateNewKey() : AddKey failed");

    return vch;
}

bool CKeyStore::GetPubKey(const CBitcoinAddress &address, std::vector<unsigned char> &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();

    //HCE: check if hash of public key is equal
    CPubKey pubkey = CPubKey::NewPubKey(vchPubKeyOut, true);
    CBitcoinAddress addressOut(pubkey.GetID());
    if (addressOut == address) {
        //HCE: compressed public key
        vchPubKeyOut = vector<unsigned char>(pubkey.begin(), pubkey.end());
        return true;
    }

    //HCE: uncompressed public key
    return true;
}

bool CBasicKeyStore::AddKey(const vector<unsigned char>& vchPubKey, const CKey& key)
{
    CPubKey pubkey(vchPubKey);
    CRITICAL_BLOCK(cs_KeyStore)
        mapKeys[pubkey.GetID()] = key.GetSecret();
    return true;
}

bool CCryptoKeyStore::SetCrypted()
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (fUseCrypto)
            return true;
        if (!mapKeys.empty())
            return false;
        fUseCrypto = true;
    }
    return true;
}

std::vector<unsigned char> CCryptoKeyStore::GenerateNewKey()
{
    return CKeyStore::GenerateNewKey();
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!SetCrypted())
            return false;

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const std::vector<unsigned char> &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if(!DecryptSecret(vMasterKeyIn, vchCryptedSecret, Hash(vchPubKey.begin(), vchPubKey.end()), vchSecret))
                return false;
            CKey key;
            key.SetSecret(vchSecret);
            if (key.GetPubKey() == vchPubKey)
                break;
            return false;
        }
        vMasterKey = vMasterKeyIn;
    }
    return true;
}

bool CCryptoKeyStore::AddKey(const vector<unsigned char>& vchPubKey, const CKey& key)
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!IsCrypted())
            return CBasicKeyStore::AddKey(vchPubKey, key);

        if (IsLocked())
            return false;

        std::vector<unsigned char> vchCryptedSecret;
        //HCE: To public key, cannot extract from key for two kinds of situation
        //std::vector<unsigned char> vchPubKey = key.GetPubKey();
        if (!EncryptSecret(vMasterKey, key.GetSecret(), Hash(vchPubKey.begin(), vchPubKey.end()), vchCryptedSecret))
            return false;

        if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
            return false;
    }
    return true;
}


bool CCryptoKeyStore::AddCryptedKey(const std::vector<unsigned char> &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!SetCrypted())
            return false;

        mapCryptedKeys[CBitcoinAddress(vchPubKey)] = make_pair(vchPubKey, vchCryptedSecret);
    }
    return true;
}

bool CCryptoKeyStore::GetKey(const CBitcoinAddress &address, CKey& keyOut) const
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!IsCrypted())
            return CBasicKeyStore::GetKey(address, keyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            const std::vector<unsigned char> &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, Hash(vchPubKey.begin(), vchPubKey.end()), vchSecret))
                return false;
            keyOut.SetSecret(vchSecret);
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::GetPubKey(const CBitcoinAddress &address, std::vector<unsigned char>& vchPubKeyOut) const
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!IsCrypted())
            return CKeyStore::GetPubKey(address, vchPubKeyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            vchPubKeyOut = (*mi).second.first;
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
    CRITICAL_BLOCK(cs_KeyStore)
    {
        if (!mapCryptedKeys.empty() || IsCrypted())
            return false;

        fUseCrypto = true;
        CKey key;
        BOOST_FOREACH(KeyMap::value_type& mKey, mapKeys)
        {
            if (!key.SetSecret(mKey.second))
                return false;
            const std::vector<unsigned char> vchPubKey = key.GetPubKey();
            std::vector<unsigned char> vchCryptedSecret;
            if (!EncryptSecret(vMasterKeyIn, key.GetSecret(), Hash(vchPubKey.begin(), vchPubKey.end()), vchCryptedSecret))
                return false;
            if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
                return false;
        }
        mapKeys.clear();
    }
    return true;
}
