/*Copyright 2016-2024 hyperchain.net (Hyperchain)

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

//////////////////////////////////////////////////////////////////////////
//all plugin module share
//////////////////////////////////////////////////////////////////////////
#include "headers.h"

#include "plshared.h"
#include "block.h"
#include "wallet.h"

#include "key_io.h"

extern CWallet* pwalletMain;

Array toArray(const list<string>& cmdlist)
{
    Array arr;
    auto cmd = cmdlist.begin();
    for (; cmd != cmdlist.end(); ++cmd)
        arr.push_back(*cmd);
    return arr;
}

//HCE: ASN.1 DER format
std::string PrKey2WIF(const CPrivKey& prikey, bool isCompressed)
{
    std::vector<unsigned char> ret;
    auto pos = prikey.begin();
    std::advance(pos, 9);

    //HCE: 0x80 is a prefix, in newer Bitcoin, different network environment has different prefix
    //HCE: in the further, maybe will be replaced by base58Prefixes[SECRET_KEY]
    ret.push_back(0x80);  //HCE: version number
    std::copy(pos, pos + 32, std::back_inserter(ret));

    if (isCompressed) {
        ret.push_back(1);
    }

    return EncodeBase58Check(ret);
}

bool WIF2PrKey(const string& strprivkey, bool isCompressed, std::vector<unsigned char>& vchPriKey)
{
    //HCE: WIF compressed, begin with K or L
    //HCE: remove 5|4 bytes of tail: ( 01 (flag for compressed) + 4bytes(hash(hash(Private key)) prefix) )
    if (!DecodeBase58Check(strprivkey, vchPriKey))
        return false;

    if (isCompressed) {
        //remove 01 (flag for compressed)
        auto pos = vchPriKey.end();
        if (*(--pos) != 1) {
            return false;
        }
        vchPriKey.erase(pos);
    }
    return true;
}


//HCE: if form of strprivkey is 'WIF', public key will be uncompressed, address uncompressed
//HCE: otherwise all are compressed form.
int impwalletkey(const string& strprivkey, const string& strlabel, string& msg)
{
    CBitcoinAddress coinaddress;

    std::vector<unsigned char> vchPriKey;

    bool isCompressed = false;
    bool isWIFOK = true;
    size_t nSize = strprivkey.size();
    if (nSize == 52 && (strprivkey[0] == 'K' || strprivkey[0] == 'L')) {
        //HC: WIF-compressed begin with K or L
        isCompressed = true;
        isWIFOK = WIF2PrKey(strprivkey, true, vchPriKey);
    }
    else if (nSize == 51 && strprivkey[0] == '5') {
        //HC: WIF begin with 5
        isWIFOK = WIF2PrKey(strprivkey, false, vchPriKey);
    }
    else {
        //HC: 16 hex format
        vchPriKey = ParseHex(strprivkey);
    }

    msg = "Invalid private key encoding";
    if (vchPriKey.size() == 0) {
        return -1;
    }

    if (vchPriKey[0] == 0x80 && vchPriKey.size() == 0x21) {
        vchPriKey.erase(vchPriKey.begin());
    }

    CPrivKey privkey;
    privkey.insert(privkey.end(), vchPriKey.begin(), vchPriKey.end());

    CKey keyPair;
    if (vchPriKey.size() != 0x20 || !isWIFOK || !keyPair.SetSecret(privkey)) {
        return -1;
    }


    CKey_Secp256k1 key_secp;
    key_secp.Set(privkey.begin(), privkey.end(), isCompressed);

    CPubKey pubkey = key_secp.GetPubKey();
    vector<unsigned char> vecPubKey = vector<unsigned char>(pubkey.begin(), pubkey.end());

    likely_wallet_locked

    auto fnImport = [&msg](CPubKey& pubkey, const vector<unsigned char>& vchPubK, CKey& key) ->int {
        int ret = 0;
        CTxDestination dest = GetDestinationForKey(pubkey, DEFAULT_ADDRESS_TYPE);
        string strdest = EncodeDestination(dest);

        CBitcoinAddress coinaddress;
        CKeyID vchAddr = pubkey.GetID();

        coinaddress.SetHash160(vchAddr);
        if (pwalletMain->HaveKey(coinaddress)) {
            msg += StringFormat("Key pair has already been in wallet, which address is %s\n", strdest);
            ret = 0;
        } else if (pwalletMain->AddKey(vchPubK, key)) {
            msg += StringFormat("Key pair has imported successfully, which address is %s\n", strdest);
            ret = 1;
        } else {
            msg += "Failed to import key pair\n";
            ret = -1;
        }
        return ret;
    };


    CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        msg = "";
        if (fnImport(pubkey, vecPubKey, keyPair) == -1)
            return -1;

        // We don't know which corresponding address will be used;
        // label all new addresses, and label existing addresses if a
        // label was passed.
        for (const auto& dest : GetAllDestinationsForKey(pubkey)) {
            if (!strlabel.empty()) {
                pwalletMain->SetAddressBookName(dest, strlabel);
            }
        }
    }
    return 0;
}

Value impwalletkeysfromfile(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error(COMMANDPREFIX " ikpf <filename> [label] : import private keys from <filename>");
    }

    likely_wallet_locked

    string ret;
    const string& filename = params[0].get_str();
    ifstream ff(filename);
    if (!ff) {
        return (StringFormat("%s cannot be opened\n", filename));
    }

    string strLine;
    char pstrPriKey[128];
    int nImportedCount = 0;
    int nSkipCount = 0;
    int nLineNum = 0;

    string strlabel;
    if (params.size() > 1) {
        strlabel = params[1].get_str();
    }
    CommadLineProgress progress;
    progress.Start();

    while (true) {
        std::getline(ff, strLine);
        if (!ff.good()) {
            break;
        }
        nLineNum++;
        if (std::sscanf(strLine.c_str(), "%*s %*s %s", pstrPriKey) != 1) {
            progress.PrintStatus(1, StringFormat("Invalid line:%d, stopped", nLineNum));
            break;
        }

        string msg;
        int r = impwalletkey(pstrPriKey, strlabel, msg);

        progress.PrintStatus(1, "******");

        if (r < 0) {
            return StringFormat("%s : %s\n", msg, pstrPriKey);
        }
        r == 1 ? nImportedCount++ : nSkipCount++;
    }

    return StringFormat("Key imported: %d, Key existed : %d", nImportedCount, nSkipCount);
}

Value expwalletkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            COMMANDPREFIX " ekp <address>: export the public-private key pair corresponding to <address> to console");

    likely_wallet_locked

    string ret;
    CPrivKey privkey;
    CKey keyPair;
    string error;

    CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        CTxDestination address = DecodeDestination(params[0].get_str());
        if (pwalletMain->GetKeyFromDestination(address, keyPair, error).IsValid()) {

            return StringFormat("Public key: %s\nPrivate key(WIF, WIF-compressed): \n\t%s\n\t%s", ToHexString(keyPair.GetPubKey()),
                PrKey2WIF(keyPair.GetPrivKey(), false),
                PrKey2WIF(keyPair.GetPrivKey(), true));
        }
    }
    return StringFormat("Failed to export key pair, %s", error);
}

Value expwalletkeystofile(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error(COMMANDPREFIX " ekpf <filename> [WIF|WIFC] : export private keys(WIF|WIFC) to <filename>");
    }

    likely_wallet_locked

    Array ret;
    const string& filename = params[0].get_str();

    ofstream ff(filename);
    ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!ff) {
        ret.push_back(StringFormat("%s cannot be opened\n", filename));
        return ret;
    }

    CommadLineProgress progress;
    progress.Start();

    int64_t nCount = 0;

    bool isCompressed = true;
    if (params.size() > 1 && params[1].get_str() == "WIF") {
        isCompressed = false;
    }
    bool r = pwalletMain->AllOfKeys([&ff, &nCount, &progress, isCompressed](const CKey& keyPair) ->bool {

        CBitcoinAddress bitcoinaddr;
        bitcoinaddr.SetPubKey(keyPair.GetPubKey());

        CPrivKey pr = keyPair.GetPrivKey();

        ff << StringFormat("%s %s %s", bitcoinaddr.ToString(),
            ToHexString(keyPair.GetPubKey()),
            PrKey2WIF(pr, isCompressed)) << endl;
        nCount++;

        progress.PrintStatus(1, "******");
        return true;
    });

    if (!r) {
        ret.push_back("Failed to export wallet keys, maybe wallet unlock timeout");
        return ret;
    }

    ff.flush();

    return Value::null;
}

Value setdefaultkey(const Array& params, bool fHelp)
{
    if (fHelp) {
        throw runtime_error(COMMANDPREFIX " dkp <address> : specify the key pair whose address is <address> as default key");
    }

    Array ret;

    likely_wallet_locked

    if (params.size() < 1) {

        CRITICAL_BLOCK(pwalletMain->cs_wallet)
        {
            CTxDestination address = pwalletMain->GetDefaultKey();
            ret.push_back(EncodeDestination(address));
            return ret;
        }
    }

    CTxDestination address = DecodeDestination(params[0].get_str());

    if (!IsValidDestination(address)) {
        ret.push_back("Error: Invalid address");
        return ret;
    }

    CKey keyPair;
    CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {

        OutputType otype;
        if (boost::get<PKHash>(&address))
            otype = OutputType::LEGACY;
        else if (boost::get<WitnessV0KeyHash>(&address))
            otype = OutputType::BECH32;
        else if (boost::get<ScriptHash>(&address))
            otype = OutputType::P2SH_SEGWIT;
        else {
            ret.push_back("maybe address is invalid");
            return ret;
        }

        string error;
        CBitcoinAddress bitaddr = pwalletMain->GetKeyFromDestination(address, keyPair, error);

        if(!bitaddr.IsValid()) {
            ret.push_back(error);
            return ret;
        }

        std::vector<unsigned char> vchPubKey;
        //HCE: important note: don't use keyPair.GetPubKey()
        if (!pwalletMain->GetPubKey(bitaddr, vchPubKey)) {
            ret.push_back(error);
            return ret;
        }

        pwalletMain->SetDefaultKey(vchPubKey, otype);
        if(!pwalletMain->HavingAddressBookName(address))
            pwalletMain->SetAddressBookName(address, "");
    }

    return Value::null;
}

string MakeNewKeyPair()
{
    CKey_Secp256k1 key_secp;
    key_secp.MakeNewKey(false);

    return StringFormat("Public key: %s\nPrivate key(WIF, WIF-compressed): \n\t%s\n\t%s", ToHexString(key_secp.GetPubKey()),
        PrKey2WIF(key_secp.GetPrivKey(), false),
        PrKey2WIF(key_secp.GetPrivKey(), true));

    //HC: or use the following solution:
    CKey keyPair;
    try {
        keyPair.MakeNewKey();
    }
    catch (std::exception& e) {
        return e.what();
    }

    //CPrivKey pr = keyPair.GetPrivKey();
    //std::vector<unsigned char> vPr(pr.begin(), pr.end());

    return StringFormat("Public key: %s\nPrivate key(WIF, WIF-compressed): \n\t%s\n\t%s", ToHexString(keyPair.GetPubKey()),
        PrKey2WIF(keyPair.GetPrivKey(), false),
        PrKey2WIF(keyPair.GetPrivKey(), true));
}
